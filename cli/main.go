// minica is a small CLI for retrieving certificates from a MiniCA server.
//
// Usage:
//
//	minica cert [flags]
//
// It first checks whether a certificate with the requested common name already
// exists under the CA; if so it downloads that certificate (renewing it for 365
// days first when it expires within a year), otherwise it creates a new one.
// Either way it saves the cert, key, PKCS#12 bundle, the bundle password, and
// the issuing CA certificate to disk.
//
// Configuration is resolved with the precedence: flag > environment > prompt.
// Prompts are skipped entirely with -y/--non-interactive.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultKeyProfile = "rsa:4096"
	defaultDigest     = "sha256"
	defaultDays       = 825

	msPerDay = int64(86_400_000)
	// On the reuse path, renew when the existing certificate expires within
	// this many days, re-issuing it for renewDays days.
	renewWithinDays = int64(365)
	renewDays       = 365
)

// timeNowMs returns the current time in milliseconds since the Unix epoch,
// matching the server's millisecond timestamps.
func timeNowMs() int64 { return time.Now().UnixMilli() }

// needsRenew reports whether a certificate with the given issue time (ms) and
// validity (days) expires less than renewWithinDays days from nowMs. An
// already-expired certificate also needs renewal.
func needsRenew(issueTimeMs, validDays, nowMs int64) bool {
	remainingMs := issueTimeMs + validDays*msPerDay - nowMs
	return remainingMs < renewWithinDays*msPerDay
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "cert" {
		usage()
		os.Exit(2)
	}
	if err := runCert(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `minica - retrieve certificates from a MiniCA server

Checks whether a certificate with the requested common name already exists under
the CA: if it does, that certificate is downloaded (and first renewed for 365
days when it expires within a year); otherwise a new one is created. Either way
the certificate, private key, PKCS#12 bundle, the bundle password, and the
issuing CA certificate are saved to disk.

USAGE:
  minica cert [flags]

Every value can be supplied as a flag, a MINICA_* environment variable, or a
KEY=VALUE line in the ~/.minica file. Resolution precedence:

  flag  >  environment  >  ~/.minica  >  interactive prompt

(a prompt's own default is the resolved env value, or the built-in default
below). Run with -y to skip all prompts and use flags/env/defaults.

The ~/.minica file holds KEY=VALUE lines (an optional leading "export " and
quotes around the value are stripped; '#' lines are comments). Override its
location with MINICA_CONFIG. Example ~/.minica:

  export MINICA_URL=https://ca.example.com/minica
  MINICA_USER=admin
  MINICA_KEY_PROFILE=ecdsa:secp384r1

CONNECTION (required; flag or env only, never prompted)
  --url            MINICA_URL        Base URL incl. base path, e.g. http://host:9988/minica
  --user           MINICA_USER       Username (must be an admin to create certs)
  --password       MINICA_PASSWORD   Password
  --ca             MINICA_CA_ID      Target CA id

CERTIFICATE FIELDS (flag or env; prompted otherwise)
  Flag             Env var               Default
  --cn             MINICA_CN             (none, required)   Common name
  --country        MINICA_COUNTRY        US                 Country code (server requires non-empty)
  --org            MINICA_ORG            MiniCA             Organization (server requires non-empty)
  --state          MINICA_STATE          (empty)
  --city           MINICA_CITY           (empty)
  --org-unit       MINICA_ORG_UNIT       (empty)
  --key-profile    MINICA_KEY_PROFILE    rsa:4096           rsa:2048|4096|8192 or
                                                            ecdsa:prime256v1|secp384r1|secp521r1
  --digest         MINICA_DIGEST         sha256
  --days           MINICA_DAYS           825                Validity in days (1..7350)
  --hostnames      MINICA_HOSTNAMES      (empty)            Comma-separated DNS names and/or IPs;
                                                            IPs become IP SANs, the rest DNS SANs
  --p12-password   MINICA_P12_PASSWORD   server-generated   Blank = server generates and we download it
  --name           MINICA_NAME           <sanitized CN>     Output file prefix

OUTPUT / BEHAVIOR (flag or env only, never prompted)
  --out-dir        MINICA_OUT_DIR        ./certs            Directory to write files into
  --insecure       MINICA_INSECURE       (off)              Skip TLS certificate verification
  -y, --non-interactive                                     Use flags/env/defaults without prompting
  -h, --help                                                Show this help

OUTPUT FILES (with prefix "test1")
  test1.pem            certificate
  test1.key            private key
  test1.p12            PKCS#12 bundle
  test1.p12.password   PKCS#12 password
  CA.pem               issuing CA certificate

EXAMPLE
  MINICA_URL=http://host:9988/minica MINICA_USER=admin MINICA_PASSWORD=secret \
  MINICA_CA_ID=TiiKxJtS0Rkf \
  minica cert -y --cn test1.example.com --hostnames a.com,b.com,10.0.0.5 \
    --name test1 --out-dir ./out
`)
}

// flags holds raw command-line values; empty string means "not set".
type flags struct {
	url, user, password, ca         string
	cn, hostnames, days             string
	keyProfile, digest, p12Password string
	country, state, city            string
	org, orgUnit                    string
	name, outDir                    string
	nonInteractive, insecure        bool
}

func parseFlags(args []string) (*flags, error) {
	f := &flags{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		// Support --flag=value and --flag value.
		var val string
		hasInline := false
		if eq := strings.IndexByte(a, '='); strings.HasPrefix(a, "--") && eq >= 0 {
			val = a[eq+1:]
			a = a[:eq]
			hasInline = true
		}
		next := func() (string, error) {
			if hasInline {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch a {
		case "-y", "--non-interactive":
			f.nonInteractive = true
		case "--insecure":
			f.insecure = true
		case "--url":
			f.url, err = next()
		case "--user":
			f.user, err = next()
		case "--password":
			f.password, err = next()
		case "--ca":
			f.ca, err = next()
		case "--cn":
			f.cn, err = next()
		case "--hostnames":
			f.hostnames, err = next()
		case "--days":
			f.days, err = next()
		case "--key-profile":
			f.keyProfile, err = next()
		case "--digest":
			f.digest, err = next()
		case "--p12-password":
			f.p12Password, err = next()
		case "--country":
			f.country, err = next()
		case "--state":
			f.state, err = next()
		case "--city":
			f.city, err = next()
		case "--org":
			f.org, err = next()
		case "--org-unit":
			f.orgUnit, err = next()
		case "--name":
			f.name, err = next()
		case "--out-dir":
			f.outDir, err = next()
		case "-h", "--help":
			usage()
			os.Exit(0)
		default:
			return nil, fmt.Errorf("unknown flag: %s", a)
		}
		if err != nil {
			return nil, err
		}
	}
	return f, nil
}

func runCert(args []string) error {
	f, err := parseFlags(args)
	if err != nil {
		return err
	}
	// ~/.minica is read as environment variables but the process environment
	// takes precedence over it, so getEnv resolves a key as: os env > ~/.minica.
	fileEnv, err := loadEnvFile(minicaFilePath())
	if err != nil {
		return err
	}
	getEnv := func(key string) string {
		if v, ok := os.LookupEnv(key); ok {
			return v
		}
		return fileEnv[key]
	}

	in := bufio.NewReader(os.Stdin)
	ask := func(label, flagVal, envKey, def string) string {
		// flag wins, then env (file > os), then prompt (whose default is env-or-built-in).
		if flagVal != "" {
			return flagVal
		}
		if v := getEnv(envKey); v != "" {
			def = v
		}
		if f.nonInteractive {
			return def
		}
		return prompt(in, label, def)
	}

	// Connection settings resolve from flag or env only (never prompted), so the
	// interactive session begins at the certificate questions.
	resolve := func(flagVal, envKey string) string {
		if flagVal != "" {
			return flagVal
		}
		return getEnv(envKey)
	}
	url := strings.TrimRight(resolve(f.url, "MINICA_URL"), "/")
	user := resolve(f.user, "MINICA_USER")
	password := resolve(f.password, "MINICA_PASSWORD")
	caID := resolve(f.ca, "MINICA_CA_ID")
	for k, v := range map[string]string{"MINICA_URL": url, "MINICA_USER": user, "MINICA_PASSWORD": password, "MINICA_CA_ID": caID} {
		if v == "" {
			return fmt.Errorf("%s is required (set flag or env)", k)
		}
	}

	// Certificate parameters.
	commonName := ask("What is your commonName", f.cn, "MINICA_CN", "")
	if commonName == "" {
		return fmt.Errorf("commonName is required")
	}

	client := newClient(user, password, f.insecure || getEnv("MINICA_INSECURE") != "")

	// Output name and directory resolution, shared by the reuse and create
	// paths. Name: flag > prompt (default sanitized CN) > env > "cert". Dir:
	// flag > env > "./certs".
	resolveOutPrefix := func() string {
		outPrefix := f.name
		if outPrefix == "" {
			outPrefix = ask("Output name (file prefix)", "", "MINICA_NAME", sanitize(commonName))
		}
		if outPrefix == "" {
			outPrefix = "cert"
		}
		return outPrefix
	}
	resolveOutDir := func() string {
		outDir := f.outDir
		if outDir == "" {
			outDir = getEnv("MINICA_OUT_DIR")
		}
		if outDir == "" {
			outDir = "./certs"
		}
		return outDir
	}

	// Probe first: if a certificate with this common name already exists under
	// the CA, download it instead of creating a new one (the create call would
	// fail the server's per-CA CN uniqueness check anyway).
	if existingID, found, err := client.findCertIDByCN(url, caID, commonName); err != nil {
		return err
	} else if found {
		fmt.Fprintf(os.Stderr, "Certificate %q already exists in this CA; downloading.\n", commonName)
		fmt.Printf("Cert Id is: %s\n", existingID)

		// Renew before downloading if the existing certificate is within a year
		// of expiry, so the downloaded artifacts carry the renewed validity. A
		// failed renewal is not fatal: warn and download the current cert.
		existing, err := client.getCert(url, caID, existingID)
		if err != nil {
			return err
		}
		if needsRenew(existing.IssueTime, existing.ValidDays, timeNowMs()) {
			remaining := (existing.IssueTime + existing.ValidDays*msPerDay - timeNowMs()) / msPerDay
			fmt.Fprintf(os.Stderr, "Certificate expires in %d days; renewing for %d days.\n", remaining, renewDays)
			if err := client.renewCert(url, caID, existingID, renewDays); err != nil {
				fmt.Fprintf(os.Stderr, "could not renew (%v); downloading current certificate.\n", err)
			}
		}

		certPEM, err := client.download(url, fmt.Sprintf("/download/cert/%s/%s/cert", caID, existingID))
		if err != nil {
			return err
		}
		keyPEM, err := client.download(url, fmt.Sprintf("/download/cert/%s/%s/key", caID, existingID))
		if err != nil {
			return err
		}
		p12, err := client.download(url, fmt.Sprintf("/download/cert/%s/%s/pkcs12", caID, existingID))
		if err != nil {
			return err
		}
		pw, err := client.download(url, fmt.Sprintf("/download/cert/%s/%s/password", caID, existingID))
		if err != nil {
			return err
		}
		caPEM, err := client.download(url, fmt.Sprintf("/download/ca/%s/cert", caID))
		if err != nil {
			return err
		}
		written, err := saveBundle(resolveOutDir(), resolveOutPrefix(), certPEM, keyPEM, p12, pw, caPEM)
		if err != nil {
			return err
		}
		fmt.Printf("Saved as %s\n", strings.Join(written, ", "))
		return nil
	}

	// country_code and organization are required non-empty by the server,
	// so they carry meaningful defaults; state/city/org_unit may be blank.
	country := ask("What is your country code", f.country, "MINICA_COUNTRY", "US")
	state := ask("What is your state", f.state, "MINICA_STATE", "")
	city := ask("What is your city", f.city, "MINICA_CITY", "")
	org := ask("What is your organization", f.org, "MINICA_ORG", "MiniCA")
	orgUnit := ask("What is your organization unit", f.orgUnit, "MINICA_ORG_UNIT", "")
	keyProfile := ask("Key profile", f.keyProfile, "MINICA_KEY_PROFILE", defaultKeyProfile)
	digest := ask("Digest algorithm", f.digest, "MINICA_DIGEST", defaultDigest)
	daysStr := ask("Valid days", f.days, "MINICA_DAYS", strconv.Itoa(defaultDays))
	days, err := strconv.Atoi(strings.TrimSpace(daysStr))
	if err != nil {
		return fmt.Errorf("invalid valid-days %q: %w", daysStr, err)
	}
	hostnames := ask("What is your hostnames (comma separated)", f.hostnames, "MINICA_HOSTNAMES", "")
	dnsList, ipList := splitHostnames(hostnames)

	// p12 password is optional; blank means the server generates one.
	p12Password := f.p12Password
	if p12Password == "" {
		p12Password = getEnv("MINICA_P12_PASSWORD")
	}

	outPrefix := resolveOutPrefix()
	outDir := resolveOutDir()

	body := map[string]any{
		"common_name":       commonName,
		"country_code":      country,
		"state":             state,
		"city":              city,
		"organization":      org,
		"organization_unit": orgUnit,
		"valid_days":        days,
		"digest_algorithm":  digest,
		"key_profile":       keyProfile,
		"dns_list":          dnsList,
		"ip_list":           ipList,
	}
	if p12Password != "" {
		body["password"] = p12Password
	}

	// The leading blank line separates the interactive prompts from the status
	// output; with -y there are no prompts, so skip it to avoid a stray blank line.
	if f.nonInteractive {
		fmt.Fprintln(os.Stderr, "Getting certs...")
	} else {
		fmt.Fprintln(os.Stderr, "\nGetting certs...")
	}
	cert, err := client.createCert(url, caID, body)
	if err != nil {
		return err
	}
	fmt.Printf("Cert Id is: %s\n", cert.ID)

	// PKCS#12, its password, and the CA cert come from download endpoints; the
	// cert and key come from the create response.
	p12, err := client.download(url, fmt.Sprintf("/download/cert/%s/%s/pkcs12", caID, cert.ID))
	if err != nil {
		return err
	}
	pw, err := client.download(url, fmt.Sprintf("/download/cert/%s/%s/password", caID, cert.ID))
	if err != nil {
		return err
	}
	caPEM, err := client.download(url, fmt.Sprintf("/download/ca/%s/cert", caID))
	if err != nil {
		return err
	}
	written, err := saveBundle(outDir, outPrefix, []byte(cert.CertPEM), []byte(cert.KeyPEM), p12, pw, caPEM)
	if err != nil {
		return err
	}

	fmt.Printf("Saved as %s\n", strings.Join(written, ", "))
	return nil
}

// saveBundle writes the five certificate artifacts into outDir using the given
// file-name prefix, returning the names written in order. Modes match the
// sensitivity of each file: the certificate and CA cert are world-readable
// (0644); the key, PKCS#12 bundle, and its password are owner-only (0600).
func saveBundle(outDir, prefix string, certPEM, keyPEM, p12, p12pw, caPEM []byte) ([]string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	written := []string{}
	write := func(name string, data []byte, mode os.FileMode) error {
		p := filepath.Join(outDir, name)
		if err := os.WriteFile(p, data, mode); err != nil {
			return fmt.Errorf("writing %s: %w", p, err)
		}
		written = append(written, name)
		return nil
	}
	if err := write(prefix+".pem", certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := write(prefix+".key", keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := write(prefix+".p12", p12, 0o600); err != nil {
		return nil, err
	}
	if err := write(prefix+".p12.password", p12pw, 0o600); err != nil {
		return nil, err
	}
	if err := write("CA.pem", caPEM, 0o644); err != nil {
		return nil, err
	}
	return written, nil
}

// splitHostnames classifies a comma-separated list into DNS names and IPs.
func splitHostnames(s string) (dns, ips []string) {
	for _, raw := range strings.Split(s, ",") {
		h := strings.TrimSpace(raw)
		if h == "" {
			continue
		}
		if net.ParseIP(h) != nil {
			ips = append(ips, h)
		} else {
			dns = append(dns, h)
		}
	}
	return dns, ips
}

func sanitize(s string) string {
	s = strings.TrimSpace(s)
	repl := func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}
	return strings.Map(repl, s)
}

// minicaFilePath returns the path to the optional ~/.minica config file.
func minicaFilePath() string {
	if p := os.Getenv("MINICA_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".minica")
}

// loadEnvFile reads a ~/.minica file of KEY=VALUE lines into a map. A missing
// file is not an error (returns an empty map). Blank lines and lines beginning
// with '#' are ignored; an optional leading "export " and surrounding single or
// double quotes around the value are stripped.
func loadEnvFile(path string) (map[string]string, error) {
	out := map[string]string{}
	if path == "" {
		return out, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	for n, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s line %d: expected KEY=VALUE", path, n+1)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if key != "" {
			out[key] = val
		}
	}
	return out, nil
}

func prompt(in *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", label)
	}
	line, _ := in.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return def
	}
	return line
}

// --- HTTP client ---

type client struct {
	user, password string
	http           *http.Client
}

func csrfToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newClient(user, password string, insecure bool) *client {
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &client{
		user:     user,
		password: password,
		http:     &http.Client{Timeout: 60 * time.Second, Transport: tr},
	}
}

type certificate struct {
	ID        string `json:"id"`
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	IssueTime int64  `json:"issue_time"`
	ValidDays int64  `json:"valid_days"`
}

type envelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Status  int    `json:"status"`
	} `json:"error"`
}

func (c *client) createCert(baseURL, caID string, body map[string]any) (*certificate, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/api/cas/%s/certs", baseURL, caID)
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Content-Type", "application/json")
	// MiniCA enforces a double-submit CSRF check on mutating API calls: the
	// minica_csrf cookie must equal the X-CSRF-Token header. The token value
	// is otherwise unvalidated, so a fresh random pair satisfies it.
	csrf := csrfToken()
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Cookie", "minica_csrf="+csrf)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("unexpected response (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if !env.Success || resp.StatusCode >= 300 {
		if env.Error != nil {
			return nil, fmt.Errorf("create failed (%s): %s", env.Error.Code, env.Error.Message)
		}
		return nil, fmt.Errorf("create failed: HTTP %d", resp.StatusCode)
	}
	var cert certificate
	if err := json.Unmarshal(env.Data, &cert); err != nil {
		return nil, fmt.Errorf("decoding certificate: %w", err)
	}
	if cert.ID == "" {
		return nil, fmt.Errorf("server returned an empty certificate id")
	}
	return &cert, nil
}

// getCert fetches a certificate's metadata (including issue time and validity)
// by id under a CA.
func (c *client) getCert(baseURL, caID, certID string) (*certificate, error) {
	endpoint := fmt.Sprintf("%s/api/cas/%s/certs/%s", baseURL, caID, certID)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.password)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("unexpected response (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if !env.Success || resp.StatusCode >= 300 {
		if env.Error != nil {
			return nil, fmt.Errorf("get cert failed (%s): %s", env.Error.Code, env.Error.Message)
		}
		return nil, fmt.Errorf("get cert failed: HTTP %d", resp.StatusCode)
	}
	var cert certificate
	if err := json.Unmarshal(env.Data, &cert); err != nil {
		return nil, fmt.Errorf("decoding certificate: %w", err)
	}
	return &cert, nil
}

// renewCert re-issues an existing certificate for the given number of days.
func (c *client) renewCert(baseURL, caID, certID string, days int) error {
	endpoint := fmt.Sprintf("%s/api/cas/%s/certs/%s/renew/%d", baseURL, caID, certID, days)
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.password)
	// Mutating API calls require the double-submit CSRF token pair.
	csrf := csrfToken()
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Cookie", "minica_csrf="+csrf)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("unexpected response (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if !env.Success || resp.StatusCode >= 300 {
		if env.Error != nil {
			return fmt.Errorf("%s: %s", env.Error.Code, env.Error.Message)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// findCertIDByCN looks up an existing certificate id by common name under a CA.
// A 404 means no such certificate (found=false, no error); the common name is
// matched case- and whitespace-insensitively by the server.
func (c *client) findCertIDByCN(baseURL, caID, cn string) (string, bool, error) {
	endpoint := fmt.Sprintf("%s/api/cas/%s/certs_by_cn?cn=%s", baseURL, caID, url.QueryEscape(cn))
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", false, err
	}
	req.SetBasicAuth(c.user, c.password)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", false, fmt.Errorf("unexpected response (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if !env.Success || resp.StatusCode >= 300 {
		if env.Error != nil {
			return "", false, fmt.Errorf("lookup failed (%s): %s", env.Error.Code, env.Error.Message)
		}
		return "", false, fmt.Errorf("lookup failed: HTTP %d", resp.StatusCode)
	}
	var data struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return "", false, fmt.Errorf("decoding lookup response: %w", err)
	}
	if data.ID == "" {
		return "", false, fmt.Errorf("server returned an empty certificate id")
	}
	return data.ID, true, nil
}

// download fetches a raw artifact (PKCS#12, password, CA cert) from a
// download endpoint, returning the body bytes.
func (c *client) download(baseURL, path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.password)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("download %s failed (HTTP %d): %s", path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}
