package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeEnvelope writes the standard MiniCA success envelope with the given data.
func writeEnvelope(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"data":    data,
		"error":   null{},
	})
}

type null struct{}

func (null) MarshalJSON() ([]byte, error) { return []byte("null"), nil }

func TestFindCertIDByCNFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cas/ca1/certs_by_cn" && r.URL.Query().Get("cn") == "web.example.com" {
			writeEnvelope(w, map[string]any{"id": "abc123"})
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newClient("admin", "pass", false)
	id, found, err := c.findCertIDByCN(srv.URL, "ca1", "web.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatalf("expected found=true")
	}
	if id != "abc123" {
		t.Fatalf("expected id abc123, got %q", id)
	}
}

func TestFindCertIDByCNNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"data":    nil,
			"error":   map[string]any{"code": "not_found", "message": "nope", "status": 404},
		})
	}))
	defer srv.Close()

	c := newClient("admin", "pass", false)
	id, found, err := c.findCertIDByCN(srv.URL, "ca1", "missing.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatalf("expected found=false")
	}
	if id != "" {
		t.Fatalf("expected empty id, got %q", id)
	}
}

func TestFindCertIDByCNServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newClient("admin", "pass", false)
	if _, _, err := c.findCertIDByCN(srv.URL, "ca1", "web.example.com"); err == nil {
		t.Fatalf("expected error on 500")
	}
}

// reuseServer serves the lookup as a hit plus all download endpoints, and
// records whether create/renew calls were received. The lookup is a hit; the
// cert metadata reports the given issue time / validity so the renew decision
// can be exercised; the renew endpoint replies with renewStatus (0 => 200 OK).
type reuseRecorder struct {
	sawCreate bool
	sawRenew  bool
}

func reuseServer(t *testing.T, rec *reuseRecorder, issueTimeMs, validDays int64, renewStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/cas/ca1/certs_by_cn":
			writeEnvelope(w, map[string]any{"id": "abc123"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/cas/ca1/certs/abc123":
			writeEnvelope(w, map[string]any{
				"id": "abc123", "issue_time": issueTimeMs, "valid_days": validDays,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/cas/ca1/certs/abc123/renew/365":
			rec.sawRenew = true
			if renewStatus != 0 && renewStatus != http.StatusOK {
				w.WriteHeader(renewStatus)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": false, "data": nil,
					"error": map[string]any{"code": "forbidden", "message": "nope", "status": renewStatus},
				})
				return
			}
			writeEnvelope(w, map[string]any{"id": "abc123"})
		case r.Method == http.MethodPut && r.URL.Path == "/api/cas/ca1/certs":
			rec.sawCreate = true
			writeEnvelope(w, map[string]any{"id": "should-not-happen"})
		case r.URL.Path == "/download/cert/ca1/abc123/cert":
			fmt.Fprint(w, "CERT-PEM")
		case r.URL.Path == "/download/cert/ca1/abc123/key":
			fmt.Fprint(w, "KEY-PEM")
		case r.URL.Path == "/download/cert/ca1/abc123/pkcs12":
			fmt.Fprint(w, "P12-BYTES")
		case r.URL.Path == "/download/cert/ca1/abc123/password":
			fmt.Fprint(w, "P12-PASSWORD")
		case r.URL.Path == "/download/ca/ca1/cert":
			fmt.Fprint(w, "CA-PEM")
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
		}
	}))
}

// daysFromNowMs returns an issue_time (ms) such that a cert of the given
// validity has roughly `remainingDays` left from now.
func issueTimeForRemaining(remainingDays, validDays int64) int64 {
	const msPerDay = 86_400_000
	now := timeNowMs()
	return now - (validDays-remainingDays)*msPerDay
}

func setReuseEnv(t *testing.T, srvURL, outDir string) {
	t.Helper()
	t.Setenv("MINICA_CONFIG", filepath.Join(t.TempDir(), "no-such-file"))
	t.Setenv("MINICA_URL", srvURL)
	t.Setenv("MINICA_USER", "admin")
	t.Setenv("MINICA_PASSWORD", "pass")
	t.Setenv("MINICA_CA_ID", "ca1")
	t.Setenv("MINICA_OUT_DIR", outDir)
}

func assertBundle(t *testing.T, outDir, prefix string) {
	t.Helper()
	want := map[string]string{
		prefix + ".pem":          "CERT-PEM",
		prefix + ".key":          "KEY-PEM",
		prefix + ".p12":          "P12-BYTES",
		prefix + ".p12.password": "P12-PASSWORD",
		"CA.pem":                 "CA-PEM",
	}
	for name, content := range want {
		got, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatalf("expected file %s: %v", name, err)
		}
		if strings.TrimSpace(string(got)) != content {
			t.Fatalf("file %s: expected %q, got %q", name, content, string(got))
		}
	}
}

func TestRunCertReusesExistingCert(t *testing.T) {
	var rec reuseRecorder
	// Plenty of validity left (~800 days) => no renewal.
	srv := reuseServer(t, &rec, issueTimeForRemaining(800, 825), 825, 0)
	defer srv.Close()

	outDir := t.TempDir()
	setReuseEnv(t, srv.URL, outDir)

	if err := runCert([]string{"-y", "--cn", "web.example.com", "--name", "reused"}); err != nil {
		t.Fatalf("runCert returned error: %v", err)
	}
	if rec.sawCreate {
		t.Fatalf("create PUT must not be called when the cert already exists")
	}
	if rec.sawRenew {
		t.Fatalf("renew must not be called for a cert far from expiry")
	}
	assertBundle(t, outDir, "reused")
}

func TestNeedsRenew(t *testing.T) {
	const msPerDay = 86_400_000
	now := int64(1_000_000_000_000)
	cases := []struct {
		name        string
		issueTimeMs int64
		validDays   int64
		want        bool
	}{
		{"expires in 200 days", now - 600*msPerDay, 800, true},
		{"expires in 400 days", now - 400*msPerDay, 800, false},
		{"already expired", now - 900*msPerDay, 800, true},
		{"just under a year", now - 1*msPerDay, 365, true},
		{"well over a year", now, 800, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := needsRenew(c.issueTimeMs, c.validDays, now); got != c.want {
				t.Fatalf("needsRenew=%v, want %v", got, c.want)
			}
		})
	}
}

func TestRunCertRenewsExpiringCert(t *testing.T) {
	var rec reuseRecorder
	// ~100 days left => should renew.
	srv := reuseServer(t, &rec, issueTimeForRemaining(100, 825), 825, 0)
	defer srv.Close()

	outDir := t.TempDir()
	setReuseEnv(t, srv.URL, outDir)

	if err := runCert([]string{"-y", "--cn", "web.example.com", "--name", "reused"}); err != nil {
		t.Fatalf("runCert returned error: %v", err)
	}
	if !rec.sawRenew {
		t.Fatalf("renew must be called for a cert expiring within a year")
	}
	assertBundle(t, outDir, "reused")
}

func TestRunCertRenewFailureWarnsAndDownloads(t *testing.T) {
	var rec reuseRecorder
	// Expiring soon, but the renew endpoint refuses (403).
	srv := reuseServer(t, &rec, issueTimeForRemaining(100, 825), 825, http.StatusForbidden)
	defer srv.Close()

	outDir := t.TempDir()
	setReuseEnv(t, srv.URL, outDir)

	if err := runCert([]string{"-y", "--cn", "web.example.com", "--name", "reused"}); err != nil {
		t.Fatalf("renew failure must not be fatal, got: %v", err)
	}
	if !rec.sawRenew {
		t.Fatalf("renew should have been attempted")
	}
	assertBundle(t, outDir, "reused")
}

func TestRunCertCreatesWhenAbsent(t *testing.T) {
	sawCreate := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/cas/ca1/certs_by_cn":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false, "data": nil,
				"error": map[string]any{"code": "not_found", "message": "nope", "status": 404},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/api/cas/ca1/certs":
			sawCreate = true
			writeEnvelope(w, map[string]any{"id": "new123", "cert_pem": "NEW-CERT", "key_pem": "NEW-KEY"})
		case r.URL.Path == "/download/cert/ca1/new123/pkcs12":
			fmt.Fprint(w, "P12-BYTES")
		case r.URL.Path == "/download/cert/ca1/new123/password":
			fmt.Fprint(w, "P12-PASSWORD")
		case r.URL.Path == "/download/ca/ca1/cert":
			fmt.Fprint(w, "CA-PEM")
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	outDir := t.TempDir()
	t.Setenv("MINICA_CONFIG", filepath.Join(t.TempDir(), "no-such-file"))
	t.Setenv("MINICA_URL", srv.URL)
	t.Setenv("MINICA_USER", "admin")
	t.Setenv("MINICA_PASSWORD", "pass")
	t.Setenv("MINICA_CA_ID", "ca1")
	t.Setenv("MINICA_OUT_DIR", outDir)

	err := runCert([]string{"-y", "--cn", "new.example.com", "--name", "fresh"})
	if err != nil {
		t.Fatalf("runCert returned error: %v", err)
	}
	if !sawCreate {
		t.Fatalf("create PUT must be called when the cert does not exist")
	}
	got, err := os.ReadFile(filepath.Join(outDir, "fresh.pem"))
	if err != nil || strings.TrimSpace(string(got)) != "NEW-CERT" {
		t.Fatalf("expected fresh.pem with NEW-CERT, got %q err=%v", string(got), err)
	}
}
