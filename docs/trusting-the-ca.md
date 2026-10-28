# Trusting a MiniCA certificate authority

Certificates issued by MiniCA are only accepted by a client once that client
trusts the issuing CA. This page collects the recipes for the common
platforms and tools. Everything starts from the two public downloads every CA
has (no login needed):

| Download | URL | Use it for |
| --- | --- | --- |
| CA certificate (PEM) | `https://ca.example.com/minica/<ca-id>/download` | everything except Java |
| CA truststore (PKCS#12, password `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java / JVM applications |

Both are also linked from the public CA index at `https://ca.example.com/minica/`
and from the CA page. The file is named after the CA's common name, e.g.
`Homelab_CA.pem`; the examples below call it `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Only the **CA certificate** is ever installed on clients — never a private
key. If the CA is an intermediate, install its root instead (or as well).

## Operating systems

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

This adds the CA to `/etc/ssl/certs/ca-certificates.crt`, which curl, wget,
Python, Go, Node (with `NODE_EXTRA_CA_CERTS` or `--use-openssl-ca`), apt and
most other programs on the system use. `/usr/local/share/ca-certificates/`
is the right place for local additions; `/usr/share/ca-certificates/` belongs
to the distribution's package.

### RHEL / Fedora / CentOS Stream / Alma / Rocky

```sh
sudo cp minica-ca.pem /etc/pki/ca-trust/source/anchors/minica-ca.pem
sudo update-ca-trust
```

### Alpine

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
sudo update-ca-certificates
```

(`apk add ca-certificates` first if `update-ca-certificates` is missing.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Or double-click the file, add it to the *System* keychain in Keychain Access,
open it and set *When using this certificate* to *Always Trust*. Safari and
Chrome use the keychain; Firefox needs the extra step below.

### Windows

As administrator (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

or `certutil -addstore -f Root minica-ca.pem`, or double-click → *Install
Certificate* → *Local Machine* → *Place all certificates in the following
store* → *Trusted Root Certification Authorities*. Edge, Chrome and
.NET/PowerShell use this store; Firefox needs the extra step below.

### Android

Android only installs DER or PEM files with a `.crt`/`.cer` name:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Copy it to the phone, then *Settings → Security → Encryption & credentials →
Install a certificate → CA certificate*. Android 11+ warns that the
certificate must be installed from Settings; that is the path above.
Chrome and most apps then trust it, but apps that pin certificates or ship
their own trust store (and some that use their own network stack) will not.

### iOS / iPadOS

Open the `.pem` on the device (AirDrop, Mail, Files) → *Settings → Profile
Downloaded → Install*, then enable it under *Settings → General → About →
Certificate Trust Settings*.

## Browsers

Chrome, Edge and Safari use the operating system store, so the steps above
are enough. **Firefox** keeps its own store unless told otherwise:

- Preferences → Privacy & Security → Certificates → *View Certificates* →
  *Authorities* → *Import* → tick *Trust this CA to identify websites*; or
- set `security.enterprise_roots.enabled` to `true` in `about:config` to make
  Firefox use the Windows / macOS system store; or
- on Linux, import into the NSS database of the profile:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` from `libnss3-tools` / `nss-tools`).

Chromium on Linux also has an NSS store for user-installed CAs:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Command-line tools and languages

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

After installing the CA into the system store (above) no option is needed.
`CURL_CA_BUNDLE` *replaces* the bundle, so point it at a file that also
contains the public CAs if you need both (e.g. append the MiniCA PEM to a copy
of `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` and the `ssl` module use OpenSSL's default paths,
i.e. the system store, and honour `SSL_CERT_FILE` / `SSL_CERT_DIR`. The
`requests` library (and everything built on it, including `pip`) uses the
`certifi` bundle instead:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

To keep the public CAs as well, append the MiniCA PEM to a copy of certifi's
bundle (`python -m certifi` prints its path) and point the variables at the
copy. `pip install pip-system-certs` or `truststore` makes requests use the
operating-system store instead.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

The CA truststore download is a ready-to-use PKCS#12 truststore (password
`changeit`, the CA stored as a `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

That truststore contains *only* the MiniCA CA. To add the CA to the JDK's
default store instead (so public CAs keep working):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Kafka clients take `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go uses the system store (`crypto/x509` reads `/etc/ssl/certs` on Linux) and
honours `SSL_CERT_FILE` / `SSL_CERT_DIR`. To add a CA from code:

```go
pool, _ := x509.SystemCertPool()
pem, _ := os.ReadFile("minica-ca.pem")
pool.AppendCertsFromPEM(pem)
client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
```

### Node.js

```sh
NODE_EXTRA_CA_CERTS=/path/to/minica-ca.pem node app.js
```

This *adds* to Node's bundled CAs. `--use-openssl-ca` makes Node use the
system store instead.

### yt-dlp

yt-dlp is a Python program and follows the Python rules: with `certifi`
installed (the usual case) it uses certifi's bundle, otherwise OpenSSL's
default store. Either install the CA into the system store and remove /
bypass certifi, or point yt-dlp's HTTP stack at a bundle that contains both:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Avoid `--no-check-certificates`; it turns verification off entirely.

## Servers and services

### Nginx

Three different things are easy to confuse:

- **Serving a MiniCA-issued certificate.** Download the certificate's
  *Bundle* (zip) — `cert.pem`, `cert.key` and `ca.pem` — and use
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Clients then need the CA installed as described on this page.
- **Nginx as a TLS client** (proxying to an upstream that presents a
  MiniCA certificate):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Client certificates (mTLS) issued by MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  The CRL is at `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

For an **image**, add the CA at build time so every tool in the image sees it:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

For a **container you cannot rebuild**, mount a bundle that already contains
the CA (e.g. the host's `/etc/ssl/certs/ca-certificates.crt` after installing
the CA on the host) over the image's bundle, or point the tools inside at it
through the environment variables above:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Images based on distributions that keep the bundle elsewhere
(RHEL-family: `/etc/pki/tls/certs/ca-bundle.crt`) need that path instead.

The Docker *daemon* trusts a private registry's CA from
`/etc/docker/certs.d/<registry:port>/ca.crt`, independent of the system store.

### LLDAP

LLDAP is a server: give it a certificate issued by MiniCA for its LDAPS
listener (download the certificate's bundle; the key is `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

or `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` in the environment. Every LDAP client
(Authelia, Nextcloud, Jellyfin, ...) then needs the MiniCA CA in its own
trust store, per the recipes above for the platform or language it runs on.

## Checking that it works

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` means the client found and trusted the CA.
