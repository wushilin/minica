# Design: CLI Probe-and-Reuse Certificate by Common Name

Date: 2026-06-17

## Problem

The Go client (`cli/main.go`, the `cert` command) always tries to *create* a
certificate under a CA. Now that the server enforces per-CA common-name (CN)
uniqueness and exposes a lookup endpoint
(`GET /api/cas/{ca_id}/certs_by_cn?cn=<cn>`), a second run with the same CN
fails the create call with a duplicate error instead of returning the existing
certificate.

## Goal

Before creating, the CLI probes whether the CN already exists under the target
CA. If it does, download the existing certificate and its artifacts instead of
creating a new one.

## Decisions

- **Always probe** (no opt-in flag). Every `cert` run probes first; the create
  call only happens on a miss. This matches "if it exists, just download it" and
  avoids the create call failing on the duplicate CN.
- **Skip create-only prompts on reuse.** Probe right after the CN is known; if
  the cert exists, the create-only questions (country, state, city, org,
  org-unit, key profile, digest, days, hostnames, p12 password) are skipped.
  Only output name and output directory are resolved before downloading.

## Flow

`runCert` becomes:

1. Resolve connection settings (`url`, `user`, `password`, `ca`) and the CN
   (unchanged from today).
2. Build the HTTP client early (it is needed for the probe).
3. Probe `GET {url}/api/cas/{caID}/certs_by_cn?cn=<url-escaped cn>`
   (basic auth, no CSRF — it is a GET):
   - **200** → certificate exists. Resolve output name + dir, download the five
     artifacts, save, print the id, return.
   - **404** → fall through to the existing create flow, unchanged.
   - any other status / transport error → return an error.

## Artifacts on Reuse

The probe response carries only `{ "id": "<cert_id>" }` by design, so all key
material is fetched from the existing download endpoints (kinds verified in
`src/web.rs::cert_download_kind` / `ca_download_kind`):

| File                 | Endpoint                                      |
|----------------------|-----------------------------------------------|
| `<prefix>.pem`       | `/download/cert/{caID}/{id}/cert`             |
| `<prefix>.key`       | `/download/cert/{caID}/{id}/key`              |
| `<prefix>.p12`       | `/download/cert/{caID}/{id}/pkcs12`           |
| `<prefix>.p12.password` | `/download/cert/{caID}/{id}/password`      |
| `CA.pem`             | `/download/ca/{caID}/cert`                    |

File modes match the create path: `.pem`/`CA.pem` = 0644; `.key`/`.p12`/
`.p12.password` = 0600.

## Components / Refactors

Focused refactors in `cli/main.go` to avoid duplication:

- `findCertIDByCN(baseURL, caID, cn string) (id string, found bool, err error)`
  — new method on `client`. GET with basic auth; `404` ⇒ `found=false, err=nil`;
  `>=300` (other) ⇒ error; on `200` parse the standard envelope and read
  `data.id`. Empty id on a 200 is an error.
- `saveBundle(outDir, prefix string, certPEM, keyPEM, p12, p12pw, caPEM []byte)
  (written []string, err error)` — extract the `MkdirAll` + five file writes
  shared by both paths. The create path passes cert/key bytes from the create
  response; the reuse path passes downloaded bytes.
- Output-resolution closures (`resolveOutPrefix`, `resolveOutDir`) defined once
  after the CN is known and used by both branches. `resolveOutPrefix` keeps
  today's logic: `--name` > prompt (interactive) with default `sanitize(cn)` >
  `MINICA_NAME` > `"cert"`. `resolveOutDir`: `--out-dir` > `MINICA_OUT_DIR` >
  `./certs`.
- Add the `net/url` import for `url.QueryEscape` on the CN.

## Output

- Reuse: stderr `Certificate "<cn>" already exists in this CA; downloading.`,
  then stdout `Cert Id is: <id>` and `Saved as <files>` (same as create).
- Create path output unchanged.

## Help Text

Update the `cert` command description (the `usage()` banner) to state that it
first checks for an existing certificate with the same CN under the CA and
downloads it if present, creating one only when absent.

## Testing

New `cli/main_test.go` using `net/http/httptest`. No Go tests exist today.

- `findCertIDByCN`:
  - 200 envelope `{success:true,data:{id:"abc"}}` → `("abc", true, nil)`.
  - 404 → `("", false, nil)`.
  - 500 → error.
- End-to-end **reuse**: a fake server serves `certs_by_cn` 200 and the five
  download endpoints; run `runCert` with `-y` and env pointing `MINICA_URL` at
  the server and `MINICA_OUT_DIR` at a temp dir. Assert the five files exist
  with expected contents and that **no** `PUT /api/cas/{ca}/certs` was received.
- End-to-end **create**: fake server serves `certs_by_cn` 404, the create
  `PUT`, and the download endpoints. Assert the `PUT` was received and files
  were written.

## Non-Goals

- No change to create semantics on a miss.
- No new flags.
- No reuse for the CA artifacts beyond the existing `CA.pem` download.

## Risks

- A CN that contains characters needing escaping is handled via
  `url.QueryEscape`. The server matches case- and whitespace-insensitively, so a
  probe with differing case still finds the cert and triggers reuse.
- The probe adds one extra GET per run; negligible.
