# Design: CLI Auto-Renew on Reuse When Expiring Within a Year

Date: 2026-06-17

## Problem

The Go client's reuse path (download an existing certificate when the common
name already exists under a CA) returns whatever validity the stored certificate
has left. A certificate that is close to expiry is downloaded as-is, so the
caller ends up with a short-lived certificate.

## Goal

On the reuse path, if the existing certificate expires within a year, renew it
for 365 days before downloading, so the downloaded artifacts reflect the renewed
validity.

This is entirely client-side: the required endpoints already exist
(`GET /api/cas/{ca}/certs/{id}` returns `issue_time` and `valid_days`;
`POST /api/cas/{ca}/certs/{id}/renew/{days}` re-issues the certificate). No
server changes.

## Decisions

- **Trigger / amount:** renew when the certificate's expiry
  (`issue_time + valid_days * 86_400_000`) is less than 365 days from now
  (already-expired certificates also qualify). Renewal re-issues for 365 days.
  Both numbers are hardcoded constants.
- **Renew failure is non-fatal:** if the renew call fails (e.g. viewer-only
  auth, CA briefly locked), print a warning to stderr and download the current
  (soon-to-expire) certificate. The command still exits 0.
- **Create path untouched:** when the common name is absent, the existing create
  flow runs unchanged.

## Flow (reuse branch of `runCert`)

1. Probe finds the certificate id (unchanged).
2. `GET /api/cas/{caID}/certs/{id}` → read `issue_time` (ms) and `valid_days`.
3. If `needsRenew(issue_time, valid_days, now)`:
   - stderr: `Certificate expires in N days; renewing for 365 days.`
   - `POST /api/cas/{caID}/certs/{id}/renew/365` (basic auth + random CSRF pair,
     same double-submit scheme `createCert` uses).
   - On error: stderr `could not renew (<reason>); downloading current
     certificate.` and continue.
4. Download the five artifacts (cert, key, pkcs12, password, CA cert) **after**
   the renew so they reflect the renewed validity, then save (unchanged).

## Components (all in `cli/main.go`)

- `needsRenew(issueTimeMs, validDays, nowMs int64) bool` — pure helper.
  Returns `true` when `issueTimeMs + validDays*msPerDay - nowMs < renewWithinDays*msPerDay`.
  Unit-testable with no I/O.
- `getCert(baseURL, caID, certID string) (*certificate, error)` — GET, decodes
  the certificate envelope. The existing `certificate` struct gains
  `IssueTime int64 \`json:"issue_time"\`` and `ValidDays int64 \`json:"valid_days"\``.
- `renewCert(baseURL, caID, certID string, days int) error` — POST with the CSRF
  header/cookie pair; parses the envelope and returns an error on non-success,
  which the reuse branch downgrades to a warning.
- Constants: `renewWithinDays = 365`, `renewDays = 365`, `msPerDay = 86_400_000`.

`now` is `time.Now().UnixMilli()`. Server timestamps are milliseconds
(`issue_time` is stored as `timestamp_millis`).

## Output

- Renewing: stderr `Certificate expires in N days; renewing for 365 days.`
- Renew failed: stderr `could not renew (<reason>); downloading current
  certificate.`
- Otherwise unchanged (`Cert Id is: <id>`, `Saved as <files>`).

## Testing (extend `cli/main_test.go`, httptest)

- `needsRenew`: ~200 days remaining → true; ~400 days remaining → false;
  already expired → true; near the 365-day boundary.
- Reuse **with** renewal: lookup hit + `GET certs/{id}` returns a cert expiring
  in ~100 days; assert `POST …/renew/365` was received, then files written.
- Reuse **without** renewal: `GET certs/{id}` returns ~800 days left; assert
  **no** renew call and files written.
- Renew **fails** (renew endpoint returns 403): assert files still written and
  `runCert` returns nil.
- Update the existing reuse test's fake server to also serve
  `GET /api/cas/ca1/certs/abc123` with a long validity (exercises the no-renew
  path).

## Non-Goals

- No renewal on the create path.
- No configurable threshold or renewal length (hardcoded 365/365).
- No change to which artifacts are downloaded.

## Risks

- Renewal re-issues the certificate; the downloaded `.pem` (and PKCS#12) reflect
  the new validity. This is the intended effect. The private key is preserved by
  the server's renew, so the downloaded `.key` stays consistent with prior
  copies.
- One extra `GET` (cert metadata) per reuse, plus one `POST` only when renewing;
  negligible.
