# MiniCA (Rust)

A small Certificate Authority service with a REST API and web UI. Create CAs,
issue certificates, publish CRLs, and download PEM/PKCS#12 bundles — without ever
touching an `openssl` command line.

This is a ground-up Rust rewrite of the original
[minica](./upstream-minica/README.md) (Kotlin + Spring Boot + Angular). It keeps
the same mental model — CAs and certificates managed over a Basic-auth REST API
with admin/viewer roles — while replacing the runtime, storage, and operational
story with something smaller, safer, and easier to run.

## Feature highlights

- **Single static binary, two dependencies.** The service is one Rust binary
  that shells out to `openssl`. There is no JVM, no application server, and no
  JDK `keytool` to install — the only runtime requirement is `openssl` on
  `PATH`. *Rationale:* the original needed JDK 17+, a Spring Boot fat JAR, and
  `keytool`; this removes an entire language runtime from the deployment.

- **Database-backed, durable state.** All CAs, certificates, users, and CRLs
  live in a bundled SQLite database rather than loose files in a directory tree.
  *Rationale:* state is transactional and easy to snapshot, instead of being
  spread across per-CA folders on disk.

- **First-class CRL support.** Every CA gets a CRL that is (re)generated on
  creation, import, and revocation; issued certs can embed a
  `crlDistributionPoints` URL, and the DER CRL is served at `/crl/{ca_id}`.
  *Rationale:* the original had no certificate revocation at all — once issued, a
  cert could not be revoked.

- **Backup & restore.** One YAML export captures everything durable — users
  (bcrypt hashes), active and soft-deleted CAs/certs, all private material,
  `index.txt`/`serial.txt`, and the CRLs — and restores byte-for-byte into an
  empty database inside a transaction. *Rationale:* real disaster recovery from a
  single file, versioned for forward compatibility.

- **Safer multi-user auth.** A single bootstrap admin lives in the config file;
  all other accounts are managed in the database with **bcrypt-hashed**
  passwords via an Admin Console, with admin/viewer roles. *Rationale:* you don't
  keep every user's plaintext password in a properties file.

- **Concurrency-safe revocation.** Revocation takes a per-CA lock and persists
  the new `index.txt`, serial, and CRL atomically, releasing the lock on error.
  *Rationale:* concurrent revokes can't corrupt the CA's OpenSSL database.

- **Soft delete & restore.** CAs and certificates are soft-deleted and can be
  restored from the Admin Console. *Rationale:* an accidental delete is
  recoverable.

- **Bounded, self-cleaning OpenSSL execution.** Each `openssl` invocation runs in
  a throwaway working directory with a wall-clock timeout (SIGTERM then SIGKILL),
  and abandoned workdirs are swept periodically. *Rationale:* a hung or crashed
  subprocess can't leak processes or temp files.

- **OpenAPI / Swagger UI.** The REST API is documented and explorable in-browser
  at `/swagger`. *Rationale:* discoverable, testable API instead of README-only
  docs.

- **Companion Go CLI.** A small [`minica cert` CLI](./cli/README.md) drives the
  API end-to-end — create a cert and save the PEM, key, PKCS#12, its password,
  and the CA cert — configured by flags, `MINICA_*` env vars, or a `~/.minica`
  file. *Rationale:* automate issuance from scripts without hand-rolling the API
  calls and CSRF handling.

## Why this is a better version of minica

| Aspect | Original minica | MiniCA (Rust) |
| --- | --- | --- |
| Runtime | JVM + Spring Boot + JDK `keytool` | Single Rust binary + `openssl` |
| Storage | Per-CA directories on disk | Bundled SQLite database |
| Revocation / CRL | None | CRL generation, revocation, distribution points |
| Backup/restore | Copy the directory tree | One transactional YAML export/restore |
| User passwords | Plaintext in config | Bootstrap admin in config; DB users bcrypt-hashed |
| Delete safety | Hard delete | Soft delete with restore |
| Subprocess safety | — | Timeout-bounded, self-cleaning workdirs |
| Automation | REST API | REST API + OpenAPI/Swagger + Go CLI |

In short: the original proved the model — a friendly REST/UI front end over
`openssl` so you never memorize its flags. This rewrite keeps that ergonomics
win and hardens everything around it: fewer moving parts to deploy, durable and
backup-able state, real revocation, hashed credentials, and safe concurrency.

### Honest trade-offs

- **No JKS / Java truststore output.** Dropping the JDK dependency also drops
  `keytool`-produced JKS keystores and truststores; downloads are PEM and
  PKCS#12. If your toolchain needs JKS, convert from the PKCS#12 bundle.
- **CRLs are not auto-refreshed on a timer.** A CRL is regenerated on
  create/import/revoke, so a quiet CA can serve a CRL past its `nextUpdate` until
  the next change.

## Getting started

1. **Configure.** Generate a starter config from the bundled sample, then edit it:
   ```sh
   minica --gen-config        # writes ./config.yaml (won't overwrite an existing one)
   ```
   Set the server bind/port and `base_path`, `public_base_url` (used for CRL
   distribution URLs and links behind a proxy), the `openssl` path, and the
   bootstrap `admin` user. The bootstrap password may be a **bcrypt hash**
   (recommended — generate one with `minica --gen-password`) or plaintext; a
   plaintext bootstrap password still works but logs a warning at startup. All
   other users are bcrypt-hashed in the DB.

2. **Run the service.**
   ```sh
   cargo run --release -- --start -c config.yaml
   # or, from a built binary:
   ./minica --start -c config.yaml
   ```
   The UI and API are served under `base_path` (default `/minica`); Swagger is at
   `/minica/swagger`. Run `minica --help` to see all actions
   (`--start`, `--gen-config`, `--gen-password`, `--verify-password`).

3. **Issue certs from the CLI.** See [cli/README.md](./cli/README.md):
   ```sh
   cd cli && go build -o mcacli .
   MINICA_URL=http://127.0.0.1:9988/minica MINICA_USER=admin \
   MINICA_PASSWORD=adminpass MINICA_CA_ID=<ca-id> \
   ./mcacli cert --cn test1.example.com --hostnames a.com,b.com,10.0.0.5
   ```

### Environment variables in the config (Docker)

Any value in the config file may be written as `{{ENV:VAR:default}}`: it
resolves to the environment variable `VAR` when set, otherwise to the default
after the second colon (`{{ENV:VAR}}` with no default fails startup when the
variable is unset). Resolution happens after the file is read and before YAML
parsing, so tokens don't need quoting and may expand to any YAML — even lists:

```yaml
auth:
  users:
    enabled: {{ENV:MINICA_BASIC_AUTH_ENABLE:true}}
    list:
      - username: {{ENV:MINICA_ADMIN_USER:admin}}
        password: {{ENV:MINICA_ADMIN_PASSWORD:adminpass}}
        role: admin
  headers:
    enabled: {{ENV:MINICA_HEADER_AUTH_ENABLE:false}}
    trusted_remotes: {{ENV:MINICA_TRUSTED_REMOTES:[]}}
```

[config.yaml.docker](./config.yaml.docker) is a fully parameterised template —
every setting has a `MINICA_*` variable whose default matches
`config.yaml.example`, so it runs unmodified and each value can be overridden
per container:

```sh
docker run -e MINICA_PORT=8443 -e MINICA_ADMIN_PASSWORD='$2b$12$...' \
  -e MINICA_HEADER_AUTH_ENABLE=true -e MINICA_TRUSTED_REMOTES='["10.0.0.7"]' \
  ... minica --start -c config.yaml.docker
```

### Using LibreSSL instead of OpenSSL

MiniCA shells out to the `openssl` binary, and every subcommand it uses
(`genpkey`, `req`, `ca` — including `copy_extensions`, `-gencrl`, `-revoke`,
`-crl_reason` — `crl`, `pkcs12 -export`, `verify`, `x509`) is also provided by
LibreSSL; the one OpenSSL-only flag MiniCA used (`x509 -ext`) has an automatic
fallback. To use LibreSSL, just point the config at its binary:

```yaml
openssl:
  path: /usr/bin/openssl        # OpenBSD (LibreSSL is the system openssl)
  # path: /usr/local/opt/libressl/bin/openssl   # Homebrew libressl
  # path: /usr/bin/eopenssl33                   # some Linux libressl packages
```

Caveats:

- **PKCS#12 encryption defaults.** LibreSSL's `pkcs12 -export` still defaults
  to 3DES for keys and 40-bit RC2 for certificates (OpenSSL 3 uses AES-256 +
  PBKDF2). The resulting `.p12` bundles import fine into Windows, Java, and
  browsers, but *reading* an RC2-encrypted bundle with an OpenSSL 3.x client
  needs its legacy provider (`openssl pkcs12 -legacy ...`).
- Compatibility was verified against the LibreSSL manual and sources; if you
  hit an issue with a specific LibreSSL version, set
  `openssl.keep_failed_workdirs: true` and check the logged command that
  failed.

### Reverse-proxy (SSO) header authentication

Instead of Basic auth, MiniCA can trust an authenticating reverse proxy
(Authelia, oauth2-proxy, Traefik forward-auth, ...) to identify users. In this
mode no local account is needed at all. Both `auth.users` and `auth.headers`
may be configured side by side, each with an `enabled` toggle (default true
when the section is present); **when both are enabled, header auth wins** and
the `users` accounts are ignored. At least one mode must be enabled.

```yaml
auth:
  users:
    enabled: false               # or omit the whole section
    list: []
  headers:
    enabled: true
    username: Remote-User        # header carrying the authenticated user id
    group: Remote-Groups         # header carrying the group list
    admin_group: admin           # group that grants the admin role
    viewer_group: user           # group that grants the viewer role
    # Honor identity headers only from these peers (IPs or CIDRs) — typically
    # the upstream reverse proxy. Omit or leave empty to trust every remote.
    #trusted_remotes:
    #  - 127.0.0.1
    #  - 10.0.0.0/8
```

- The group header accepts `a,b`, `a;b`, or a JSON array `["a","b"]`; group
  names match case-insensitively. Membership in `admin_group` grants the
  admin role, else `viewer_group` grants viewer, else access is denied (403).
- There is no browser login prompt and no fallback to Basic auth in this mode.
- `trusted_remotes` matches the **TCP peer** of the connection, not
  `X-Forwarded-For` — behind a chain of proxies, list the last hop. A request
  from an untrusted peer gets a page naming the declared identity, e.g.
  *user 'xyz' was declared by untrusted remote 192.168.1.5*.
- Only enable this when MiniCA is reachable exclusively through the proxy, or
  pin the proxy with `trusted_remotes`. CSRF protection stays enabled.

> **Note:** Like the original, this is intended for development and internal/test
> environments where standing up a full enterprise PKI is overkill.
