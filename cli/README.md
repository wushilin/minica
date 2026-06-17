# minica CLI (Go)

A small client for retrieving certificates from a MiniCA server. It creates a
certificate under a CA and saves the cert, private key, PKCS#12 bundle, the
bundle password, and the issuing CA certificate to disk.

## Build

```sh
cd cli
go build -o minica .
```

## Usage

```sh
minica cert [flags]
```

Connection settings come from the environment (or flags) and are **not**
prompted, so an interactive run starts straight at the certificate questions:

```
$ minica cert
What is your commonName: test1.example.com
What is your country code [US]:
What is your state:
What is your city:
What is your organization [MiniCA]:
What is your organization unit:
Key profile [rsa:4096]:
Digest algorithm [sha256]:
Valid days [825]:
What is your hostnames (comma separated): a.com,b.com,10.0.0.5
Output name (file prefix) [test1.example.com]: test1

Getting certs...
Cert Id is: zeilGBcyHGgP
Saved as test1.pem, test1.key, test1.p12, test1.p12.password, CA.pem
```

Hostnames are one comma-separated list; anything that parses as an IP address is
sent as an IP SAN, everything else as a DNS SAN. The common name is added as a
DNS SAN automatically by the server.

## Configuration

Resolution precedence: **flag > environment > `~/.minica` > interactive prompt**
(the prompt's own default comes from the resolved env value, or a built-in
default).

### `~/.minica` file

Any `MINICA_*` value may be set in a `~/.minica` file of `KEY=VALUE` lines, used
as a fallback when the variable is not set in the process environment. An
optional leading `export ` and
surrounding quotes on the value are stripped; lines starting with `#` are
comments. Override the file location with `MINICA_CONFIG`.

```sh
# ~/.minica
export MINICA_URL=https://ca.example.com/minica
MINICA_USER=admin
MINICA_KEY_PROFILE=ecdsa:secp384r1
MINICA_ORG="Example Corp"
```

### Required (env or flag)

| Env | Flag | Meaning |
| --- | --- | --- |
| `MINICA_URL` | `--url` | Base URL including the base path, e.g. `http://host:9988/minica` |
| `MINICA_USER` | `--user` | Username (must be an **admin**; creating certs requires admin) |
| `MINICA_PASSWORD` | `--password` | Password |
| `MINICA_CA_ID` | `--ca` | Target CA id |

### Certificate fields (env or flag, prompted otherwise)

| Env | Flag | Default | Notes |
| --- | --- | --- | --- |
| `MINICA_CN` | `--cn` | — | Common name (required) |
| `MINICA_COUNTRY` | `--country` | `US` | Required non-empty by the server |
| `MINICA_ORG` | `--org` | `MiniCA` | Required non-empty by the server |
| `MINICA_STATE` | `--state` | _(empty)_ | |
| `MINICA_CITY` | `--city` | _(empty)_ | |
| `MINICA_ORG_UNIT` | `--org-unit` | _(empty)_ | |
| `MINICA_KEY_PROFILE` | `--key-profile` | `rsa:4096` | `rsa:2048\|4096\|8192` or `ecdsa:prime256v1\|secp384r1\|secp521r1` |
| `MINICA_DIGEST` | `--digest` | `sha256` | |
| `MINICA_DAYS` | `--days` | `825` | 1..7350 |
| `MINICA_HOSTNAMES` | `--hostnames` | _(empty)_ | Comma-separated DNS names and/or IPs |
| `MINICA_P12_PASSWORD` | `--p12-password` | server-generated | Blank ⇒ server generates one, downloaded for you |
| `MINICA_NAME` | `--name` | sanitized common name | Output file prefix |

### Other flags

| Flag | Meaning |
| --- | --- |
| `--out-dir` (or `MINICA_OUT_DIR`) | Output directory (default `.`) |
| `-y`, `--non-interactive` | Use flags/env/defaults without prompting |
| `--insecure` (or `MINICA_INSECURE`) | Skip TLS certificate verification |

## Output files

Given an output prefix of `test1`:

| File | Source |
| --- | --- |
| `test1.pem` | `cert_pem` from the create response |
| `test1.key` | `key_pem` from the create response |
| `test1.p12` | `GET /download/cert/{ca}/{cert}/pkcs12` |
| `test1.p12.password` | `GET /download/cert/{ca}/{cert}/password` |
| `CA.pem` | `GET /download/ca/{ca}/cert` |

## Non-interactive example

```sh
MINICA_URL=http://host:9988/minica \
MINICA_USER=admin MINICA_PASSWORD=secret MINICA_CA_ID=TiiKxJtS0Rkf \
minica cert -y \
  --cn test1.example.com \
  --hostnames a.com,b.com,10.0.0.5 \
  --name test1 --out-dir ./out
```

## Notes

- MiniCA enforces a double-submit CSRF check on mutating API calls; the client
  generates a matching `minica_csrf` cookie / `X-CSRF-Token` header pair
  automatically.
- The PKCS#12 password file and the create response are written with `0600`
  permissions; the key with `0600`; cert and CA with `0644`.
