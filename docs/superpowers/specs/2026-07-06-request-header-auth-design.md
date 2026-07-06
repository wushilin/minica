# Design: Request-Header Authentication (Reverse-Proxy Trust)

Date: 2026-07-06

## Problem

The Kotlin version supported a `request-header` authentication mode for
deployments behind an authenticating reverse proxy (Authelia, oauth2-proxy,
etc.): the proxy injects the verified identity into request headers, and the
app trusts them instead of prompting for credentials. The Rust migration only
implements Basic auth. The old property-style config was:

```
authentication.mode=request-header
request-header.name.username=Remote-User
request-header.name.group=Remote-Groups
request-header.group.admin.name=admin
request-header.group.viewer.name=user
```

## Goals

1. Support header-based authentication: user id from a configurable username
   header, role derived from a configurable groups header.
2. No browser login prompt in this mode (no `WWW-Authenticate` challenge).
3. Groups header parses in three formats: `"a,b"`, `"a;b"`, and JSON array
   `["a","b"]`.
4. Users are entirely externally managed in this mode — no local user (config
   or DB) needs to exist.
5. Optional `trusted_remotes` allowlist of IPs/CIDRs: when set, the identity
   headers are only honored if the TCP peer address (typically the reverse
   proxy) is in the list; otherwise the request is rejected with a page that
   names the declared user and explains the source is untrusted. Default
   (absent/empty) trusts every remote.

## Non-Goals

- No fallback from header auth to Basic auth (or vice versa). The mode is
  exclusive; the proxy is the only trust source.
- CSRF protection is unchanged and stays enforced in both modes (ambient
  proxy auth makes CSRF more relevant, not less).
- The admin-console Users page stays visible and functional in header mode
  (per user decision). Its accounts simply have no effect on authentication
  while header mode is active; they become effective again if the operator
  switches back to `users:`.
- No signature/secret validation of the proxy headers (e.g. mTLS between
  proxy and app). `trusted_remotes` restricts which peers may assert
  identity headers; beyond that, deployment must ensure the app is
  unreachable except via the proxy — noted in the config example.

## Config (config.rs)

The `auth:` section takes **exactly one** of two keys; the key present selects
the mode:

```yaml
# Basic auth (current behavior)
auth:
  users:
    - username: admin
      password: adminpass   # bcrypt hash recommended
      role: admin

# Header auth: trust the reverse proxy; no local users at all
auth:
  headers:
    username: Remote-User    # header carrying the user id
    group: Remote-Groups     # header carrying the group list
    admin_group: admin       # group name that grants the admin role
    viewer_group: user       # group name that grants the viewer role
    # Only honor the headers when the TCP peer is one of these IPs/CIDRs
    # (typically the reverse proxy). Absent or empty = trust every remote.
    trusted_remotes:
      - 127.0.0.1
      - 10.0.0.0/8
```

- `AuthConfig` becomes `{ users: Option<Vec<UserConfig>>, headers:
  Option<HeaderAuthConfig> }` (both `#[serde(default)]`).
- `HeaderAuthConfig` fields all have serde defaults matching the values shown
  above, so a bare `headers: {}` works. `trusted_remotes` defaults to an
  empty list (trust everyone).
- `trusted_remotes` entries are strings, validated in `Config::load`: each
  must parse as a CIDR (`ipnet::IpNet`) or a bare IP (treated as a host
  network, `/32` or `/128`). A malformed entry fails startup with a message
  naming the bad entry. The parsed `Vec<IpNet>` is stored alongside the raw
  strings (`#[serde(skip)]` field populated during load). New dependency:
  `ipnet` (small, std-only).
- `Config::load` validates: both set → error `auth: configure either
  'users' or 'headers', not both`; neither → error `auth: configure one of
  'users' (basic auth) or 'headers' (reverse-proxy header auth)`.
- `users: []` (present but empty) is valid basic mode: only DB-managed
  accounts can log in.
- The plaintext-password startup warning in `main.rs` iterates
  `users.iter().flatten()`-style over the optional list; in header mode
  there is nothing to warn about.
- `config.yaml.example` keeps the active `users:` block and gains a
  **commented-out** dummy `headers:` block (all four header/group fields plus
  a commented `trusted_remotes` list), with a warning that header mode must
  only be used when the app is reachable exclusively through the proxy — or
  with `trusted_remotes` pinned to the proxy's address.
- `README.md` documents the header-auth mode: the same commented dummy YAML
  snippet, the group-format examples (`a,b` / `a;b` / `["a","b"]`), the
  `trusted_remotes` semantics, and removal of the "No trusted-header
  (SSO/IAM) auth mode yet" bullet from *Honest trade-offs*.

## Authentication (auth.rs)

`authenticate(headers, state)` dispatches on the mode. `require_viewer`,
`require_admin`, and all call sites in `web.rs` are unchanged.

Header mode (`authenticate_headers(headers, &HeaderAuthConfig)`):

1. **Remote trust**: when `trusted_remotes` is non-empty, check the TCP peer
   IP (see "Peer IP plumbing" below) against the parsed networks. IPv4-mapped
   IPv6 peers (`::ffff:a.b.c.d`) are canonicalized to IPv4
   (`IpAddr::to_canonical`) before matching. If the peer is not in any
   network, read the declared username anyway (for the message only) and
   `bail!("user '{username}' was declared by untrusted remote {ip}")`, with
   a `tracing::warn!` naming the peer and the configured networks. Maps to
   403; the HTML error page therefore reads e.g. *user 'xyz' was declared by
   untrusted remote 192.168.1.5* (declared user shown as `(anonymous)` when
   the username header is absent). Empty/absent list skips this check
   entirely (trust everyone).
2. **Username**: read the configured username header (axum `HeaderMap`
   lookup is case-insensitive by construction; the configured name is parsed
   into a `HeaderName`). Missing, non-UTF8, or empty/whitespace value →
   `bail!("missing or empty {name} request header")` plus a `tracing::warn!`.
   Maps to 401, no challenge.
3. **Groups**: read the configured group header (missing header = no
   groups) and parse via `parse_groups`:
   - Trim the raw value. If it starts with `[`, try
     `serde_json::from_str::<Vec<String>>`; on success use those items.
   - Otherwise (or if JSON parsing fails), split on **both** `,` and `;`.
   - Trim every item; drop empties.
4. **Role mapping** (comparisons trimmed + case-insensitive):
   - any group == `admin_group` → `Role::Admin` (checked first);
   - else any group == `viewer_group` → `Role::Viewer`;
   - else `bail!("user '{username}' has no authorized group")` plus a
     `tracing::warn!` that includes the groups received and the two expected
     names. Maps to 403.

Basic mode: the existing code path, untouched, now reading
`auth.users.as_deref().unwrap_or_default()`.

## Peer IP Plumbing (main.rs, web.rs)

The auth functions only receive a `HeaderMap`, and ~20 handlers pass it
through; threading a `ConnectInfo` extractor into every handler would be
invasive. Instead:

- `main.rs` serves with
  `app.into_make_service_with_connect_info::<SocketAddr>()` so the peer
  address is available at all.
- A small middleware (`axum::middleware::from_fn`) at the top of the router
  **always sets** a synthetic request header `x-minica-peer-ip` to the
  `ConnectInfo` peer IP — overwriting any inbound value, so a client can
  never spoof it.
- `authenticate_headers` reads the peer IP from that header. If it is absent
  or unparsable (cannot happen once the middleware is installed, but
  defensively) and `trusted_remotes` is non-empty, the request is rejected
  as untrusted.

The middleware runs in both auth modes (it's cheap); only header mode reads
the value.

## No Login Prompt (web.rs)

Today `error_response` / `api_error_status` attach
`WWW-Authenticate: Basic realm="MiniCA"` to every 401, which triggers the
browser credential dialog. The status/challenge decision is already
string-pattern-based (`status_for_error_message`), so we extend the same
convention rather than threading state through ~20 call sites:

- `status_for_error_message` additions:
  - contains `"request header"` → 401 (header-mode missing identity);
  - contains `"no authorized group"` → 403;
  - contains `"untrusted remote"` → 403.
- The challenge becomes positive-matched: attach `WWW-Authenticate` only when
  status is 401 **and** the message is from the Basic path (contains
  `"Authorization"`, `"Basic auth"`, or `"username or password"`). Header-mode
  401s therefore never carry a challenge.

## Testing

Inline `#[cfg(test)]` modules, matching the codebase convention.

`parse_groups`:
- `"a,b"` → `[a, b]`; `"a;b"` → `[a, b]`; mixed `"a, b; c"` → `[a, b, c]`.
- `["a","b"]` JSON → `[a, b]`; JSON with surrounding whitespace still parses.
- Malformed JSON (`["a",`) falls back to delimiter splitting.
- Empty string / only delimiters → `[]`.

Role mapping / `authenticate_headers` (via a constructed `HeaderMap`):
- Groups containing the admin group (any case, padded) → Admin.
- Only the viewer group → Viewer; admin wins when both present.
- Unmatched groups or missing group header → "no authorized group" error.
- Missing or empty username header → "request header" error.
- Header name lookup is case-insensitive (config `remote-user`, request
  `Remote-User`).

Config validation:
- Both `users` and `headers` set → load error.
- Neither set → load error.
- `headers: {}` → defaults `Remote-User` / `Remote-Groups` / `admin` / `user`,
  empty `trusted_remotes`.
- `trusted_remotes` entries: bare IPv4/IPv6, CIDR forms parse; garbage
  (`"10.0.0.0/33"`, `"proxy"`) fails load with the entry named.

Trusted remotes:
- Empty list → any peer accepted.
- Peer inside a CIDR → accepted; outside all entries → "untrusted remote"
  error carrying the declared username.
- Bare-IP entry matches exactly that host.
- IPv4-mapped IPv6 peer (`::ffff:10.0.0.1`) matches an IPv4 entry.
- Missing peer header with non-empty `trusted_remotes` → rejected.

Response mapping:
- Header-mode 401 carries no `WWW-Authenticate`; basic-mode 401 still does.
- "untrusted remote" / "no authorized group" messages → 403.

## Risks

- String-based status mapping means future error messages containing
  `"request header"`, `"no authorized group"`, or `"untrusted remote"` would
  be misclassified; the phrases are distinctive and the mechanism is already
  the codebase norm.
- `trusted_remotes` checks the **TCP peer**, not `X-Forwarded-For`. Behind a
  chain of proxies the peer is the last hop; the config must list that hop.
  Documented in the README.
- `into_make_service_with_connect_info` changes the serve call; behavior for
  basic mode is otherwise identical.
- Existing configs keep working unchanged (`users:` present → basic mode);
  the only breaking config is one that already had no `auth.users`, which was
  previously a parse error anyway.
