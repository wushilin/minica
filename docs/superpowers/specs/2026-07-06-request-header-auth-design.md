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
  proxy and app). Deployment must ensure the app is unreachable except via
  the proxy — noted in the config example.

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
```

- `AuthConfig` becomes `{ users: Option<Vec<UserConfig>>, headers:
  Option<HeaderAuthConfig> }` (both `#[serde(default)]`).
- `HeaderAuthConfig` fields all have serde defaults matching the values shown
  above, so a bare `headers: {}` works.
- `Config::load` validates: both set → error `auth: configure either
  'users' or 'headers', not both`; neither → error `auth: configure one of
  'users' (basic auth) or 'headers' (reverse-proxy header auth)`.
- `users: []` (present but empty) is valid basic mode: only DB-managed
  accounts can log in.
- The plaintext-password startup warning in `main.rs` iterates
  `users.iter().flatten()`-style over the optional list; in header mode
  there is nothing to warn about.
- `config.yaml.example` documents both forms, with a warning that header mode
  must only be used when the app is reachable exclusively through the proxy.

## Authentication (auth.rs)

`authenticate(headers, state)` dispatches on the mode. `require_viewer`,
`require_admin`, and all call sites in `web.rs` are unchanged.

Header mode (`authenticate_headers(headers, &HeaderAuthConfig)`):

1. **Username**: read the configured username header (axum `HeaderMap`
   lookup is case-insensitive by construction; the configured name is parsed
   into a `HeaderName`). Missing, non-UTF8, or empty/whitespace value →
   `bail!("missing or empty {name} request header")` plus a `tracing::warn!`.
   Maps to 401, no challenge.
2. **Groups**: read the configured group header (missing header = no
   groups) and parse via `parse_groups`:
   - Trim the raw value. If it starts with `[`, try
     `serde_json::from_str::<Vec<String>>`; on success use those items.
   - Otherwise (or if JSON parsing fails), split on **both** `,` and `;`.
   - Trim every item; drop empties.
3. **Role mapping** (comparisons trimmed + case-insensitive):
   - any group == `admin_group` → `Role::Admin` (checked first);
   - else any group == `viewer_group` → `Role::Viewer`;
   - else `bail!("user '{username}' has no authorized group")` plus a
     `tracing::warn!` that includes the groups received and the two expected
     names. Maps to 403.

Basic mode: the existing code path, untouched, now reading
`auth.users.as_deref().unwrap_or_default()`.

## No Login Prompt (web.rs)

Today `error_response` / `api_error_status` attach
`WWW-Authenticate: Basic realm="MiniCA"` to every 401, which triggers the
browser credential dialog. The status/challenge decision is already
string-pattern-based (`status_for_error_message`), so we extend the same
convention rather than threading state through ~20 call sites:

- `status_for_error_message` additions:
  - contains `"request header"` → 401 (header-mode missing identity);
  - contains `"no authorized group"` → 403.
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
- `headers: {}` → defaults `Remote-User` / `Remote-Groups` / `admin` / `user`.

Response mapping:
- Header-mode 401 carries no `WWW-Authenticate`; basic-mode 401 still does.

## Risks

- String-based status mapping means future error messages containing
  `"request header"` or `"no authorized group"` would be misclassified; the
  phrases are distinctive and the mechanism is already the codebase norm.
- Existing configs keep working unchanged (`users:` present → basic mode);
  the only breaking config is one that already had no `auth.users`, which was
  previously a parse error anyway.
