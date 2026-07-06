# Request-Header Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reverse-proxy header authentication mode (user id from `Remote-User`-style header, role from a groups header, optional `trusted_remotes` IP/CIDR allowlist) selected by configuring `auth.headers` instead of `auth.users`.

**Architecture:** `auth::authenticate` gains a dispatch: when `config.auth.headers` is set, identity comes from request headers instead of Basic auth. A middleware stamps the TCP peer IP into a synthetic `x-minica-peer-ip` request header (always overwritten, so unspoofable) so the `HeaderMap`-based auth code can check `trusted_remotes`. The 401 `WWW-Authenticate: Basic` challenge becomes conditional so header mode never triggers a browser login dialog.

**Tech Stack:** Rust (edition 2024), axum 0.8, serde/serde_yaml, new dependency `ipnet` 2.x.

**Spec:** `docs/superpowers/specs/2026-07-06-request-header-auth-design.md`

## Global Constraints

- Exactly one of `auth.users` / `auth.headers` must be configured; both or neither is a `Config::load` error.
- Error message phrases are load-bearing (string-based status mapping in `web.rs`): `"request header"` → 401, `"no authorized group"` → 403, `"untrusted remote"` → 403. Use them verbatim.
- `WWW-Authenticate: Basic realm="MiniCA"` only on 401s from the Basic path (message contains `"Authorization"`, `"username or password"`, or `"Basic auth"`).
- Group parsing accepts `"a,b"`, `"a;b"`, and JSON arrays `["a","b"]`; items trimmed, empties dropped; group-name matching trimmed + case-insensitive; admin wins over viewer.
- `trusted_remotes` empty/absent = trust every peer. Entries are bare IPs (host match) or CIDRs. IPv4-mapped IPv6 peers are canonicalized (`IpAddr::to_canonical`).
- CSRF checks are unchanged in both modes. Basic auth behavior is unchanged.
- Tests live in inline `#[cfg(test)]` modules (codebase convention). Run `cargo test` from the repo root `/home/code/workspace/minica`.

---

### Task 1: Config — `users` XOR `headers`, `HeaderAuthConfig`, `trusted_remotes` parsing

**Files:**
- Modify: `Cargo.toml` (add `ipnet`)
- Modify: `src/config.rs` (AuthConfig, HeaderAuthConfig, validation, tests)
- Modify: `src/auth.rs:30` (users is now `Option`)
- Modify: `src/main.rs:185` (users is now `Option`)
- Modify: `src/main.rs:289-302` (test env constructs AuthConfig)

**Interfaces:**
- Produces: `config::HeaderAuthConfig { username: String, group: String, admin_group: String, viewer_group: String, trusted_remotes: Vec<String>, trusted_networks: Vec<ipnet::IpNet> }` (all fields `pub`), `config::AuthConfig { users: Option<Vec<UserConfig>>, headers: Option<HeaderAuthConfig> }`, `AuthConfig::validate(&mut self) -> Result<()>`.

- [ ] **Step 1: Add the `ipnet` dependency**

In `Cargo.toml`, after the `hex = "0.4"` line, add:

```toml
ipnet = "2"
```

- [ ] **Step 2: Write the failing tests**

Append to `src/config.rs`:

```rust
#[cfg(test)]
mod auth_config_tests {
    use super::*;

    fn parse(yaml: &str) -> AuthConfig {
        serde_yaml::from_str(yaml).expect("parse auth config")
    }

    #[test]
    fn users_only_is_valid_basic_mode() {
        let mut auth = parse("users:\n  - username: a\n    password: p\n    role: admin\n");
        auth.validate().expect("valid");
        assert!(auth.headers.is_none());
    }

    #[test]
    fn headers_only_uses_defaults() {
        let mut auth = parse("headers: {}\n");
        auth.validate().expect("valid");
        let headers = auth.headers.expect("headers config");
        assert_eq!(headers.username, "Remote-User");
        assert_eq!(headers.group, "Remote-Groups");
        assert_eq!(headers.admin_group, "admin");
        assert_eq!(headers.viewer_group, "user");
        assert!(headers.trusted_networks.is_empty());
    }

    #[test]
    fn both_users_and_headers_rejected() {
        let mut auth = parse("users: []\nheaders: {}\n");
        let err = auth.validate().unwrap_err().to_string();
        assert!(err.contains("not both"), "{err}");
    }

    #[test]
    fn neither_users_nor_headers_rejected() {
        let mut auth = parse("{}");
        let err = auth.validate().unwrap_err().to_string();
        assert!(err.contains("configure one of"), "{err}");
    }

    #[test]
    fn empty_users_list_is_valid_basic_mode() {
        let mut auth = parse("users: []\n");
        auth.validate().expect("valid: only DB accounts can log in");
    }

    #[test]
    fn trusted_remotes_parse_ips_and_cidrs() {
        let mut auth =
            parse("headers:\n  trusted_remotes:\n    - 127.0.0.1\n    - 10.0.0.0/8\n    - '::1'\n");
        auth.validate().expect("valid");
        let networks = auth.headers.expect("headers config").trusted_networks;
        assert_eq!(networks.len(), 3);
        let ip = |s: &str| s.parse::<std::net::IpAddr>().expect("test ip");
        assert!(networks[0].contains(&ip("127.0.0.1")));
        assert!(!networks[0].contains(&ip("127.0.0.2")));
        assert!(networks[1].contains(&ip("10.9.8.7")));
        assert!(!networks[1].contains(&ip("11.0.0.1")));
        assert!(networks[2].contains(&ip("::1")));
    }

    #[test]
    fn malformed_trusted_remote_is_named_in_error() {
        let mut auth = parse("headers:\n  trusted_remotes:\n    - 10.0.0.0/33\n");
        let err = auth.validate().unwrap_err().to_string();
        assert!(err.contains("10.0.0.0/33"), "{err}");
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test auth_config_tests 2>&1 | tail -20`
Expected: compile error (`validate` not found / `headers` field missing).

- [ ] **Step 4: Implement the config changes**

In `src/config.rs`, add below the `use` block:

```rust
use ipnet::IpNet;
```

Replace the existing `AuthConfig` struct with:

```rust
#[derive(Clone, Debug, Deserialize)]
pub struct AuthConfig {
    /// Basic-auth bootstrap accounts. Present (even empty) = basic-auth mode.
    #[serde(default)]
    pub users: Option<Vec<UserConfig>>,
    /// Reverse-proxy header auth. Present = header mode; mutually exclusive
    /// with `users`.
    #[serde(default)]
    pub headers: Option<HeaderAuthConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HeaderAuthConfig {
    /// Header carrying the authenticated user id.
    #[serde(default = "default_username_header")]
    pub username: String,
    /// Header carrying the group list ("a,b", "a;b", or JSON ["a","b"]).
    #[serde(default = "default_group_header")]
    pub group: String,
    /// Group name that grants the admin role.
    #[serde(default = "default_admin_group")]
    pub admin_group: String,
    /// Group name that grants the viewer role.
    #[serde(default = "default_viewer_group")]
    pub viewer_group: String,
    /// Peers (bare IPs or CIDRs) allowed to assert identity headers;
    /// empty = trust every remote.
    #[serde(default)]
    pub trusted_remotes: Vec<String>,
    /// Parsed form of `trusted_remotes`, populated by `AuthConfig::validate`.
    #[serde(skip)]
    pub trusted_networks: Vec<IpNet>,
}

fn default_username_header() -> String {
    "Remote-User".to_string()
}

fn default_group_header() -> String {
    "Remote-Groups".to_string()
}

fn default_admin_group() -> String {
    "admin".to_string()
}

fn default_viewer_group() -> String {
    "user".to_string()
}

impl AuthConfig {
    /// Exactly one of `users` (basic auth) or `headers` (reverse-proxy header
    /// auth) selects the authentication mode. Also pre-parses
    /// `trusted_remotes` so bad entries fail at startup, not per-request.
    pub fn validate(&mut self) -> Result<()> {
        match (self.users.is_some(), self.headers.as_mut()) {
            (true, Some(_)) => {
                anyhow::bail!("auth: configure either 'users' or 'headers', not both")
            }
            (false, None) => anyhow::bail!(
                "auth: configure one of 'users' (basic auth) or 'headers' (reverse-proxy header auth)"
            ),
            (false, Some(headers)) => {
                headers.trusted_networks = parse_trusted_remotes(&headers.trusted_remotes)?;
                Ok(())
            }
            (true, None) => Ok(()),
        }
    }
}

fn parse_trusted_remotes(entries: &[String]) -> Result<Vec<IpNet>> {
    entries
        .iter()
        .map(|entry| {
            let trimmed = entry.trim();
            trimmed
                .parse::<IpNet>()
                .or_else(|_| trimmed.parse::<std::net::IpAddr>().map(IpNet::from))
                .map_err(|_| {
                    anyhow::anyhow!("auth.headers.trusted_remotes: invalid IP or CIDR: {entry}")
                })
        })
        .collect()
}
```

In `Config::load` (src/config.rs), after the `let mut config: Config = ...` statement and before the `base_path` normalization, add:

```rust
        config
            .auth
            .validate()
            .with_context(|| format!("invalid auth config in {}", path.display()))?;
```

- [ ] **Step 5: Fix the three `auth.users` consumers**

`src/auth.rs:30` — change:

```rust
    for user in &state.config.auth.users {
```

to:

```rust
    for user in state.config.auth.users.as_deref().unwrap_or_default() {
```

`src/main.rs:185` — change:

```rust
    for user in &config.auth.users {
```

to:

```rust
    for user in config.auth.users.as_deref().unwrap_or_default() {
```

`src/main.rs:289-302` (TestEnv) — change the `auth:` field to:

```rust
                auth: config::AuthConfig {
                    users: Some(vec![
                        config::UserConfig {
                            username: "admin".to_string(),
                            password: "adminpass".to_string(),
                            role: config::Role::Admin,
                        },
                        config::UserConfig {
                            username: "viewer".to_string(),
                            password: "viewerpass".to_string(),
                            role: config::Role::Viewer,
                        },
                    ]),
                    headers: None,
                },
```

- [ ] **Step 6: Run the full test suite**

Run: `cargo test 2>&1 | tail -5`
Expected: all tests pass, including the new `auth_config_tests`.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/config.rs src/auth.rs src/main.rs
git commit -m "feat: auth config takes exactly one of users (basic) or headers (proxy header auth)"
```

---

### Task 2: Group parsing and role mapping (auth.rs)

**Files:**
- Modify: `src/auth.rs`

**Interfaces:**
- Consumes: `config::HeaderAuthConfig` (Task 1), `config::Role`.
- Produces: `fn parse_groups(raw: &str) -> Vec<String>` and `fn role_for_groups(groups: &[String], config: &HeaderAuthConfig) -> Option<Role>` (both private to `auth.rs`; Task 3 calls them from the same file).

- [ ] **Step 1: Write the failing tests**

Append to `src/auth.rs`:

```rust
#[cfg(test)]
mod group_parsing_tests {
    use super::*;
    use crate::config::HeaderAuthConfig;

    fn cfg() -> HeaderAuthConfig {
        HeaderAuthConfig {
            username: "Remote-User".to_string(),
            group: "Remote-Groups".to_string(),
            admin_group: "admin".to_string(),
            viewer_group: "user".to_string(),
            trusted_remotes: Vec::new(),
            trusted_networks: Vec::new(),
        }
    }

    #[test]
    fn splits_on_comma_and_semicolon() {
        assert_eq!(parse_groups("a,b"), vec!["a", "b"]);
        assert_eq!(parse_groups("a;b"), vec!["a", "b"]);
        assert_eq!(parse_groups("a, b; c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn parses_json_array() {
        assert_eq!(parse_groups(r#"["a","b"]"#), vec!["a", "b"]);
        assert_eq!(parse_groups(r#"  [" a ", "b"]  "#), vec!["a", "b"]);
    }

    #[test]
    fn malformed_json_falls_back_to_delimiters() {
        assert_eq!(parse_groups(r#"["a", "b"#), vec![r#"["a""#, r#""b"#]);
    }

    #[test]
    fn drops_empty_items() {
        assert!(parse_groups("").is_empty());
        assert!(parse_groups(" ; , ").is_empty());
        assert_eq!(parse_groups("a,,b;"), vec!["a", "b"]);
    }

    #[test]
    fn admin_group_wins_over_viewer() {
        let groups = vec!["user".to_string(), "admin".to_string()];
        assert_eq!(role_for_groups(&groups, &cfg()), Some(Role::Admin));
    }

    #[test]
    fn group_match_is_case_insensitive() {
        let groups = vec!["ADMIN".to_string()];
        assert_eq!(role_for_groups(&groups, &cfg()), Some(Role::Admin));
        let groups = vec!["User".to_string()];
        assert_eq!(role_for_groups(&groups, &cfg()), Some(Role::Viewer));
    }

    #[test]
    fn unmatched_groups_map_to_no_role() {
        let groups = vec!["ops".to_string(), "dev".to_string()];
        assert_eq!(role_for_groups(&groups, &cfg()), None);
        assert_eq!(role_for_groups(&[], &cfg()), None);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test group_parsing_tests 2>&1 | tail -10`
Expected: compile error (`parse_groups` not found).

- [ ] **Step 3: Implement**

Add to `src/auth.rs` (above the existing `#[cfg(test)]` modules), and extend the first import line to `use crate::{AppState, config::{HeaderAuthConfig, Role}};`:

```rust
/// Parse a groups header value. Accepts a JSON array (`["a","b"]`) or a list
/// split on `,` and `;`. Items are trimmed; empties dropped.
fn parse_groups(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.starts_with('[') {
        if let Ok(items) = serde_json::from_str::<Vec<String>>(trimmed) {
            return items
                .iter()
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect();
        }
    }
    trimmed
        .split([',', ';'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// Admin group membership wins over viewer; no membership means no access.
/// Comparison is trimmed + ASCII case-insensitive.
fn role_for_groups(groups: &[String], config: &HeaderAuthConfig) -> Option<Role> {
    let member_of = |name: &str| {
        let name = name.trim();
        groups.iter().any(|group| group.eq_ignore_ascii_case(name))
    };
    if member_of(&config.admin_group) {
        Some(Role::Admin)
    } else if member_of(&config.viewer_group) {
        Some(Role::Viewer)
    } else {
        None
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test group_parsing_tests 2>&1 | tail -5`
Expected: 7 tests pass. (A dead-code warning for the new fns is fine; Task 3 uses them.)

- [ ] **Step 5: Commit**

```bash
git add src/auth.rs
git commit -m "feat: group-list parsing (csv/semicolon/JSON) and group-to-role mapping"
```

---

### Task 3: Header authentication path (auth.rs)

**Files:**
- Modify: `src/auth.rs`

**Interfaces:**
- Consumes: `parse_groups`, `role_for_groups` (Task 2), `HeaderAuthConfig` (Task 1).
- Produces: `pub const PEER_IP_HEADER: &str = "x-minica-peer-ip"` (used by Task 4's middleware and Task 6's tests); `authenticate` now dispatches to header mode when `config.auth.headers` is set. Error messages contain the load-bearing phrases `"request header"`, `"no authorized group"`, `"untrusted remote"` (Task 5 maps them to statuses).

- [ ] **Step 1: Write the failing tests**

Append to `src/auth.rs`:

```rust
#[cfg(test)]
mod header_auth_tests {
    use super::*;
    use crate::config::HeaderAuthConfig;
    use axum::http::{HeaderName, HeaderValue};

    fn cfg() -> HeaderAuthConfig {
        HeaderAuthConfig {
            username: "Remote-User".to_string(),
            group: "Remote-Groups".to_string(),
            admin_group: "admin".to_string(),
            viewer_group: "user".to_string(),
            trusted_remotes: Vec::new(),
            trusted_networks: Vec::new(),
        }
    }

    fn cfg_trusting(networks: &[&str]) -> HeaderAuthConfig {
        let mut config = cfg();
        config.trusted_remotes = networks.iter().map(ToString::to_string).collect();
        config.trusted_networks = networks
            .iter()
            .map(|entry| {
                entry
                    .parse::<ipnet::IpNet>()
                    .or_else(|_| entry.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                    .expect("valid test network")
            })
            .collect();
        config
    }

    fn request_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                HeaderValue::from_str(value).expect("header value"),
            );
        }
        headers
    }

    #[test]
    fn viewer_group_grants_viewer() {
        let headers = request_headers(&[("Remote-User", "alice"), ("Remote-Groups", "user")]);
        let user = authenticate_headers(&headers, &cfg()).expect("authenticated");
        assert_eq!(user.username, "alice");
        assert_eq!(user.role, Role::Viewer);
    }

    #[test]
    fn header_names_match_case_insensitively_and_admin_wins() {
        let headers = request_headers(&[
            ("remote-user", "bob"),
            ("remote-groups", r#"["USER", " Admin "]"#),
        ]);
        let user = authenticate_headers(&headers, &cfg()).expect("authenticated");
        assert_eq!(user.username, "bob");
        assert_eq!(user.role, Role::Admin);
    }

    #[test]
    fn missing_username_is_request_header_error() {
        let headers = request_headers(&[("Remote-Groups", "user")]);
        let err = authenticate_headers(&headers, &cfg()).unwrap_err().to_string();
        assert!(err.contains("request header"), "{err}");
        assert!(err.contains("Remote-User"), "{err}");
    }

    #[test]
    fn blank_username_is_request_header_error() {
        let headers = request_headers(&[("Remote-User", "   "), ("Remote-Groups", "user")]);
        let err = authenticate_headers(&headers, &cfg()).unwrap_err().to_string();
        assert!(err.contains("request header"), "{err}");
    }

    #[test]
    fn unmatched_groups_are_rejected() {
        let headers = request_headers(&[("Remote-User", "alice"), ("Remote-Groups", "ops;dev")]);
        let err = authenticate_headers(&headers, &cfg()).unwrap_err().to_string();
        assert!(err.contains("no authorized group"), "{err}");
        assert!(err.contains("alice"), "{err}");
    }

    #[test]
    fn missing_group_header_is_rejected() {
        let headers = request_headers(&[("Remote-User", "alice")]);
        let err = authenticate_headers(&headers, &cfg()).unwrap_err().to_string();
        assert!(err.contains("no authorized group"), "{err}");
    }

    #[test]
    fn trusted_peer_in_cidr_is_accepted() {
        let headers = request_headers(&[
            ("Remote-User", "alice"),
            ("Remote-Groups", "user"),
            (PEER_IP_HEADER, "10.1.2.3"),
        ]);
        authenticate_headers(&headers, &cfg_trusting(&["10.0.0.0/8"])).expect("trusted");
    }

    #[test]
    fn untrusted_peer_is_rejected_naming_the_declared_user() {
        let headers = request_headers(&[
            ("Remote-User", "alice"),
            ("Remote-Groups", "user"),
            (PEER_IP_HEADER, "192.168.1.5"),
        ]);
        let err = authenticate_headers(&headers, &cfg_trusting(&["10.0.0.0/8"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("untrusted remote"), "{err}");
        assert!(err.contains("alice"), "{err}");
        assert!(err.contains("192.168.1.5"), "{err}");
    }

    #[test]
    fn ipv4_mapped_peer_matches_ipv4_entry() {
        let headers = request_headers(&[
            ("Remote-User", "alice"),
            ("Remote-Groups", "user"),
            (PEER_IP_HEADER, "::ffff:10.1.2.3"),
        ]);
        authenticate_headers(&headers, &cfg_trusting(&["10.0.0.0/8"])).expect("trusted");
    }

    #[test]
    fn bare_ip_entry_matches_exactly_that_host() {
        let base = &[("Remote-User", "alice"), ("Remote-Groups", "user")];
        let mut ok = request_headers(base);
        ok.insert(PEER_IP_HEADER, HeaderValue::from_static("127.0.0.1"));
        authenticate_headers(&ok, &cfg_trusting(&["127.0.0.1"])).expect("trusted");

        let mut bad = request_headers(base);
        bad.insert(PEER_IP_HEADER, HeaderValue::from_static("127.0.0.2"));
        let err = authenticate_headers(&bad, &cfg_trusting(&["127.0.0.1"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("untrusted remote"), "{err}");
    }

    #[test]
    fn missing_peer_with_trusted_remotes_is_rejected_as_anonymous_when_no_user() {
        let headers = request_headers(&[("Remote-Groups", "user")]);
        let err = authenticate_headers(&headers, &cfg_trusting(&["10.0.0.0/8"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("untrusted remote"), "{err}");
        assert!(err.contains("(anonymous)"), "{err}");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test header_auth_tests 2>&1 | tail -10`
Expected: compile error (`authenticate_headers` / `PEER_IP_HEADER` not found).

- [ ] **Step 3: Implement**

In `src/auth.rs`, add near the top (after the `User` struct):

```rust
/// Synthetic request header carrying the TCP peer IP. Stamped by the
/// `stamp_peer_ip` middleware in web.rs, which always overwrites any inbound
/// value — clients cannot spoof it.
pub const PEER_IP_HEADER: &str = "x-minica-peer-ip";
```

Change `authenticate` to dispatch, inserting at the very top of the existing function body:

```rust
pub fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<User> {
    if let Some(header_config) = &state.config.auth.headers {
        return authenticate_headers(headers, header_config);
    }
    // ... existing Basic-auth body unchanged ...
```

Add the header-mode path:

```rust
/// Reverse-proxy header authentication: identity is asserted by request
/// headers injected by a trusted proxy. No local account is consulted and
/// there is no fallback to Basic auth.
fn authenticate_headers(headers: &HeaderMap, config: &HeaderAuthConfig) -> Result<User> {
    let username = header_value(headers, &config.username);
    if !config.trusted_networks.is_empty() {
        let peer = header_value(headers, PEER_IP_HEADER)
            .and_then(|value| value.parse::<std::net::IpAddr>().ok())
            .map(|ip| ip.to_canonical());
        let trusted = peer
            .map(|ip| config.trusted_networks.iter().any(|net| net.contains(&ip)))
            .unwrap_or(false);
        if !trusted {
            let declared = username.as_deref().unwrap_or("(anonymous)");
            let peer_text = peer.map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
            tracing::warn!(
                user = %declared,
                peer = %peer_text,
                trusted_remotes = ?config.trusted_remotes,
                "header auth rejected: peer not in trusted_remotes"
            );
            bail!("user '{declared}' was declared by untrusted remote {peer_text}");
        }
    }
    let Some(username) = username else {
        tracing::warn!(
            header = %config.username,
            "header auth rejected: missing or empty username header"
        );
        bail!("missing or empty {} request header", config.username);
    };
    let groups = parse_groups(&header_value(headers, &config.group).unwrap_or_default());
    match role_for_groups(&groups, config) {
        Some(role) => Ok(User { username, role }),
        None => {
            tracing::warn!(
                user = %username,
                groups = ?groups,
                admin_group = %config.admin_group,
                viewer_group = %config.viewer_group,
                "header auth rejected: no authorized group"
            );
            bail!("user '{username}' has no authorized group")
        }
    }
}

/// Case-insensitive header lookup returning a trimmed, non-empty value.
fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?.trim();
    (!value.is_empty()).then(|| value.to_string())
}
```

- [ ] **Step 4: Run the full test suite**

Run: `cargo test 2>&1 | tail -5`
Expected: all tests pass (12 new in `header_auth_tests`).

- [ ] **Step 5: Commit**

```bash
git add src/auth.rs
git commit -m "feat: request-header authentication with trusted_remotes peer check"
```

---

### Task 4: Peer-IP middleware and connect-info serving

**Files:**
- Modify: `src/web.rs` (middleware + test)
- Modify: `src/main.rs:222-239` (layer + serve call)

**Interfaces:**
- Consumes: `auth::PEER_IP_HEADER` (Task 3).
- Produces: `pub async fn stamp_peer_ip(ConnectInfo(SocketAddr), Request, Next) -> Response` in `web.rs`, layered onto the app in `main.rs`.

- [ ] **Step 1: Write the failing test**

Append to `src/web.rs`:

```rust
#[cfg(test)]
mod peer_ip_tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        extract::connect_info::MockConnectInfo,
        middleware,
        routing::get,
    };
    use std::net::SocketAddr;
    use tower::ServiceExt;

    #[tokio::test]
    async fn middleware_stamps_peer_ip_and_overwrites_spoofed_value() {
        async fn echo_peer(headers: HeaderMap) -> String {
            headers
                .get(auth::PEER_IP_HEADER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("missing")
                .to_string()
        }

        let app = Router::new()
            .route("/peer", get(echo_peer))
            .layer(middleware::from_fn(stamp_peer_ip))
            .layer(MockConnectInfo(SocketAddr::from(([10, 1, 2, 3], 5555))));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/peer")
                    .header(auth::PEER_IP_HEADER, "1.2.3.4")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("route request");
        let body = to_bytes(response.into_body(), 1024).await.expect("read body");
        assert_eq!(&body[..], b"10.1.2.3");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test peer_ip_tests 2>&1 | tail -10`
Expected: compile error (`stamp_peer_ip` not found).

- [ ] **Step 3: Implement the middleware**

In `src/web.rs`, extend the axum import: add `ConnectInfo` and `Request` to the `extract::{...}` list and add `middleware::Next` (final import shape):

```rust
use axum::{
    Form, Json, Router,
    extract::{
        ConnectInfo, Multipart, Path, Query, Request, State, rejection::JsonRejection,
    },
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, get, post, put},
};
```

Add above `pub fn router`:

```rust
/// Stamps the TCP peer IP into a synthetic request header so auth code that
/// only sees a `HeaderMap` can enforce `trusted_remotes`. Always overwrites
/// any inbound value — clients cannot spoof it. Runs in both auth modes; only
/// header mode reads it.
pub async fn stamp_peer_ip(
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    let ip = peer.ip().to_canonical().to_string();
    let value =
        HeaderValue::from_str(&ip).unwrap_or_else(|_| HeaderValue::from_static("unknown"));
    request.headers_mut().insert(auth::PEER_IP_HEADER, value);
    next.run(request).await
}
```

- [ ] **Step 4: Wire it up in main.rs**

In `src/main.rs` `start_server`, add the layer between `.nest(...)` and `.layer(TraceLayer...)`:

```rust
        .nest(&config.server.base_path, web::router(state))
        .layer(axum::middleware::from_fn(web::stamp_peer_ip))
        .layer(TraceLayer::new_for_http());
```

Change the serve call from `axum::serve(listener, app).await?;` to:

```rust
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
```

- [ ] **Step 5: Run the full test suite and build**

Run: `cargo test 2>&1 | tail -5 && cargo build 2>&1 | tail -3`
Expected: all tests pass; build succeeds.

- [ ] **Step 6: Commit**

```bash
git add src/web.rs src/main.rs
git commit -m "feat: stamp unspoofable peer-IP header via connect-info middleware"
```

---

### Task 5: Status mapping and conditional WWW-Authenticate (web.rs)

**Files:**
- Modify: `src/web.rs:1622-1637` (`status_for_error_message`), `src/web.rs:1497-1502` (`api_error_status`), `src/web.rs:1613-1618` (`error_response`)

**Interfaces:**
- Consumes: error message phrases from Task 3 (`"request header"`, `"no authorized group"`, `"untrusted remote"`).
- Produces: `fn basic_challenge_applies(msg: &str) -> bool` (private). Header-mode 401/403s never carry `WWW-Authenticate`.

- [ ] **Step 1: Write the failing tests**

Append to `src/web.rs`:

```rust
#[cfg(test)]
mod error_mapping_tests {
    use super::*;

    #[test]
    fn header_auth_errors_map_to_statuses() {
        assert_eq!(
            status_for_error_message("missing or empty Remote-User request header"),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_for_error_message("user 'alice' has no authorized group"),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status_for_error_message("user 'alice' was declared by untrusted remote 1.2.3.4"),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn basic_challenge_only_for_basic_auth_messages() {
        assert!(basic_challenge_applies("missing Authorization header"));
        assert!(basic_challenge_applies("invalid username or password"));
        assert!(basic_challenge_applies("invalid Basic auth payload"));
        assert!(!basic_challenge_applies(
            "missing or empty Remote-User request header"
        ));
    }

    #[test]
    fn unauthorized_response_carries_challenge_only_for_basic() {
        let with = api_error_status(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing Authorization header",
        );
        assert!(with.headers().contains_key(header::WWW_AUTHENTICATE));

        let without = api_error_status(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or empty Remote-User request header",
        );
        assert!(!without.headers().contains_key(header::WWW_AUTHENTICATE));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test error_mapping_tests 2>&1 | tail -10`
Expected: compile error (`basic_challenge_applies` not found).

- [ ] **Step 3: Implement**

Replace the first two branches of `status_for_error_message` with:

```rust
fn status_for_error_message(msg: &str) -> StatusCode {
    if msg.contains("Authorization")
        || msg.contains("invalid username or password")
        || msg.contains("Basic auth")
        || msg.contains("request header")
    {
        StatusCode::UNAUTHORIZED
    } else if msg.contains("admin role")
        || msg.contains("no authorized group")
        || msg.contains("untrusted remote")
    {
        StatusCode::FORBIDDEN
```

(remaining branches unchanged). Add next to it:

```rust
/// The browser Basic-auth dialog is only meaningful when Basic auth produced
/// the 401; header-mode rejections must never trigger it.
fn basic_challenge_applies(msg: &str) -> bool {
    msg.contains("Authorization")
        || msg.contains("username or password")
        || msg.contains("Basic auth")
}
```

In `api_error_status`, change the challenge condition from:

```rust
    if status == StatusCode::UNAUTHORIZED {
```

to:

```rust
    if status == StatusCode::UNAUTHORIZED && basic_challenge_applies(message) {
```

In `error_response`, change the same condition from `if status == StatusCode::UNAUTHORIZED {` to:

```rust
    if status == StatusCode::UNAUTHORIZED && basic_challenge_applies(&msg) {
```

- [ ] **Step 4: Run the full test suite**

Run: `cargo test 2>&1 | tail -5`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/web.rs
git commit -m "feat: map header-auth errors to 401/403 and suppress Basic challenge in header mode"
```

---

### Task 6: End-to-end integration tests (main.rs)

**Files:**
- Modify: `src/main.rs` tests module (`TestEnv` at src/main.rs:259-321 and new tests)

**Interfaces:**
- Consumes: everything from Tasks 1–5 (`AuthConfig`, `HeaderAuthConfig`, `auth::PEER_IP_HEADER`, router behavior).
- Produces: nothing new — verification only.

- [ ] **Step 1: Make TestEnv accept an auth config**

In `src/main.rs` tests, split `TestEnv::new` so the auth block is injectable. Replace `fn new() -> Self {` and the `auth:` field with:

```rust
        fn new() -> Self {
            Self::with_auth(config::AuthConfig {
                users: Some(vec![
                    config::UserConfig {
                        username: "admin".to_string(),
                        password: "adminpass".to_string(),
                        role: config::Role::Admin,
                    },
                    config::UserConfig {
                        username: "viewer".to_string(),
                        password: "viewerpass".to_string(),
                        role: config::Role::Viewer,
                    },
                ]),
                headers: None,
            })
        }

        fn with_auth(auth: config::AuthConfig) -> Self {
```

and inside the `Config { ... }` literal use the parameter: `auth,` (the rest of the former `new` body is unchanged).

Add helpers to the tests module:

```rust
    fn header_auth(trusted_remotes: &[&str]) -> config::AuthConfig {
        let mut auth = config::AuthConfig {
            users: None,
            headers: Some(config::HeaderAuthConfig {
                username: "Remote-User".to_string(),
                group: "Remote-Groups".to_string(),
                admin_group: "admin".to_string(),
                viewer_group: "user".to_string(),
                trusted_remotes: trusted_remotes.iter().map(ToString::to_string).collect(),
                trusted_networks: Vec::new(),
            }),
        };
        auth.validate().expect("valid header auth config");
        auth
    }
```

and a request method on `TestEnv` (next to `send`):

```rust
        async fn request_with_headers(
            &self,
            method: &str,
            uri: &str,
            extra: &[(&str, &str)],
        ) -> TestResponse {
            let mut builder = Request::builder().method(method).uri(uri);
            for (name, value) in extra {
                builder = builder.header(*name, *value);
            }
            let response = self
                .app
                .clone()
                .oneshot(builder.body(Body::empty()).expect("build request"))
                .await
                .expect("route request");
            TestResponse::from_response(response).await
        }
```

- [ ] **Step 2: Write the integration tests**

Add to the tests module:

```rust
    #[tokio::test]
    async fn header_auth_viewer_group_can_list_cas() {
        let env = TestEnv::with_auth(header_auth(&[]));
        let response = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[("Remote-User", "alice"), ("Remote-Groups", "user")],
            )
            .await;
        response.assert_status(StatusCode::OK);
    }

    #[tokio::test]
    async fn header_auth_semicolon_groups_and_admin_role() {
        let env = TestEnv::with_auth(header_auth(&[]));
        // viewer-only groups cannot perform admin actions
        let forbidden = env
            .request_with_headers(
                "DELETE",
                "/minica/api/cas/nonexistent",
                &[("Remote-User", "alice"), ("Remote-Groups", "ops;user")],
            )
            .await;
        forbidden.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn header_auth_missing_username_is_401_without_basic_challenge() {
        let env = TestEnv::with_auth(header_auth(&[]));
        let response = env
            .request_with_headers("GET", "/minica/api/cas", &[])
            .await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        assert!(
            !response.headers.contains_key(header::WWW_AUTHENTICATE),
            "header mode must not trigger the browser Basic-auth prompt"
        );
    }

    #[tokio::test]
    async fn header_auth_untrusted_peer_is_403_naming_the_user() {
        let env = TestEnv::with_auth(header_auth(&["10.0.0.0/8"]));
        let response = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[
                    ("Remote-User", "alice"),
                    ("Remote-Groups", "user"),
                    (auth::PEER_IP_HEADER, "192.168.1.5"),
                ],
            )
            .await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body = String::from_utf8_lossy(&response.body);
        assert!(body.contains("alice"), "{body}");
        assert!(body.contains("untrusted remote"), "{body}");
    }

    #[tokio::test]
    async fn header_auth_trusted_peer_is_accepted() {
        let env = TestEnv::with_auth(header_auth(&["10.0.0.0/8"]));
        let response = env
            .request_with_headers(
                "GET",
                "/minica/api/cas",
                &[
                    ("Remote-User", "alice"),
                    ("Remote-Groups", "user"),
                    (auth::PEER_IP_HEADER, "10.1.2.3"),
                ],
            )
            .await;
        response.assert_status(StatusCode::OK);
    }

    #[tokio::test]
    async fn basic_auth_401_still_carries_challenge() {
        let env = TestEnv::new();
        let response = env
            .request_with_headers("GET", "/minica/api/cas", &[])
            .await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        assert!(response.headers.contains_key(header::WWW_AUTHENTICATE));
    }
```

(`TestEnv` cleans up its temp directory via its existing `Drop` impl — no explicit cleanup call is needed.)

- [ ] **Step 3: Run the new tests**

Run: `cargo test header_auth_ 2>&1 | tail -8 && cargo test basic_auth_401 2>&1 | tail -5`
Expected: all 6 tests pass. (These require `/usr/bin/openssl`, like the existing TestEnv tests.)

- [ ] **Step 4: Run the full test suite**

Run: `cargo test 2>&1 | tail -5`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "test: end-to-end header-auth integration coverage"
```

---

### Task 7: Documentation — config.yaml.example and README

**Files:**
- Modify: `config.yaml.example` (auth section)
- Modify: `README.md` (trade-offs bullet at README.md:89-91, new section after Getting started)

**Interfaces:**
- Consumes: final config shape from Task 1. `config.yaml.example` is embedded via `include_str!` (`config::SAMPLE_CONFIG`) — it must stay a valid basic-mode config (commented-out header block only).

- [ ] **Step 1: Update config.yaml.example**

Replace the auth comment block and `auth:` section at the bottom of `config.yaml.example` with:

```yaml
# Authentication: configure EXACTLY ONE of `users:` (Basic auth) or `headers:`
# (reverse-proxy header auth).
#
# Basic auth — only the bootstrap admin is configured here. All other accounts
# (including viewers) are managed in the database via the Admin Console at
# /minica/admin. The password may be a bcrypt hash (recommended:
# `minica --gen-password`) or plaintext. Plaintext still works but logs a
# warning at startup.
auth:
  users:
    - username: admin
      password: adminpass
      role: admin

  # Reverse-proxy header auth — trust an authenticating proxy (Authelia,
  # oauth2-proxy, ...) in front of MiniCA to identify users via request
  # headers. No local account is needed; users are managed entirely by the
  # proxy/IdP and there is no login prompt. Only enable this when MiniCA is
  # reachable exclusively through that proxy, or pin the proxy's address with
  # trusted_remotes. To use it, REPLACE the `users:` block above with:
  #headers:
  #  username: Remote-User        # header carrying the authenticated user id
  #  group: Remote-Groups         # header with the group list; accepts
  #                               # "a,b", "a;b", or a JSON array ["a","b"]
  #  admin_group: admin           # group that grants the admin role
  #  viewer_group: user           # group that grants the viewer role
  #  # Honor identity headers only from these peers (IPs or CIDRs) — typically
  #  # the upstream reverse proxy. Omit or leave empty to trust every remote.
  #  trusted_remotes:
  #    - 127.0.0.1
  #    - 10.0.0.0/8
```

- [ ] **Step 2: Update README.md**

Remove this bullet from *Honest trade-offs* (README.md:89-91):

```markdown
- **No trusted-header (SSO/IAM) auth mode** yet. Authentication is HTTP Basic
  (config bootstrap admin + bcrypt DB users). Put it behind a reverse proxy if
  you need SSO.
```

After the *Getting started* numbered list (before the closing `> **Note:**` block), add:

````markdown
### Reverse-proxy (SSO) header authentication

Instead of Basic auth, MiniCA can trust an authenticating reverse proxy
(Authelia, oauth2-proxy, Traefik forward-auth, ...) to identify users. In this
mode no local account exists at all — configure `auth.headers` **instead of**
`auth.users` (exactly one of the two must be present):

```yaml
auth:
  headers:
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
````

- [ ] **Step 3: Verify the sample config still loads**

Run: `cargo test 2>&1 | tail -5`
Expected: all tests pass (the sample is embedded via `include_str!` and must stay valid basic-mode YAML).

Also verify manually that the commented block round-trips: temporarily uncomment `headers:` through `trusted_remotes` in a scratch copy and load it:

```bash
cd /home/code/workspace/minica
python3 - <<'EOF'
import re
text = open('config.yaml.example').read()
# activate the commented header block, deactivate users
text = text.replace('  users:\n    - username: admin\n      password: adminpass\n      role: admin\n', '')
text = re.sub(r'^  #', '  ', text, flags=re.M)
open('/tmp/claude-1001/-home-code-workspace-minica/51182b67-74b1-4514-a276-6e007fee5302/scratchpad/header-config.yaml', 'w').write(text)
EOF
cargo run -- --start -c /tmp/claude-1001/-home-code-workspace-minica/51182b67-74b1-4514-a276-6e007fee5302/scratchpad/header-config.yaml &
sleep 2
curl -s -H 'Remote-User: alice' -H 'Remote-Groups: user' http://127.0.0.1:9988/minica/api/cas | head -c 200; echo
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9988/minica/api/cas   # expect 401
kill %1
```

Expected: first curl returns a `{"success":true,...}` JSON list; second prints `401`. (Note: `127.0.0.1` is inside the sample `trusted_remotes`, so requests are trusted.)

- [ ] **Step 4: Commit**

```bash
git add config.yaml.example README.md
git commit -m "docs: document reverse-proxy header auth mode in sample config and README"
```
