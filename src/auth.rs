use crate::{
    AppState,
    config::{HeaderAuthConfig, Role},
};
use anyhow::{Result, bail};
use axum::http::{HeaderMap, Method};
use base64::Engine;
use rand::{Rng, distr::Alphanumeric};

#[derive(Clone, Debug)]
pub struct User {
    pub username: String,
    pub role: Role,
}

/// Synthetic request header carrying the TCP peer IP. Stamped by the
/// `stamp_peer_ip` middleware in web.rs, which always overwrites any inbound
/// value — clients cannot spoof it.
pub const PEER_IP_HEADER: &str = "x-minica-peer-ip";

pub fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<User> {
    if let Some(header_config) = state.config.auth.active_headers() {
        if header_identity_present(headers, header_config)
            || !state.config.auth.users.as_ref().is_some_and(|users| users.enabled)
        {
            return authenticate_headers(headers, header_config);
        }
    }
    authenticate_basic(headers, state)
}

fn authenticate_basic(headers: &HeaderMap, state: &AppState) -> Result<User> {
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        bail!("missing Authorization header");
    };
    let value = value.to_str().unwrap_or("");
    let Some(encoded) = value.strip_prefix("Basic ") else {
        bail!("unsupported Authorization header");
    };
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let decoded = String::from_utf8_lossy(&decoded);
    let Some((username, password)) = decoded.split_once(':') else {
        bail!("invalid Basic auth payload");
    };

    // Bootstrap accounts come from the config file. Their stored password may be
    // a bcrypt hash or (legacy) plaintext; these exist so the very first admin
    // can log in and manage DB-backed users.
    for user in state.config.auth.basic_users() {
        if user.username == username
            && verify_cached(username, password, &user.password, || {
                verify_config_password(&user.password, password)
            })
        {
            return Ok(User {
                username: user.username.clone(),
                role: user.role,
            });
        }
    }

    // All other accounts live in the database with bcrypt-hashed passwords.
    // Unknown usernames still pay for one bcrypt verification against a dummy
    // hash, so response timing does not reveal which accounts exist.
    match state.service.db().find_user(username)? {
        Some(record) => {
            if verify_cached(username, password, &record.password_hash, || {
                bcrypt::verify(password, &record.password_hash).unwrap_or(false)
            }) {
                let role = Role::parse(&record.role).unwrap_or(Role::Viewer);
                return Ok(User {
                    username: record.username,
                    role,
                });
            }
        }
        None => {
            let _ = bcrypt::verify(password, dummy_bcrypt_hash());
        }
    }

    bail!("invalid username or password")
}

/// How long a successful password check is remembered. Basic auth re-sends
/// the password on every request; without this each click paid a full bcrypt
/// verification.
const LOGIN_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);
const LOGIN_CACHE_MAX: usize = 1024;

/// Runs `verify` unless this exact (username, stored credential, password)
/// succeeded within `LOGIN_CACHE_TTL`. Only successes are cached, keyed by a
/// salted SHA-256 so no password is kept in memory. The stored credential is
/// part of the key, so a password change misses the cache immediately; the
/// caller still looks the account up on every request, so deleted users and
/// role changes take effect at once.
fn verify_cached(username: &str, password: &str, stored: &str, verify: impl FnOnce() -> bool) -> bool {
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;

    static SALT: OnceLock<[u8; 32]> = OnceLock::new();
    static CACHE: OnceLock<Mutex<HashMap<[u8; 32], Instant>>> = OnceLock::new();
    let salt = SALT.get_or_init(|| rand::rng().random());
    let mut hasher = Sha256::new();
    for part in [&salt[..], username.as_bytes(), stored.as_bytes(), password.as_bytes()] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let key: [u8; 32] = hasher.finalize().into();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    let now = Instant::now();
    if cache
        .lock()
        .is_ok_and(|cache| cache.get(&key).is_some_and(|expires| *expires > now))
    {
        return true;
    }
    if !verify() {
        return false;
    }
    if let Ok(mut cache) = cache.lock() {
        if cache.len() >= LOGIN_CACHE_MAX {
            cache.retain(|_, expires| *expires > now);
            if cache.len() >= LOGIN_CACHE_MAX {
                cache.clear();
            }
        }
        cache.insert(key, now + LOGIN_CACHE_TTL);
    }
    true
}

/// A bcrypt hash at the default cost, computed once, used to equalise timing
/// for usernames that do not exist.
fn dummy_bcrypt_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        bcrypt::hash("minica-dummy-password", bcrypt::DEFAULT_COST).unwrap_or_default()
    })
}

/// Reverse-proxy header authentication: identity is asserted by request
/// headers injected by a trusted proxy. No local account is consulted.
fn authenticate_headers(headers: &HeaderMap, config: &HeaderAuthConfig) -> Result<User> {
    let username = header_value(headers, &config.username);
    // An empty trusted list only means "trust everyone" when the operator
    // opted in with `trust_all_remotes` (config validation enforces this at
    // startup; this re-check is defence in depth).
    if !config.trusted_networks.is_empty() || !config.trust_all_remotes {
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

pub fn header_identity_present(headers: &HeaderMap, config: &HeaderAuthConfig) -> bool {
    header_value(headers, &config.username).is_some()
}

/// Case-insensitive header lookup returning a trimmed, non-empty value.
fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

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

/// A stored credential is treated as a bcrypt hash when it carries a recognised
/// bcrypt identifier prefix; otherwise it is legacy plaintext.
pub fn looks_like_bcrypt(stored: &str) -> bool {
    stored.starts_with("$2a$") || stored.starts_with("$2b$") || stored.starts_with("$2y$")
}

/// Verify a provided password against a config-file credential. Bcrypt hashes are
/// verified with bcrypt; anything else is compared as plaintext (a startup
/// warning is emitted for plaintext credentials, so we don't warn per-request).
pub fn verify_config_password(stored: &str, provided: &str) -> bool {
    if looks_like_bcrypt(stored) {
        bcrypt::verify(provided, stored).unwrap_or(false)
    } else {
        ct_eq(stored.as_bytes(), provided.as_bytes())
    }
}

/// Constant-time byte comparison: the running time depends only on the
/// lengths, not on where the inputs first differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// Shape accepted for CSRF tokens: 16..=128 chars of `[A-Za-z0-9_-]`. Covers
/// tokens minted by `csrf_token` (32 alphanumerics) and client-generated ones
/// such as the CLI's 32 hex chars, while rejecting empty or cookie-breaking
/// values.
pub fn is_valid_csrf_token(token: &str) -> bool {
    (16..=128).contains(&token.len())
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Double-submit check: both tokens present, well-formed, and equal.
pub fn csrf_tokens_match(cookie_token: Option<&str>, submitted: Option<&str>) -> bool {
    match (cookie_token, submitted) {
        (Some(cookie), Some(submitted)) => {
            is_valid_csrf_token(cookie) && ct_eq(cookie.as_bytes(), submitted.as_bytes())
        }
        _ => false,
    }
}

pub fn require_viewer(headers: &HeaderMap, state: &AppState) -> Result<User> {
    authenticate(headers, state)
}

pub fn require_admin(headers: &HeaderMap, state: &AppState) -> Result<User> {
    let user = authenticate(headers, state)?;
    if !user.role.can_write() {
        bail!("admin role required");
    }
    Ok(user)
}

pub fn csrf_token() -> String {
    rand::rng()
        .sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod password_tests {
    use super::*;

    #[test]
    fn plaintext_credential_matches_exact() {
        assert!(verify_config_password("adminpass", "adminpass"));
        assert!(!verify_config_password("adminpass", "wrong"));
        assert!(!looks_like_bcrypt("adminpass"));
    }

    #[test]
    fn ct_eq_compares_bytes() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn csrf_tokens_must_be_present_well_formed_and_equal() {
        let token = csrf_token();
        assert!(is_valid_csrf_token(&token));
        assert!(csrf_tokens_match(Some(&token), Some(&token)));
        assert!(!csrf_tokens_match(Some(""), Some("")));
        assert!(!csrf_tokens_match(None, None));
        assert!(!csrf_tokens_match(Some(&token), None));
        assert!(!csrf_tokens_match(Some(&token), Some(&csrf_token())));
        // CLI-style hex tokens are accepted; cookie-breaking ones are not.
        assert!(is_valid_csrf_token("0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_csrf_token("short"));
        assert!(!is_valid_csrf_token("aaaaaaaaaaaaaaaa; Path=/"));
        assert!(!is_valid_csrf_token("aaaaaaaaaaaaaaaa<script>"));
    }

    #[test]
    fn successful_logins_are_cached_per_stored_credential() {
        let calls = std::cell::Cell::new(0);
        let check = |ok: bool| {
            calls.set(calls.get() + 1);
            ok
        };
        let user = "cache-test-user";
        assert!(verify_cached(user, "pw", "hash-1", || check(true)));
        assert!(verify_cached(user, "pw", "hash-1", || check(true)));
        assert_eq!(calls.get(), 1, "second success served from cache");

        // A changed stored credential (password reset) is verified again.
        assert!(!verify_cached(user, "pw", "hash-2", || check(false)));
        // A wrong password is never served from cache, and failures are not cached.
        assert!(!verify_cached(user, "other", "hash-1", || check(false)));
        assert!(!verify_cached(user, "other", "hash-1", || check(false)));
        assert_eq!(calls.get(), 4);
    }

    #[test]
    fn bcrypt_credential_verifies_against_hash() {
        let hash = bcrypt::hash("adminpass", 4).unwrap();
        assert!(looks_like_bcrypt(&hash));
        assert!(verify_config_password(&hash, "adminpass"));
        assert!(!verify_config_password(&hash, "wrong"));
    }
}

#[cfg(test)]
mod group_parsing_tests {
    use super::*;
    use crate::config::HeaderAuthConfig;

    fn cfg() -> HeaderAuthConfig {
        HeaderAuthConfig {
            enabled: true,
            username: "Remote-User".to_string(),
            group: "Remote-Groups".to_string(),
            admin_group: "admin".to_string(),
            viewer_group: "user".to_string(),
            trusted_remotes: Vec::new(),
            trust_all_remotes: true,
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

#[cfg(test)]
mod header_auth_tests {
    use super::*;
    use crate::config::HeaderAuthConfig;
    use axum::http::{HeaderName, HeaderValue};

    fn cfg() -> HeaderAuthConfig {
        HeaderAuthConfig {
            enabled: true,
            username: "Remote-User".to_string(),
            group: "Remote-Groups".to_string(),
            admin_group: "admin".to_string(),
            viewer_group: "user".to_string(),
            trusted_remotes: Vec::new(),
            trust_all_remotes: true,
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
    fn empty_trusted_list_without_opt_in_rejects_everyone() {
        let mut config = cfg();
        config.trust_all_remotes = false;
        let headers = request_headers(&[
            ("Remote-User", "alice"),
            ("Remote-Groups", "user"),
            (PEER_IP_HEADER, "10.1.2.3"),
        ]);
        let err = authenticate_headers(&headers, &config)
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

pub fn check_csrf(method: &Method, headers: &HeaderMap) -> Result<()> {
    if matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS) {
        return Ok(());
    }
    let cookie = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let cookie_token = cookie.split(';').find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        (k == "minica_csrf").then(|| v.to_string())
    });
    let header_token = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    if csrf_tokens_match(cookie_token.as_deref(), header_token.as_deref()) {
        Ok(())
    } else {
        bail!("CSRF token missing or invalid")
    }
}
