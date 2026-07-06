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

pub fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<User> {
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
    for user in state.config.auth.users.as_deref().unwrap_or_default() {
        if user.username == username && verify_config_password(&user.password, password) {
            return Ok(User {
                username: user.username.clone(),
                role: user.role,
            });
        }
    }

    // All other accounts live in the database with bcrypt-hashed passwords.
    if let Some(record) = state.service.db().find_user(username)? {
        if bcrypt::verify(password, &record.password_hash).unwrap_or(false) {
            let role = Role::parse(&record.role).unwrap_or(Role::Viewer);
            return Ok(User {
                username: record.username,
                role,
            });
        }
    }

    bail!("invalid username or password")
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
        stored == provided
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
    if cookie_token.is_some() && cookie_token == header_token {
        Ok(())
    } else {
        bail!("CSRF token missing or invalid")
    }
}
