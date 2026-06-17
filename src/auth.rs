use crate::{AppState, config::Role};
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

    // Bootstrap accounts come from the config file (plaintext). These exist so
    // the very first admin can log in and manage DB-backed users.
    for user in &state.config.auth.users {
        if user.username == username && user.password == password {
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
