use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub public_base_url: Option<String>,
    #[serde(default)]
    pub crl: CrlConfig,
    pub runtime: RuntimeConfig,
    pub openssl: OpenSslConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub base_path: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RuntimeConfig {
    pub folder: PathBuf,
    pub db_folder: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenSslConfig {
    pub path: PathBuf,
    /// Maximum wall-clock time a single openssl invocation may run before it is
    /// terminated. Defaults to 15s when omitted from the config file.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    pub working_root: PathBuf,
    pub keep_failed_workdirs: bool,
    pub reap_after_hours: u64,
}

fn default_timeout_seconds() -> u64 {
    15
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthConfig {
    /// Basic-auth section (bootstrap accounts + enabled toggle).
    #[serde(default)]
    pub users: Option<UsersConfig>,
    /// Reverse-proxy header auth. When present and enabled it wins over
    /// basic auth, so both sections can coexist in one config template.
    #[serde(default)]
    pub headers: Option<HeaderAuthConfig>,
}

fn default_true() -> bool {
    true
}

/// Basic-auth section: an `enabled` toggle plus the bootstrap account list.
/// Accepts either the object form (`enabled:` + `list:`) or, for backward
/// compatibility, a bare account list (which implies `enabled: true`).
#[derive(Clone, Debug, Deserialize)]
#[serde(from = "UsersConfigRepr")]
pub struct UsersConfig {
    pub enabled: bool,
    pub list: Vec<UserConfig>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum UsersConfigRepr {
    List(Vec<UserConfig>),
    Object {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(default)]
        list: Vec<UserConfig>,
    },
}

impl From<UsersConfigRepr> for UsersConfig {
    fn from(repr: UsersConfigRepr) -> Self {
        match repr {
            UsersConfigRepr::List(list) => Self {
                enabled: true,
                list,
            },
            UsersConfigRepr::Object { enabled, list } => Self { enabled, list },
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct HeaderAuthConfig {
    /// Toggle for this mode; on by default when the section is present.
    #[serde(default = "default_true")]
    pub enabled: bool,
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
    /// At least one auth mode must be enabled. Header auth is active when
    /// identity headers are present; enabled Basic auth remains available as a
    /// fallback for requests without identity headers. Also pre-parses
    /// `trusted_remotes` so bad entries fail at startup, not per-request.
    pub fn validate(&mut self) -> Result<()> {
        if let Some(headers) = self.headers.as_mut().filter(|headers| headers.enabled) {
            headers.trusted_networks = parse_trusted_remotes(&headers.trusted_remotes)?;
            return Ok(());
        }
        if self.users.as_ref().is_some_and(|users| users.enabled) {
            return Ok(());
        }
        anyhow::bail!(
            "auth: no authentication mode enabled — enable 'users' (basic auth) or 'headers' (reverse-proxy header auth)"
        )
    }

    /// The header-auth config when that mode is active (present and enabled).
    pub fn active_headers(&self) -> Option<&HeaderAuthConfig> {
        self.headers.as_ref().filter(|headers| headers.enabled)
    }

    /// Bootstrap accounts for basic auth; empty when disabled or absent.
    pub fn basic_users(&self) -> &[UserConfig] {
        self.users
            .as_ref()
            .filter(|users| users.enabled)
            .map(|users| users.list.as_slice())
            .unwrap_or_default()
    }
}

/// Resolve `{{ENV:NAME}}` / `{{ENV:NAME:default}}` tokens against environment
/// variables. Runs on the raw config text after the file is read and before
/// YAML parsing (unquoted tokens are not valid YAML), so any value in the
/// file can be injected via the environment -- handy for Docker.
fn resolve_env_tokens(text: &str) -> Result<String> {
    let (resolved, used_names) =
        resolve_env_tokens_with_used(text, |name| std::env::var(name).ok())?;
    warn_unused_minica_env_vars(&used_names);
    Ok(resolved)
}

#[cfg(test)]
fn resolve_env_tokens_with(text: &str, lookup: impl Fn(&str) -> Option<String>) -> Result<String> {
    resolve_env_tokens_with_used(text, lookup).map(|(resolved, _)| resolved)
}

fn resolve_env_tokens_with_used(
    text: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<(String, HashSet<String>)> {
    const OPEN: &str = "{{ENV:";
    const CLOSE: &str = "}}";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut used_names = HashSet::new();
    while let Some(start) = rest.find(OPEN) {
        out.push_str(&rest[..start]);
        let token = &rest[start..];
        let Some(end) = token.find(CLOSE) else {
            anyhow::bail!("unterminated {{{{ENV:...}}}} token");
        };
        // NAME or NAME:default. The default may itself contain colons and is
        // percent-decoded so awkward values like "}}" can be written safely.
        let inner = &token[OPEN.len()..end];
        let (name, default) = match inner.split_once(':') {
            Some((name, default)) => (name.trim(), Some(url_decode_best_effort(default.trim()))),
            None => (inner.trim(), None),
        };
        if name.is_empty() {
            anyhow::bail!("empty variable name in {{{{ENV:...}}}} token");
        }
        used_names.insert(name.to_string());
        let value = lookup(name).or(default).unwrap_or_default();
        if value.is_empty() {
            eprintln!("config env {name} -> <empty>");
        } else {
            eprintln!("config env {name} -> {}", mask_env_value(name, &value));
        }
        out.push_str(&value);
        rest = &token[end + CLOSE.len()..];
    }
    out.push_str(rest);
    Ok((out, used_names))
}

fn url_decode_best_effort(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                decoded.push((high << 4) | low);
                changed = true;
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    if !changed {
        return value.to_string();
    }
    String::from_utf8(decoded).unwrap_or_else(|_| value.to_string())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn warn_unused_minica_env_vars(used_names: &HashSet<String>) {
    let mut unused: Vec<String> = std::env::vars()
        .map(|(name, _)| name)
        .filter(|name| name.starts_with("MINICA_") && !used_names.contains(name))
        .collect();
    unused.sort();

    for name in unused {
        eprintln!("warning: unused MINICA_ environment variable: {name}");
    }
}

fn mask_env_value(name: &str, value: &str) -> String {
    if !is_sensitive_env_name(name) {
        return value.to_string();
    }

    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 2 {
        return value.to_string();
    }

    let mut masked = String::with_capacity(value.len());
    masked.push(chars[0]);
    masked.extend(std::iter::repeat('*').take(chars.len() - 2));
    masked.push(chars[chars.len() - 1]);
    masked
}

fn is_sensitive_env_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("password")
        || name.contains("passwword")
        || name.contains("passwd")
        || name.contains("passphrase")
}

fn parse_trusted_remotes(entries: &[String]) -> Result<Vec<IpNet>> {
    entries
        .iter()
        // '-' (and empty) means "not specified" — it is the placeholder default
        // used by env-templated configs (MINICA_TRUSTED_REMOTE_1..10 in
        // config.yaml.docker), so unset slots drop out of the list.
        .filter(|entry| {
            let trimmed = entry.trim();
            !trimmed.is_empty() && trimmed != "-"
        })
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

#[derive(Clone, Debug, Deserialize)]
pub struct LoggingConfig {
    pub file: PathBuf,
    pub rotate_size_bytes: u64,
    pub max_backups: usize,
    pub compress: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CrlConfig {
    pub enabled: bool,
    pub next_update_days: i64,
}

impl Default for CrlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            next_update_days: 30,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            file: PathBuf::from("./logs/minica.log"),
            rotate_size_bytes: 10 * 1024 * 1024,
            max_backups: 10,
            compress: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct UserConfig {
    pub username: String,
    pub password: String,
    pub role: Role,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Viewer,
}

impl Role {
    pub fn can_write(self) -> bool {
        matches!(self, Self::Admin)
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "admin" => Some(Self::Admin),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Viewer => "viewer",
        }
    }
}

/// The sample configuration, bundled into the binary at compile time. Exposed
/// to users via the `--gen-config` flag.
pub const SAMPLE_CONFIG: &str = include_str!("../config.yaml.example");

impl Config {
    /// Write the bundled sample config to `config.yaml` in the current
    /// directory, refusing to clobber an existing file. Backs the
    /// `--gen-config` flag.
    pub fn gen_config() -> Result<PathBuf> {
        let path = PathBuf::from("config.yaml");
        if path.exists() {
            anyhow::bail!(
                "{} already exists; remove it first or write the sample elsewhere",
                path.display()
            );
        }
        fs::write(&path, SAMPLE_CONFIG)
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(path)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let text = resolve_env_tokens(&text).with_context(|| {
            format!(
                "failed to resolve {{{{ENV:...}}}} tokens in {}",
                path.display()
            )
        })?;
        let mut config: Config = serde_yaml::from_str(&text)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        config
            .auth
            .validate()
            .with_context(|| format!("invalid auth config in {}", path.display()))?;
        if !config.server.base_path.starts_with('/') {
            config.server.base_path = format!("/{}", config.server.base_path);
        }
        if config.server.base_path.ends_with('/') && config.server.base_path.len() > 1 {
            config.server.base_path.pop();
        }
        if let Some(base) = config.public_base_url.as_mut() {
            while base.ends_with('/') {
                base.pop();
            }
        }
        if config.crl.next_update_days < 1 {
            config.crl.next_update_days = 30;
        }
        Ok(config)
    }

    pub fn addr(&self) -> Result<SocketAddr> {
        format!("{}:{}", self.server.host, self.server.port)
            .parse()
            .context("invalid server host/port")
    }

    pub fn db_path(&self) -> PathBuf {
        self.runtime
            .db_folder
            .clone()
            .unwrap_or_else(|| self.runtime.folder.clone())
            .join("db.sqlite")
    }
}

#[cfg(test)]
mod env_token_tests {
    use super::*;

    fn lookup(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    }

    #[test]
    fn set_variable_is_substituted() {
        let out = resolve_env_tokens_with("user: {{ENV:U:admin}}", lookup(&[("U", "alice")]))
            .expect("resolves");
        assert_eq!(out, "user: alice");
    }

    #[test]
    fn unset_variable_falls_back_to_default() {
        let out = resolve_env_tokens_with("user: {{ENV:U:admin}}", lookup(&[])).expect("resolves");
        assert_eq!(out, "user: admin");
    }

    #[test]
    fn default_may_be_empty_or_contain_colons() {
        let out = resolve_env_tokens_with("x: {{ENV:A:}}", lookup(&[])).expect("resolves");
        assert_eq!(out, "x: ");
        let out =
            resolve_env_tokens_with("url: {{ENV:B:http://h:99/p}}", lookup(&[])).expect("resolves");
        assert_eq!(out, "url: http://h:99/p");
    }

    #[test]
    fn unset_variable_without_default_resolves_to_empty() {
        let out = resolve_env_tokens_with("user: {{ENV:MISSING}}", lookup(&[])).expect("resolves");
        assert_eq!(out, "user: ");
    }

    #[test]
    fn names_and_defaults_are_trimmed() {
        let out =
            resolve_env_tokens_with("x: {{ENV: A :  fallback  }}", lookup(&[])).expect("resolves");
        assert_eq!(out, "x: fallback");

        let out = resolve_env_tokens_with("x: {{ENV: A :  fallback  }}", lookup(&[("A", "set")]))
            .expect("resolves");
        assert_eq!(out, "x: set");
    }

    #[test]
    fn default_is_percent_decoded_best_effort() {
        let out = resolve_env_tokens_with("x: {{ENV:A:a%3Ab%20%7D%7D}} trailing", lookup(&[]))
            .expect("resolves");
        assert_eq!(out, "x: a:b }} trailing");

        let out = resolve_env_tokens_with("x: {{ENV:A:%ZZ%7D}}", lookup(&[])).expect("resolves");
        assert_eq!(out, "x: %ZZ}");
    }

    #[test]
    fn multiple_tokens_resolve_independently() {
        let out =
            resolve_env_tokens_with("a: {{ENV:A:1}}\nb: {{ENV:B:2}}\n", lookup(&[("B", "bee")]))
                .expect("resolves");
        assert_eq!(out, "a: 1\nb: bee\n");
    }

    #[test]
    fn resolved_tokens_report_used_env_names() {
        let (out, used) =
            resolve_env_tokens_with_used("a: {{ENV:A:1}}\nb: {{ENV:B:2}}\n", lookup(&[]))
                .expect("resolves");
        assert_eq!(out, "a: 1\nb: 2\n");
        assert!(used.contains("A"));
        assert!(used.contains("B"));
        assert_eq!(used.len(), 2);
    }

    #[test]
    fn text_without_tokens_is_unchanged() {
        let text = "plain: value\ncurly: {not-a-token}\n";
        assert_eq!(
            resolve_env_tokens_with(text, lookup(&[])).expect("resolves"),
            text
        );
    }

    #[test]
    fn unterminated_token_is_an_error() {
        let err = resolve_env_tokens_with("user: {{ENV:U:admin", lookup(&[]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("unterminated"), "{err}");
    }

    #[test]
    fn resolved_unquoted_token_yields_parseable_yaml() {
        let yaml = "users:\n  - username: {{ENV:MINICA_ADMIN_USER:admin}}\n    password: p\n    role: admin\n";
        let resolved = resolve_env_tokens_with(yaml, lookup(&[])).expect("resolves");
        let mut auth: AuthConfig = serde_yaml::from_str(&resolved).expect("parses");
        auth.validate().expect("valid");
        assert_eq!(auth.users.expect("users").list[0].username, "admin");
    }

    #[test]
    fn password_like_env_values_are_masked_for_logs() {
        assert_eq!(
            mask_env_value("MINICA_ADMIN_PASSWORD", "adminpass"),
            "a*******s"
        );
        assert_eq!(mask_env_value("DB_PASSWD", "secret"), "s****t");
        assert_eq!(mask_env_value("TLS_PASSPHRASE", "abc"), "a*c");
        assert_eq!(mask_env_value("TYPO_PASSWWORD", "secret"), "s****t");
    }

    #[test]
    fn non_password_env_values_are_not_masked_for_logs() {
        assert_eq!(mask_env_value("MINICA_PORT", "9988"), "9988");
    }

    #[test]
    fn very_short_password_like_env_values_keep_available_edges() {
        assert_eq!(mask_env_value("PASSWORD", ""), "");
        assert_eq!(mask_env_value("PASSWORD", "a"), "a");
        assert_eq!(mask_env_value("PASSWORD", "ab"), "ab");
    }
}

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
        // legacy bare-list form implies enabled
        assert_eq!(auth.basic_users().len(), 1);
        let users = auth.users.expect("users");
        assert!(users.enabled);
        assert_eq!(users.list.len(), 1);
    }

    #[test]
    fn users_object_form_with_enabled_and_list() {
        let mut auth = parse(
            "users:\n  enabled: true\n  list:\n    - username: a\n      password: p\n      role: admin\n",
        );
        auth.validate().expect("valid");
        assert_eq!(auth.basic_users().len(), 1);
    }

    #[test]
    fn disabled_users_without_headers_rejected() {
        let mut auth = parse("users:\n  enabled: false\n  list: []\n");
        let err = auth.validate().unwrap_err().to_string();
        assert!(err.contains("no authentication mode enabled"), "{err}");
        assert!(auth.basic_users().is_empty());
    }

    #[test]
    fn disabled_headers_fall_back_to_users() {
        let mut auth = parse(
            "users:\n  - username: a\n    password: p\n    role: admin\nheaders:\n  enabled: false\n",
        );
        auth.validate().expect("valid: basic auth active");
        assert!(auth.active_headers().is_none(), "disabled headers inert");
        assert_eq!(auth.basic_users().len(), 1);
    }

    #[test]
    fn both_disabled_rejected() {
        let mut auth = parse("users:\n  enabled: false\nheaders:\n  enabled: false\n");
        let err = auth.validate().unwrap_err().to_string();
        assert!(err.contains("no authentication mode enabled"), "{err}");
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
    fn both_enabled_prefers_headers() {
        let mut auth = parse(
            "users:\n  - username: a\n    password: p\n    role: admin\nheaders:\n  trusted_remotes:\n    - 10.0.0.0/8\n",
        );
        auth.validate()
            .expect("valid: header identity can be active");
        // headers is active (auth.rs dispatches on it) and its networks are parsed
        let headers = auth.active_headers().expect("headers active");
        assert_eq!(headers.trusted_networks.len(), 1);
        assert!(auth.users.is_some(), "users kept for basic fallback");
    }

    #[test]
    fn neither_users_nor_headers_rejected() {
        let mut auth = parse("{}");
        let err = auth.validate().unwrap_err().to_string();
        assert!(err.contains("no authentication mode enabled"), "{err}");
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
    fn dash_and_empty_trusted_remotes_are_ignored() {
        // '-' is the env-template placeholder for "not specified" (see
        // config.yaml.docker's MINICA_TRUSTED_REMOTE_1..10); empty entries are
        // skipped too. All placeholders -> empty list -> trust everyone.
        let mut auth = parse(
            "headers:\n  trusted_remotes:\n    - '-'\n    - ''\n    - 10.0.0.0/8\n    - ' - '\n",
        );
        auth.validate().expect("valid");
        let networks = auth.headers.expect("headers config").trusted_networks;
        assert_eq!(networks.len(), 1);
        assert!(networks[0].contains(&"10.1.2.3".parse::<std::net::IpAddr>().expect("test ip")));

        let mut auth = parse("headers:\n  trusted_remotes:\n    - '-'\n    - '-'\n");
        auth.validate().expect("valid");
        assert!(auth
            .headers
            .expect("headers config")
            .trusted_networks
            .is_empty());
    }

    #[test]
    fn malformed_trusted_remote_is_named_in_error() {
        let mut auth = parse("headers:\n  trusted_remotes:\n    - 10.0.0.0/33\n");
        let err = auth.validate().unwrap_err().to_string();
        assert!(err.contains("10.0.0.0/33"), "{err}");
    }
}
