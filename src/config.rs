use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Deserialize;
use std::{
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
    /// `headers` (reverse-proxy header auth) takes precedence when defined;
    /// otherwise `users` (basic auth) applies. At least one must be present.
    /// Also pre-parses `trusted_remotes` so bad entries fail at startup, not
    /// per-request.
    pub fn validate(&mut self) -> Result<()> {
        match (self.users.is_some(), self.headers.as_mut()) {
            (_, Some(headers)) => {
                headers.trusted_networks = parse_trusted_remotes(&headers.trusted_remotes)?;
                Ok(())
            }
            (true, None) => Ok(()),
            (false, None) => anyhow::bail!(
                "auth: configure one of 'users' (basic auth) or 'headers' (reverse-proxy header auth)"
            ),
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
    fn both_present_prefers_headers() {
        let mut auth = parse(
            "users:\n  - username: a\n    password: p\n    role: admin\nheaders:\n  trusted_remotes:\n    - 10.0.0.0/8\n",
        );
        auth.validate().expect("valid: headers takes precedence");
        // headers stays active (auth.rs dispatches on it) and its networks are parsed
        assert_eq!(
            auth.headers.expect("headers config").trusted_networks.len(),
            1
        );
        assert!(auth.users.is_some(), "users kept but ignored at runtime");
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
