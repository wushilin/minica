use anyhow::{Context, Result};
use serde::Deserialize;
use std::{env, fs, net::SocketAddr, path::PathBuf};

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
    pub users: Vec<UserConfig>,
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

impl Config {
    pub fn load() -> Result<Self> {
        let mut args = env::args().skip(1);
        let mut path = PathBuf::from("config.yaml");
        while let Some(arg) = args.next() {
            if arg == "-c" || arg == "--config" {
                path = args
                    .next()
                    .map(PathBuf::from)
                    .context("-c requires a config path")?;
            }
        }

        let text = fs::read_to_string(&path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let mut config: Config = serde_yaml::from_str(&text)
            .with_context(|| format!("failed to parse {}", path.display()))?;
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
