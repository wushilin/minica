//! The configuration registry and the settings stored in SQLite.
//!
//! [`ConfigOption`] declares every config value once: name, type, whether it
//! is required, sensitive or editable, and its default. The config loader
//! takes its defaults from here and the Admin Console enumerates it.
//!
//! Precedence is SQLite, then the config file (which pulls environment
//! variables in through `{{ENV:...}}`), then the default.
//!
//! The compiler keeps the registry complete:
//!
//! - `read` destructures the config structs without `..`, so a new struct
//!   field is a compile error until it is handled.
//! - `read` has `deny(unused_variables)`, so a field that is not shown is a
//!   compile error too.
//! - `read` and `apply` have no wildcard, so a new option needs both.
//! - Every option's type must implement [`ConfigValue`], the conversion to
//!   and from a string.
//!
//! Only options marked `editable` can come from the database. Never mark one
//! that can run a program, change a path or affect sign-in.

use crate::config::{
    AuthConfig, CertificatesConfig, Config, CrlConfig, HeaderAuthConfig, LoggingConfig,
    OpenSslConfig, Role, RuntimeConfig, ServerConfig, UserConfig, UsersConfig,
};
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const MAX_KEY_LENGTH: usize = 128;
const MAX_VALUE_LENGTH: usize = 4096;
const MAX_CRL_DAYS: i64 = 3650;
const MASK: &str = "••••••";

/// The kinds of value an option can hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueType {
    Text,
    Boolean,
    Port,
    Integer,
    CrlDays,
    Url,
    Path,
    TextList,
    Role,
}

impl ValueType {
    /// The type and its accepted values, as shown in the Admin Console.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Text => "string",
            Self::Boolean => "boolean (true | false)",
            Self::Port => "port (0..65535)",
            Self::Integer => "integer (0 or more)",
            Self::CrlDays => "integer (1..3650)",
            Self::Url => "url (http | https)",
            Self::Path => "path",
            Self::TextList => "list (comma-separated)",
            Self::Role => "role (admin | viewer)",
        }
    }
}

/// A config value's conversion to and from its string form.
pub trait ConfigValue: Sized {
    const TYPE: ValueType;
    fn from_config_string(text: &str) -> Result<Self>;
    fn to_config_string(&self) -> String;
}

impl ConfigValue for String {
    const TYPE: ValueType = ValueType::Text;
    fn from_config_string(text: &str) -> Result<Self> {
        Ok(text.to_string())
    }
    fn to_config_string(&self) -> String {
        self.clone()
    }
}

impl ConfigValue for bool {
    const TYPE: ValueType = ValueType::Boolean;
    fn from_config_string(text: &str) -> Result<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => Ok(true),
            "false" | "no" | "off" | "0" => Ok(false),
            _ => bail!("must be true or false"),
        }
    }
    fn to_config_string(&self) -> String {
        self.to_string()
    }
}

impl ConfigValue for u16 {
    const TYPE: ValueType = ValueType::Port;
    fn from_config_string(text: &str) -> Result<Self> {
        text.trim()
            .parse()
            .map_err(|_| anyhow!("must be a port from 0 to 65535"))
    }
    fn to_config_string(&self) -> String {
        self.to_string()
    }
}

impl ConfigValue for u64 {
    const TYPE: ValueType = ValueType::Integer;
    fn from_config_string(text: &str) -> Result<Self> {
        text.trim()
            .parse()
            .map_err(|_| anyhow!("must be a whole number"))
    }
    fn to_config_string(&self) -> String {
        self.to_string()
    }
}

impl ConfigValue for usize {
    const TYPE: ValueType = ValueType::Integer;
    fn from_config_string(text: &str) -> Result<Self> {
        text.trim()
            .parse()
            .map_err(|_| anyhow!("must be a whole number"))
    }
    fn to_config_string(&self) -> String {
        self.to_string()
    }
}

impl ConfigValue for PathBuf {
    const TYPE: ValueType = ValueType::Path;
    fn from_config_string(text: &str) -> Result<Self> {
        Ok(PathBuf::from(text.trim()))
    }
    fn to_config_string(&self) -> String {
        self.display().to_string()
    }
}

impl ConfigValue for Vec<String> {
    const TYPE: ValueType = ValueType::TextList;
    fn from_config_string(text: &str) -> Result<Self> {
        Ok(text
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect())
    }
    fn to_config_string(&self) -> String {
        self.join(", ")
    }
}

impl ConfigValue for Role {
    const TYPE: ValueType = ValueType::Role;
    fn from_config_string(text: &str) -> Result<Self> {
        Role::parse(text).ok_or_else(|| anyhow!("must be admin or viewer"))
    }
    fn to_config_string(&self) -> String {
        self.as_str().to_string()
    }
}

/// An http(s) URL, stored without trailing slashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpUrl(pub String);

impl ConfigValue for HttpUrl {
    const TYPE: ValueType = ValueType::Url;
    fn from_config_string(text: &str) -> Result<Self> {
        let url = text.trim().trim_end_matches('/');
        crate::service::validate_crl_url(url)?;
        Ok(Self(url.to_string()))
    }
    fn to_config_string(&self) -> String {
        self.0.clone()
    }
}

/// A CRL `nextUpdate` interval in days.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrlDays(pub i64);

impl ConfigValue for CrlDays {
    const TYPE: ValueType = ValueType::CrlDays;
    fn from_config_string(text: &str) -> Result<Self> {
        match text.trim().parse::<i64>() {
            Ok(days) if (1..=MAX_CRL_DAYS).contains(&days) => Ok(Self(days)),
            _ => bail!("must be a whole number from 1 to {MAX_CRL_DAYS}"),
        }
    }
    fn to_config_string(&self) -> String {
        self.0.to_string()
    }
}

/// Declares the registry. `*` in a name stands for each entry of a list.
macro_rules! config_options {
    ($(
        $variant:ident {
            name: $name:literal,
            ty: $ty:ty,
            required: $required:literal,
            sensitive: $sensitive:literal,
            editable: $editable:literal,
            default: $default:expr,
            docs: $docs:literal $(,)?
        }
    ),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ConfigOption { $($variant),+ }

        $(const _: () = assert!(!$docs.is_empty(), "config option docs must not be empty");)+

        impl ConfigOption {
            pub const ALL: &'static [ConfigOption] = &[$(Self::$variant),+];

            pub const fn name(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }
            pub const fn value_type(self) -> ValueType {
                match self { $(Self::$variant => <$ty as ConfigValue>::TYPE),+ }
            }
            pub const fn required(self) -> bool {
                match self { $(Self::$variant => $required),+ }
            }
            pub const fn sensitive(self) -> bool {
                match self { $(Self::$variant => $sensitive),+ }
            }
            pub const fn editable(self) -> bool {
                match self { $(Self::$variant => $editable),+ }
            }
            pub const fn default_text(self) -> Option<&'static str> {
                match self { $(Self::$variant => $default),+ }
            }
            pub const fn docs(self) -> &'static str {
                match self { $(Self::$variant => $docs),+ }
            }
            /// Parses text as this option's type and returns its stored form.
            pub fn normalize(self, text: &str) -> Result<String> {
                match self {
                    $(Self::$variant => <$ty as ConfigValue>::from_config_string(text)
                        .map(|value| value.to_config_string())),+
                }
            }
        }
    };
}

config_options! {
    PublicBaseUrl { name: "public_base_url", ty: HttpUrl, required: false, sensitive: false, editable: true, default: None, docs: "The external URL of MiniCA. Used for links in the How to Use guide and for CRL download URLs." },
    CrlEnabled { name: "crl.enabled", ty: bool, required: false, sensitive: false, editable: true, default: Some("true"), docs: "Publishes certificate revocation lists so clients can check for revoked certificates." },
    CrlNextUpdateDays { name: "crl.next_update_days", ty: CrlDays, required: false, sensitive: false, editable: true, default: Some("30"), docs: "How many days a published CRL stays valid before clients expect a newer one." },
    ExtraLongValidity { name: "certificates.extra_long_validity", ty: bool, required: false, sensitive: false, editable: true, default: Some("false"), docs: "Raises the maximum validity from 7350 days to 3,000,000 days, ending no later than 9999-12-31." },
    ServerHost { name: "server.host", ty: String, required: true, sensitive: false, editable: false, default: None, docs: "The network address MiniCA listens on. Use 127.0.0.1 when it sits behind a local reverse proxy." },
    ServerPort { name: "server.port", ty: u16, required: true, sensitive: false, editable: false, default: None, docs: "The TCP port MiniCA listens on." },
    ServerBasePath { name: "server.base_path", ty: String, required: true, sensitive: false, editable: false, default: None, docs: "The URL prefix every page is served under, such as /minica." },
    ServerSecureCookies { name: "server.secure_cookies", ty: bool, required: false, sensitive: false, editable: false, default: Some("false"), docs: "Marks cookies as Secure. Enable only when every browser reaches MiniCA over HTTPS." },
    RuntimeFolder { name: "runtime.folder", ty: PathBuf, required: true, sensitive: false, editable: false, default: None, docs: "The folder for MiniCA runtime data." },
    RuntimeDbFolder { name: "runtime.db_folder", ty: PathBuf, required: false, sensitive: false, editable: false, default: None, docs: "A separate folder for the SQLite database. When unset, the runtime folder is used." },
    OpensslPath { name: "openssl.path", ty: PathBuf, required: true, sensitive: false, editable: false, default: None, docs: "The OpenSSL program MiniCA runs to create and sign keys and certificates." },
    OpensslTimeoutSeconds { name: "openssl.timeout_seconds", ty: u64, required: false, sensitive: false, editable: false, default: Some("15"), docs: "The longest a single OpenSSL command may run before it is stopped." },
    OpensslWorkingRoot { name: "openssl.working_root", ty: PathBuf, required: true, sensitive: false, editable: false, default: None, docs: "The folder for temporary OpenSSL working directories." },
    OpensslKeepFailedWorkdirs { name: "openssl.keep_failed_workdirs", ty: bool, required: false, sensitive: false, editable: false, default: Some("false"), docs: "Keeps the working directory of a failed OpenSSL command for debugging. It may contain private keys." },
    OpensslReapAfterHours { name: "openssl.reap_after_hours", ty: u64, required: false, sensitive: false, editable: false, default: Some("24"), docs: "How often abandoned temporary working directories, such as those left by a crash, are swept." },
    LoggingFile { name: "logging.file", ty: PathBuf, required: false, sensitive: false, editable: false, default: Some("./logs/minica.log"), docs: "The log file path." },
    LoggingRotateSizeBytes { name: "logging.rotate_size_bytes", ty: u64, required: false, sensitive: false, editable: false, default: Some("10485760"), docs: "The log file size that triggers rotation." },
    LoggingMaxBackups { name: "logging.max_backups", ty: usize, required: false, sensitive: false, editable: false, default: Some("10"), docs: "How many rotated log files to keep." },
    LoggingCompress { name: "logging.compress", ty: bool, required: false, sensitive: false, editable: false, default: Some("true"), docs: "Compresses rotated log files." },
    AuthUsersEnabled { name: "auth.users.enabled", ty: bool, required: false, sensitive: false, editable: false, default: Some("true"), docs: "Allows sign-in with Basic auth accounts." },
    AuthUserPassword { name: "auth.users.*.password", ty: String, required: true, sensitive: true, editable: false, default: None, docs: "The password of this config-file account, as a bcrypt hash or plaintext. Always masked here." },
    AuthUserRole { name: "auth.users.*.role", ty: Role, required: true, sensitive: false, editable: false, default: None, docs: "The role of this config-file account: admin or viewer." },
    AuthHeadersEnabled { name: "auth.headers.enabled", ty: bool, required: false, sensitive: false, editable: false, default: Some("true"), docs: "Trusts identity headers from an authenticating reverse proxy when this section is configured." },
    AuthHeadersUsername { name: "auth.headers.username", ty: String, required: false, sensitive: false, editable: false, default: Some("Remote-User"), docs: "The request header that carries the signed-in user name." },
    AuthHeadersGroup { name: "auth.headers.group", ty: String, required: false, sensitive: false, editable: false, default: Some("Remote-Groups"), docs: "The request header that carries the user groups." },
    AuthHeadersAdminGroup { name: "auth.headers.admin_group", ty: String, required: false, sensitive: false, editable: false, default: Some("admin"), docs: "Members of this group get the admin role." },
    AuthHeadersViewerGroup { name: "auth.headers.viewer_group", ty: String, required: false, sensitive: false, editable: false, default: Some("user"), docs: "Members of this group get the viewer role." },
    AuthHeadersTrustedRemotes { name: "auth.headers.trusted_remotes", ty: Vec<String>, required: false, sensitive: false, editable: false, default: Some(""), docs: "The proxy IPs or CIDRs allowed to send identity headers." },
    AuthHeadersTrustAllRemotes { name: "auth.headers.trust_all_remotes", ty: bool, required: false, sensitive: false, editable: false, default: Some("false"), docs: "Accepts identity headers from any peer when no trusted remotes are listed. Unsafe unless only the proxy can reach MiniCA." },
}

impl ConfigOption {
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|option| option.name() == name)
    }

    /// The registered default as a typed value. The test
    /// `every_default_parses_as_its_type` covers the conversion.
    pub fn default_as<T: ConfigValue>(self) -> T {
        let text = self.default_text().unwrap_or_default();
        T::from_config_string(text)
            .unwrap_or_else(|err| panic!("invalid default for {}: {err}", self.name()))
    }

    pub fn editable_options() -> impl Iterator<Item = Self> {
        Self::ALL.iter().copied().filter(|option| option.editable())
    }
}

/// The settings that can change while the server runs.
#[derive(Clone, Debug)]
pub struct LiveSettings {
    pub public_base_url: Option<String>,
    pub crl: CrlConfig,
    pub certificates: CertificatesConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingRow {
    pub key: String,
    pub value: String,
    pub enabled: bool,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default)]
    pub updated_by: String,
}

#[derive(Clone, Debug)]
pub struct SettingAudit {
    pub at: i64,
    pub actor: String,
    pub key: String,
    pub action: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingStatus {
    Active,
    Disabled,
    NoEffect,
}

/// Where an effective value came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Sqlite,
    File,
    Environment(String),
    Default,
}

#[derive(Clone, Debug)]
pub struct EffectiveEntry {
    pub option: ConfigOption,
    /// The option name, with `*` replaced for list entries.
    pub key: String,
    pub value: Option<String>,
    pub source: Source,
}

/// Trims a key and rejects malformed names and any name in a section that
/// holds a file-only option.
pub fn validate_key(key: &str) -> Result<String> {
    let key = key.trim();
    if key.is_empty() || key.len() > MAX_KEY_LENGTH {
        bail!("setting key must be 1 to {MAX_KEY_LENGTH} characters");
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("setting key may only contain letters, digits, '.', '_' and '-'");
    }
    let section = key.split('.').next().unwrap_or(key);
    if ConfigOption::ALL.iter().any(|option| {
        !option.editable()
            && option
                .name()
                .split('.')
                .next()
                .is_some_and(|file_section| file_section.eq_ignore_ascii_case(section))
    }) {
        bail!("{key} can only be set in the config file");
    }
    Ok(key.to_string())
}

/// Validates a value and returns its stored form. Unknown keys keep any text.
pub fn normalize_value(key: &str, value: &str) -> Result<String> {
    if value.len() > MAX_VALUE_LENGTH || value.chars().any(char::is_control) {
        bail!("setting value must be at most {MAX_VALUE_LENGTH} bytes without control characters");
    }
    match ConfigOption::parse(key).filter(|option| option.editable()) {
        Some(option) => option
            .normalize(value)
            .map_err(|err| anyhow!("{key} {err}")),
        None => Ok(value.to_string()),
    }
}

pub fn status(row: &SettingRow) -> SettingStatus {
    if !row.enabled {
        SettingStatus::Disabled
    } else if ConfigOption::parse(&row.key).is_some_and(|option| option.editable())
        && normalize_value(&row.key, &row.value).is_ok()
    {
        SettingStatus::Active
    } else {
        SettingStatus::NoEffect
    }
}

/// Lays the active database rows over the file-based settings.
pub fn apply(base: &LiveSettings, rows: &[SettingRow]) -> LiveSettings {
    let mut live = base.clone();
    for row in rows {
        let Some(option) = ConfigOption::parse(&row.key).filter(|option| option.editable()) else {
            continue;
        };
        if !row.enabled {
            continue;
        }
        let Ok(value) = normalize_value(&row.key, &row.value) else {
            tracing::warn!(key = %row.key, "ignoring invalid database setting");
            continue;
        };
        if let Err(err) = apply_one(option, &value, &mut live) {
            tracing::warn!(key = %row.key, error = %err, "ignoring invalid database setting");
        }
    }
    live
}

fn apply_one(option: ConfigOption, value: &str, live: &mut LiveSettings) -> Result<()> {
    use ConfigOption as O;
    match option {
        O::PublicBaseUrl => live.public_base_url = Some(HttpUrl::from_config_string(value)?.0),
        O::CrlEnabled => live.crl.enabled = bool::from_config_string(value)?,
        O::CrlNextUpdateDays => live.crl.next_update_days = CrlDays::from_config_string(value)?.0,
        O::ExtraLongValidity => {
            live.certificates.extra_long_validity = bool::from_config_string(value)?;
        }
        // File-only: `editable` is false, so these never come from the database.
        O::ServerHost
        | O::ServerPort
        | O::ServerBasePath
        | O::ServerSecureCookies
        | O::RuntimeFolder
        | O::RuntimeDbFolder
        | O::OpensslPath
        | O::OpensslTimeoutSeconds
        | O::OpensslWorkingRoot
        | O::OpensslKeepFailedWorkdirs
        | O::OpensslReapAfterHours
        | O::LoggingFile
        | O::LoggingRotateSizeBytes
        | O::LoggingMaxBackups
        | O::LoggingCompress
        | O::AuthUsersEnabled
        | O::AuthUserPassword
        | O::AuthUserRole
        | O::AuthHeadersEnabled
        | O::AuthHeadersUsername
        | O::AuthHeadersGroup
        | O::AuthHeadersAdminGroup
        | O::AuthHeadersViewerGroup
        | O::AuthHeadersTrustedRemotes
        | O::AuthHeadersTrustAllRemotes => bail!("{} is file-only", option.name()),
    }
    Ok(())
}

type Rows = Vec<(String, Option<String>)>;

fn value_row<T: ConfigValue>(option: ConfigOption, value: &T) -> Rows {
    vec![(option.name().to_string(), Some(value.to_config_string()))]
}

/// One row, showing "not set" when the value is absent.
fn optional_row<T: ConfigValue>(option: ConfigOption, value: Option<&T>) -> Rows {
    vec![(
        option.name().to_string(),
        value.map(ConfigValue::to_config_string),
    )]
}

/// A row only when its optional config section exists.
fn section_row<T: ConfigValue>(option: ConfigOption, value: Option<&T>) -> Rows {
    value.map_or_else(Vec::new, |value| value_row(option, value))
}

/// The displayed rows of an option. Passwords are never read here.
#[deny(unused_variables)]
fn read(option: ConfigOption, config: &Config, live: &LiveSettings) -> Rows {
    use ConfigOption as O;
    let LiveSettings {
        public_base_url,
        crl:
            CrlConfig {
                enabled: crl_enabled,
                next_update_days,
            },
        certificates: CertificatesConfig {
            extra_long_validity,
        },
    } = live;
    let Config {
        server:
            ServerConfig {
                host,
                port,
                base_path,
                secure_cookies,
            },
        // Shown from the live values above.
        public_base_url: _,
        crl: _,
        certificates: _,
        runtime: RuntimeConfig { folder, db_folder },
        openssl:
            OpenSslConfig {
                path,
                timeout_seconds,
                working_root,
                keep_failed_workdirs,
                reap_after_hours,
            },
        auth: AuthConfig { users, headers },
        logging:
            LoggingConfig {
                file,
                rotate_size_bytes,
                max_backups,
                compress,
            },
        // Metadata about the other fields.
        sources: _,
    } = config;
    let (users_enabled, accounts) = match users {
        Some(UsersConfig { enabled, list }) => (Some(enabled), list.as_slice()),
        None => (None, &[][..]),
    };
    let header = headers.as_ref().map(
        |HeaderAuthConfig {
             enabled,
             username,
             group,
             admin_group,
             viewer_group,
             trusted_remotes,
             trust_all_remotes,
             // Parsed copy of `trusted_remotes`.
             trusted_networks: _,
         }| {
            (
                enabled,
                username,
                group,
                admin_group,
                viewer_group,
                trusted_remotes,
                trust_all_remotes,
            )
        },
    );
    let per_account = |value: fn(&UserConfig) -> Option<String>| -> Rows {
        accounts
            .iter()
            .map(|user| (option.name().replace('*', &user.username), value(user)))
            .collect()
    };
    match option {
        O::PublicBaseUrl => optional_row(option, public_base_url.as_ref()),
        O::CrlEnabled => value_row(option, crl_enabled),
        O::CrlNextUpdateDays => value_row(option, &CrlDays(*next_update_days)),
        O::ExtraLongValidity => value_row(option, extra_long_validity),
        O::ServerHost => value_row(option, host),
        O::ServerPort => value_row(option, port),
        O::ServerBasePath => value_row(option, base_path),
        O::ServerSecureCookies => value_row(option, secure_cookies),
        O::RuntimeFolder => value_row(option, folder),
        O::RuntimeDbFolder => optional_row(option, db_folder.as_ref()),
        O::OpensslPath => value_row(option, path),
        O::OpensslTimeoutSeconds => value_row(option, timeout_seconds),
        O::OpensslWorkingRoot => value_row(option, working_root),
        O::OpensslKeepFailedWorkdirs => value_row(option, keep_failed_workdirs),
        O::OpensslReapAfterHours => value_row(option, reap_after_hours),
        O::LoggingFile => value_row(option, file),
        O::LoggingRotateSizeBytes => value_row(option, rotate_size_bytes),
        O::LoggingMaxBackups => value_row(option, max_backups),
        O::LoggingCompress => value_row(option, compress),
        O::AuthUsersEnabled => section_row(option, users_enabled),
        // `effective` replaces this with the mask because the option is sensitive.
        O::AuthUserPassword => per_account(
            |UserConfig {
                 username: _,
                 password: _,
                 role: _,
             }| None,
        ),
        O::AuthUserRole => per_account(|user| Some(user.role.to_config_string())),
        O::AuthHeadersEnabled => section_row(option, header.map(|h| h.0)),
        O::AuthHeadersUsername => section_row(option, header.map(|h| h.1)),
        O::AuthHeadersGroup => section_row(option, header.map(|h| h.2)),
        O::AuthHeadersAdminGroup => section_row(option, header.map(|h| h.3)),
        O::AuthHeadersViewerGroup => section_row(option, header.map(|h| h.4)),
        O::AuthHeadersTrustedRemotes => section_row(option, header.map(|h| h.5)),
        O::AuthHeadersTrustAllRemotes => section_row(option, header.map(|h| h.6)),
    }
}

/// Every setting in use and where it came from, by enumerating the registry.
pub fn effective(config: &Config, live: &LiveSettings, rows: &[SettingRow]) -> Vec<EffectiveEntry> {
    let from_file = |option: ConfigOption| {
        let name = option.name();
        let in_users = name.starts_with("auth.users.");
        [Some(name), in_users.then_some("auth.users.list"), in_users.then_some("auth.users")]
            .into_iter()
            .flatten()
            .find_map(|path| config.sources.get(path))
            .cloned()
            .unwrap_or(Source::Default)
    };
    let mut out = Vec::new();
    for option in ConfigOption::ALL.iter().copied() {
        let from_database = option.editable()
            && rows
                .iter()
                .any(|row| row.key == option.name() && status(row) == SettingStatus::Active);
        let source = if from_database {
            Source::Sqlite
        } else {
            from_file(option)
        };
        for (key, value) in read(option, config, live) {
            out.push(EffectiveEntry {
                option,
                key,
                value: if option.sensitive() {
                    Some(MASK.to_string())
                } else {
                    value
                },
                source: source.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = ConfigOption::PublicBaseUrl.name();
    const CRL_ENABLED: &str = ConfigOption::CrlEnabled.name();
    const CRL_DAYS: &str = ConfigOption::CrlNextUpdateDays.name();
    const EXTRA_LONG: &str = ConfigOption::ExtraLongValidity.name();

    fn row(key: &str, value: &str, enabled: bool) -> SettingRow {
        SettingRow {
            key: key.to_string(),
            value: value.to_string(),
            enabled,
            updated_at: 0,
            updated_by: String::new(),
        }
    }

    fn base() -> LiveSettings {
        LiveSettings {
            public_base_url: Some("https://file.example/minica".to_string()),
            crl: CrlConfig::default(),
            certificates: CertificatesConfig::default(),
        }
    }

    #[test]
    fn registry_is_consistent() {
        let mut names: Vec<&str> = ConfigOption::ALL.iter().map(|o| o.name()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate option name");
        for option in ConfigOption::ALL.iter().copied() {
            assert!(
                !(option.required() && option.default_text().is_some()),
                "{option:?} is required but has a default"
            );
            assert!(
                !(option.editable() && option.sensitive()),
                "{option:?}: sensitive options cannot be edited in the database"
            );
            assert_eq!(
                validate_key(option.name().replace('*', "x").as_str()).is_ok(),
                option.editable(),
                "{option:?} storable state is wrong"
            );
        }
    }

    #[test]
    fn every_default_parses_as_its_type() {
        for option in ConfigOption::ALL.iter().copied() {
            if let Some(text) = option.default_text() {
                let stored = option
                    .normalize(text)
                    .unwrap_or_else(|err| panic!("{option:?}: {err}"));
                assert_eq!(option.normalize(&stored).unwrap(), stored, "{option:?}");
            }
        }
    }

    #[test]
    fn values_round_trip_through_strings() {
        assert!(bool::from_config_string("YES").unwrap());
        assert_eq!(true.to_config_string(), "true");
        assert_eq!(u16::from_config_string("9988").unwrap().to_config_string(), "9988");
        assert!(u16::from_config_string("70000").is_err());
        let list = Vec::<String>::from_config_string("a, b,,c").unwrap();
        assert_eq!(list.to_config_string(), "a, b, c");
        assert_eq!(Role::from_config_string("ADMIN").unwrap().to_config_string(), "admin");
        assert_eq!(CrlDays::from_config_string("30").unwrap().to_config_string(), "30");
        assert!(CrlDays::from_config_string("0").is_err());
        assert_eq!(
            HttpUrl::from_config_string("https://a.test/").unwrap().to_config_string(),
            "https://a.test"
        );
    }

    #[test]
    fn file_only_sections_cannot_be_stored() {
        for key in [
            "openssl.path",
            "OPENSSL.path",
            "auth.users",
            "server.port",
            "runtime.folder",
            "logging.file",
        ] {
            assert!(validate_key(key).is_err(), "{key}");
        }
        assert_eq!(validate_key(" my.custom-key ").unwrap(), "my.custom-key");
        assert!(validate_key("bad key").is_err());
    }

    #[test]
    fn known_values_are_validated_and_normalized() {
        assert_eq!(
            normalize_value(URL, " https://a.test/ca/ ").unwrap(),
            "https://a.test/ca"
        );
        assert!(normalize_value(URL, "ftp://a.test").is_err());
        assert!(normalize_value(URL, "https://a.test/\"x").is_err());
        assert_eq!(normalize_value(CRL_ENABLED, "NO").unwrap(), "false");
        assert!(normalize_value(CRL_ENABLED, "maybe").is_err());
        assert!(normalize_value(CRL_DAYS, "0").is_err());
        assert_eq!(normalize_value("custom.key", "any text").unwrap(), "any text");
    }

    #[test]
    fn disabled_unknown_and_invalid_rows_have_no_effect() {
        let live = apply(
            &base(),
            &[
                row(URL, "https://db.example/ca", false),
                row(CRL_DAYS, "nonsense", true),
                row("custom.key", "value", true),
                row(EXTRA_LONG, "true", true),
            ],
        );
        assert_eq!(
            live.public_base_url.as_deref(),
            Some("https://file.example/minica")
        );
        assert_eq!(live.crl.next_update_days, CrlConfig::default().next_update_days);
        assert!(live.certificates.extra_long_validity);
        assert_eq!(status(&row("custom.key", "value", true)), SettingStatus::NoEffect);
        assert_eq!(status(&row(CRL_ENABLED, "true", false)), SettingStatus::Disabled);
        assert_eq!(status(&row(CRL_ENABLED, "true", true)), SettingStatus::Active);
    }
}
