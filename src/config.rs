use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, de::Error as _};
use serde_yaml::{Mapping, Value};
use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default, deserialize_with = "lenient::opt_string")]
    pub public_base_url: Option<String>,
    #[serde(default)]
    pub crl: CrlConfig,
    pub runtime: RuntimeConfig,
    pub openssl: OpenSslConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Pre-filled form values and named presets for the New CA / New
    /// Certificate pages.
    #[serde(default)]
    pub templates: TemplatesConfig,
}

/// `templates:` section. `defaults` pre-fills both creation forms; `ca` and
/// `certificate` are named presets offered in a drop-down on the respective
/// form (fields a preset leaves out keep the defaults). Nothing here changes
/// what the API accepts; it only changes what the forms start with.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplatesConfig {
    #[serde(default)]
    pub defaults: FormTemplate,
    #[serde(default)]
    pub ca: Vec<FormTemplate>,
    #[serde(default)]
    pub certificate: Vec<FormTemplate>,
}

/// One set of form values. Every field is optional; `name` is only meaningful
/// for presets (it is the drop-down label).
#[derive(Clone, Debug, Default, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FormTemplate {
    #[serde(default, deserialize_with = "lenient::opt_string")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "lenient::opt_string")]
    pub country_code: Option<String>,
    #[serde(default, deserialize_with = "lenient::opt_string")]
    pub state: Option<String>,
    #[serde(default, deserialize_with = "lenient::opt_string")]
    pub city: Option<String>,
    #[serde(default, deserialize_with = "lenient::opt_string")]
    pub organization: Option<String>,
    #[serde(default, deserialize_with = "lenient::opt_string")]
    pub organization_unit: Option<String>,
    #[serde(default, deserialize_with = "lenient::opt_from_str")]
    pub valid_days: Option<i64>,
    #[serde(default, deserialize_with = "lenient::opt_string")]
    pub digest_algorithm: Option<String>,
    #[serde(default, deserialize_with = "lenient::opt_string")]
    pub key_profile: Option<String>,
}

impl TemplatesConfig {
    /// Presets need a non-empty, unique name; day counts must be in range.
    fn validate(&self) -> Result<()> {
        for (section, list) in [("templates.ca", &self.ca), ("templates.certificate", &self.certificate)] {
            let mut seen = HashSet::new();
            for template in list {
                let name = template.name.as_deref().map(str::trim).unwrap_or_default();
                if name.is_empty() {
                    anyhow::bail!("{section}: every preset needs a name");
                }
                if !seen.insert(name.to_lowercase()) {
                    anyhow::bail!("{section}: duplicate preset name {name:?}");
                }
                template.validate(&format!("{section} preset {name:?}"))?;
            }
        }
        self.defaults.validate("templates.defaults")
    }
}

impl FormTemplate {
    fn validate(&self, what: &str) -> Result<()> {
        if let Some(days) = self.valid_days.filter(|days| !(1..=7350).contains(days)) {
            anyhow::bail!("{what}: valid_days must be in 1..7350, got {days}");
        }
        if let Some(code) = self
            .country_code
            .as_deref()
            .filter(|code| code.trim().chars().count() > 2)
        {
            anyhow::bail!("{what}: country_code must be a 2-letter code, got {code:?}");
        }
        for (field, value) in [
            ("name", &self.name),
            ("country_code", &self.country_code),
            ("state", &self.state),
            ("city", &self.city),
            ("organization", &self.organization),
            ("organization_unit", &self.organization_unit),
            ("digest_algorithm", &self.digest_algorithm),
            ("key_profile", &self.key_profile),
        ] {
            if value
                .as_deref()
                .is_some_and(|value| value.chars().any(char::is_control))
            {
                anyhow::bail!("{what}: {field} must not contain control characters");
            }
        }
        Ok(())
    }

    /// `self` with every unset field taken from `base`.
    pub fn over(&self, base: &FormTemplate) -> FormTemplate {
        FormTemplate {
            name: self.name.clone().or_else(|| base.name.clone()),
            country_code: self.country_code.clone().or_else(|| base.country_code.clone()),
            state: self.state.clone().or_else(|| base.state.clone()),
            city: self.city.clone().or_else(|| base.city.clone()),
            organization: self.organization.clone().or_else(|| base.organization.clone()),
            organization_unit: self
                .organization_unit
                .clone()
                .or_else(|| base.organization_unit.clone()),
            valid_days: self.valid_days.or(base.valid_days),
            digest_algorithm: self
                .digest_algorithm
                .clone()
                .or_else(|| base.digest_algorithm.clone()),
            key_profile: self.key_profile.clone().or_else(|| base.key_profile.clone()),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    #[serde(deserialize_with = "lenient::from_str")]
    pub port: u16,
    /// URL prefix the app is mounted under. Normalised by `Config::load` to a
    /// leading slash and no trailing slash; the root (`/` or empty) is stored
    /// as the empty string so `format!("{base}/cas")` never yields `//cas`.
    pub base_path: String,
    /// Mark cookies `Secure`. MiniCA itself speaks plain HTTP, so only enable
    /// this when every browser reaches it over HTTPS (e.g. a TLS proxy).
    #[serde(default, deserialize_with = "lenient::bool")]
    pub secure_cookies: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RuntimeConfig {
    pub folder: PathBuf,
    #[serde(default, deserialize_with = "lenient::opt_path")]
    pub db_folder: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenSslConfig {
    pub path: PathBuf,
    /// Maximum wall-clock time a single openssl invocation may run before it is
    /// terminated. Defaults to 15s when omitted from the config file.
    #[serde(
        default = "default_timeout_seconds",
        deserialize_with = "lenient::from_str"
    )]
    pub timeout_seconds: u64,
    pub working_root: PathBuf,
    #[serde(deserialize_with = "lenient::bool")]
    pub keep_failed_workdirs: bool,
    #[serde(deserialize_with = "lenient::from_str")]
    pub reap_after_hours: u64,
}

/// Lenient scalar deserializers. `{{ENV:...}}` tokens are resolved after YAML
/// parsing, so an env-supplied value always arrives as a string; these accept
/// either the native YAML type or a string that parses as it.
mod lenient {
    use serde::{Deserialize, Deserializer, de::DeserializeOwned, de::Error};
    use serde_yaml::Value;
    use std::{fmt::Display, path::PathBuf, str::FromStr};

    pub fn from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromStr + DeserializeOwned,
        T::Err: Display,
    {
        match Value::deserialize(deserializer)? {
            Value::String(text) => text
                .trim()
                .parse()
                .map_err(|err| D::Error::custom(format!("invalid number {text:?}: {err}"))),
            other => serde_yaml::from_value(other).map_err(D::Error::custom),
        }
    }

    pub fn bool<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::Bool(value) => Ok(value),
            Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => Ok(true),
                "false" | "no" | "off" | "0" => Ok(false),
                _ => Err(D::Error::custom(format!(
                    "invalid boolean {text:?}, expected true or false"
                ))),
            },
            other => Err(D::Error::custom(format!(
                "invalid type: expected a boolean, found {other:?}"
            ))),
        }
    }

    /// `null`, `~` and the empty string all mean "not set".
    pub fn opt_string<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<String>, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::Null => Ok(None),
            Value::String(text) if is_null_word(&text) => Ok(None),
            Value::String(text) => Ok(Some(text)),
            other => Err(D::Error::custom(format!(
                "invalid type: expected a string, found {other:?}"
            ))),
        }
    }

    /// Optional number: `null`/empty mean "not set"; strings must parse.
    pub fn opt_from_str<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: FromStr + DeserializeOwned,
        T::Err: Display,
    {
        match Value::deserialize(deserializer)? {
            Value::Null => Ok(None),
            Value::String(text) if is_null_word(&text) => Ok(None),
            Value::String(text) => text
                .trim()
                .parse()
                .map(Some)
                .map_err(|err| D::Error::custom(format!("invalid number {text:?}: {err}"))),
            other => serde_yaml::from_value(other)
                .map(Some)
                .map_err(D::Error::custom),
        }
    }

    pub fn opt_path<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<PathBuf>, D::Error> {
        opt_string(deserializer).map(|value| value.map(PathBuf::from))
    }

    fn is_null_word(text: &str) -> bool {
        matches!(text.trim(), "" | "~" | "null" | "Null" | "NULL")
    }
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
#[derive(Clone, Debug)]
pub struct UsersConfig {
    pub enabled: bool,
    pub list: Vec<UserConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UsersObject {
    #[serde(default = "default_true", deserialize_with = "lenient::bool")]
    enabled: bool,
    #[serde(default)]
    list: Vec<UserConfig>,
}

/// Dispatches on the YAML shape explicitly (rather than `#[serde(untagged)]`)
/// so a typo reports the real problem instead of "did not match any variant".
impl<'de> Deserialize<'de> for UsersConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            value @ Value::Sequence(_) => serde_yaml::from_value(value)
                .map(|list| Self {
                    enabled: true,
                    list,
                })
                .map_err(|err| D::Error::custom(format!("auth.users list: {err}"))),
            value @ Value::Mapping(_) => serde_yaml::from_value::<UsersObject>(value)
                .map(|users| Self {
                    enabled: users.enabled,
                    list: users.list,
                })
                .map_err(|err| D::Error::custom(format!("auth.users: {err}"))),
            _ => Err(D::Error::custom(
                "auth.users must be a list of accounts, or a mapping with `enabled` and `list`",
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderAuthConfig {
    /// Toggle for this mode; on by default when the section is present.
    #[serde(default = "default_true", deserialize_with = "lenient::bool")]
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
    /// Peers (bare IPs or CIDRs) allowed to assert identity headers. Must be
    /// non-empty unless `trust_all_remotes` is set.
    #[serde(default)]
    pub trusted_remotes: Vec<String>,
    /// Explicit opt-in to honour identity headers from every remote when
    /// `trusted_remotes` is empty. Only safe when MiniCA is reachable solely
    /// through the authenticating proxy. Ignored when `trusted_remotes` lists
    /// at least one peer.
    #[serde(default, deserialize_with = "lenient::bool")]
    pub trust_all_remotes: bool,
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
    /// `trusted_remotes` so bad entries fail at startup, not per-request, and
    /// refuses an empty trusted list unless `trust_all_remotes` opts in.
    pub fn validate(&mut self) -> Result<()> {
        if let Some(headers) = self.headers.as_mut().filter(|headers| headers.enabled) {
            headers.trusted_networks = parse_trusted_remotes(&headers.trusted_remotes)?;
            if headers.trusted_networks.is_empty() && !headers.trust_all_remotes {
                anyhow::bail!(
                    "auth.headers: header auth is enabled but trusted_remotes is empty, so any client could \
                     assert identity headers; list the reverse proxy's IP/CIDR in auth.headers.trusted_remotes, \
                     or set auth.headers.trust_all_remotes: true to explicitly trust every remote"
                );
            }
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
/// variables and deserialize the config. Tokens are resolved *after* YAML
/// parsing, inside string scalars only: each token is first swapped for an
/// inert placeholder (unquoted tokens are not valid YAML), the text is parsed,
/// and then placeholders in string scalars are replaced with their values.
/// Env values therefore can never change the YAML structure (a password with
/// ": ", " #" or a newline stays one string), and tokens in comments are
/// neither resolved nor logged. Numeric/boolean fields accept the resulting
/// strings via the `lenient` deserializers.
fn parse_config_with_env(
    text: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<(Config, HashSet<String>)> {
    let (placeholdered, resolver) = EnvPlaceholders::extract(text)?;
    if resolver.tokens.is_empty() {
        // No tokens: parse directly so YAML errors keep line/column info.
        return Ok((serde_yaml::from_str(text)?, HashSet::new()));
    }
    let value: Value = serde_yaml::from_str(&placeholdered)?;
    let mut used_names = HashSet::new();
    let value = resolver.resolve_value(value, &lookup, &mut used_names)?;
    Ok((serde_yaml::from_value(value)?, used_names))
}

/// Raw `{{ENV:...}}` tokens lifted out of the config text, each replaced by
/// `<prefix><index>__` — a plain identifier that is valid anywhere in YAML.
struct EnvPlaceholders {
    prefix: String,
    tokens: Vec<String>,
}

impl EnvPlaceholders {
    fn extract(text: &str) -> Result<(String, Self)> {
        const OPEN: &str = "{{ENV:";
        const CLOSE: &str = "}}";
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let prefix = format!("__minica_env_{}_", &nonce[..12]);
        let mut tokens = Vec::new();
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find(OPEN) {
            out.push_str(&rest[..start]);
            let token = &rest[start..];
            let Some(end) = token.find(CLOSE) else {
                anyhow::bail!("unterminated {{{{ENV:...}}}} token");
            };
            let token = &token[..end + CLOSE.len()];
            // Validate eagerly so a malformed token fails even if unused.
            parse_env_token(&token[OPEN.len()..end])?;
            out.push_str(&format!("{prefix}{}__", tokens.len()));
            tokens.push(token.to_string());
            rest = &rest[start + token.len()..];
        }
        out.push_str(rest);
        Ok((out, Self { prefix, tokens }))
    }

    /// Substitute placeholders in one string scalar: restore the original
    /// token text, then resolve it with the token resolver.
    fn resolve_str(
        &self,
        scalar: &str,
        lookup: &impl Fn(&str) -> Option<String>,
        used_names: &mut HashSet<String>,
    ) -> Result<String> {
        if !scalar.contains(&self.prefix) {
            return Ok(scalar.to_string());
        }
        let mut restored = String::with_capacity(scalar.len());
        let mut rest = scalar;
        while let Some(start) = rest.find(&self.prefix) {
            restored.push_str(&rest[..start]);
            let after = &rest[start + self.prefix.len()..];
            let digits = after.bytes().take_while(u8::is_ascii_digit).count();
            let token = after[..digits]
                .parse::<usize>()
                .ok()
                .filter(|_| after[digits..].starts_with("__"))
                .and_then(|index| self.tokens.get(index));
            match token {
                Some(token) => {
                    restored.push_str(token);
                    rest = &after[digits + 2..];
                }
                None => {
                    restored.push_str(&self.prefix);
                    rest = after;
                }
            }
        }
        restored.push_str(rest);
        let (resolved, used) = resolve_env_tokens_with_used(&restored, lookup)?;
        used_names.extend(used);
        Ok(resolved)
    }

    fn resolve_value(
        &self,
        value: Value,
        lookup: &impl Fn(&str) -> Option<String>,
        used_names: &mut HashSet<String>,
    ) -> Result<Value> {
        Ok(match value {
            Value::String(text) => Value::String(self.resolve_str(&text, lookup, used_names)?),
            Value::Sequence(items) => Value::Sequence(
                items
                    .into_iter()
                    .map(|item| self.resolve_value(item, lookup, used_names))
                    .collect::<Result<_>>()?,
            ),
            Value::Mapping(map) => {
                let mut out = Mapping::with_capacity(map.len());
                for (key, item) in map {
                    out.insert(
                        self.resolve_value(key, lookup, used_names)?,
                        self.resolve_value(item, lookup, used_names)?,
                    );
                }
                Value::Mapping(out)
            }
            Value::Tagged(mut tagged) => {
                tagged.value = self.resolve_value(tagged.value, lookup, used_names)?;
                Value::Tagged(tagged)
            }
            other => other,
        })
    }
}

#[cfg(test)]
fn resolve_env_tokens_with(text: &str, lookup: impl Fn(&str) -> Option<String>) -> Result<String> {
    resolve_env_tokens_with_used(text, lookup).map(|(resolved, _)| resolved)
}

/// Parse a token body (`NAME` or `NAME:default`) into its name and decoded
/// default. The default may itself contain colons and supports only strict
/// %HH percent escapes, so awkward values like "}}" can be written safely
/// without form-style '+' decoding.
fn parse_env_token(inner: &str) -> Result<(&str, Option<String>)> {
    let (name, default) = match inner.split_once(':') {
        Some((name, default)) => (
            name.trim(),
            Some(percent_decode_best_effort(default.trim())),
        ),
        None => (inner.trim(), None),
    };
    if name.is_empty() {
        anyhow::bail!("empty variable name in {{{{ENV:...}}}} token");
    }
    if !is_valid_env_name(name) {
        anyhow::bail!(
            "invalid variable name {name:?} in {{{{ENV:...}}}} token; use [A-Za-z_][A-Za-z0-9_]*"
        );
    }
    Ok((name, default))
}

/// Splice resolved token values into `text`. Applied to individual string
/// scalars by `EnvPlaceholders`, never to raw YAML.
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
        let (name, default) = parse_env_token(&token[OPEN.len()..end])?;
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

fn percent_decode_best_effort(value: &str) -> String {
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

fn is_valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() && first != b'_' {
        return false;
    }
    bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
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

/// Value to print for a resolved env token. Secret-looking names never reveal
/// any characters, only that a value is set and its length.
fn mask_env_value(name: &str, value: &str) -> String {
    if !is_sensitive_env_name(name) {
        return value.to_string();
    }
    format!("<set, {} chars>", value.chars().count())
}

fn is_sensitive_env_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    ["pass", "secret", "token", "key", "credential"]
        .iter()
        .any(|marker| name.contains(marker))
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
    #[serde(deserialize_with = "lenient::from_str")]
    pub rotate_size_bytes: u64,
    #[serde(deserialize_with = "lenient::from_str")]
    pub max_backups: usize,
    #[serde(deserialize_with = "lenient::bool")]
    pub compress: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CrlConfig {
    #[serde(deserialize_with = "lenient::bool")]
    pub enabled: bool,
    #[serde(deserialize_with = "lenient::from_str")]
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
        let (config, used_names) = Self::from_yaml_with(&text, |name| std::env::var(name).ok())
            .with_context(|| format!("failed to load config file {}", path.display()))?;
        warn_unused_minica_env_vars(&used_names);
        Ok(config)
    }

    /// Parse, env-resolve, validate and normalise config text. `lookup`
    /// supplies environment variables (injectable for tests). Returns the
    /// env names referenced by resolved tokens.
    fn from_yaml_with(
        text: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<(Self, HashSet<String>)> {
        let (mut config, used_names) = parse_config_with_env(text, lookup)?;
        config.auth.validate().context("invalid auth config")?;
        config
            .templates
            .validate()
            .context("invalid templates config")?;
        config.server.base_path = normalize_base_path(&config.server.base_path);
        if let Some(base) = config.public_base_url.as_mut() {
            while base.ends_with('/') {
                base.pop();
            }
        }
        if config.crl.next_update_days < 1 {
            config.crl.next_update_days = 30;
        }
        Ok((config, used_names))
    }

    /// Cookie `Path` for the app: the base path, or `/` when mounted at root.
    pub fn cookie_path(&self) -> &str {
        if self.server.base_path.is_empty() {
            "/"
        } else {
            &self.server.base_path
        }
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

/// `minica` / `/minica/` -> `/minica`; `/`, `` and `///` -> `` (mounted at
/// the root).
fn normalize_base_path(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("/{trimmed}")
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
    fn names_follow_shell_env_var_shape() {
        let out =
            resolve_env_tokens_with("a: {{ENV:_A1:one}}\nb: {{ENV:lower_case:two}}", lookup(&[]))
                .expect("resolves");
        assert_eq!(out, "a: one\nb: two");

        for token in [
            "{{ENV:1BAD:default}}",
            "{{ENV:BAD-NAME:default}}",
            "{{ENV:BAD.NAME:default}}",
            "{{ENV:BAD NAME:default}}",
        ] {
            let err = resolve_env_tokens_with(token, lookup(&[]))
                .unwrap_err()
                .to_string();
            assert!(err.contains("invalid variable name"), "{err}");
        }
    }

    #[test]
    fn default_percent_decodes_strict_hex_escapes_only() {
        let out = resolve_env_tokens_with("x: {{ENV:A:a%3Ab%20%7D%7D}} trailing", lookup(&[]))
            .expect("resolves");
        assert_eq!(out, "x: a:b }} trailing");

        let out = resolve_env_tokens_with("x: {{ENV:A:%ZZ%7D}}", lookup(&[])).expect("resolves");
        assert_eq!(out, "x: %ZZ}");

        let out = resolve_env_tokens_with("x: {{ENV:A:a+b%2Bc}}", lookup(&[])).expect("resolves");
        assert_eq!(out, "x: a+b+c");
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
    fn secret_like_env_values_are_masked_for_logs() {
        assert_eq!(
            mask_env_value("MINICA_ADMIN_PASSWORD", "adminpass"),
            "<set, 9 chars>"
        );
        assert_eq!(mask_env_value("DB_PASSWD", "secret"), "<set, 6 chars>");
        assert_eq!(mask_env_value("TLS_PASSPHRASE", "abc"), "<set, 3 chars>");
        assert_eq!(mask_env_value("TYPO_PASSWWORD", "secret"), "<set, 6 chars>");
        assert_eq!(mask_env_value("API_SECRET", "s3"), "<set, 2 chars>");
        assert_eq!(mask_env_value("GITHUB_TOKEN", "t"), "<set, 1 chars>");
        assert_eq!(mask_env_value("SIGNING_KEY", "k"), "<set, 1 chars>");
    }

    #[test]
    fn non_secret_env_values_are_not_masked_for_logs() {
        assert_eq!(mask_env_value("MINICA_PORT", "9988"), "9988");
        assert_eq!(
            mask_env_value("MINICA_OPENSSL_KEEP_FAILED_WORKDIRS", "false"),
            "false"
        );
    }

    #[test]
    fn very_short_secret_env_values_reveal_nothing() {
        assert_eq!(mask_env_value("PASSWORD", ""), "<set, 0 chars>");
        assert_eq!(mask_env_value("PASSWORD", "a"), "<set, 1 chars>");
        assert_eq!(mask_env_value("PASSWORD", "ab"), "<set, 2 chars>");
    }

    const BASE_YAML: &str = "server:\n  host: 0.0.0.0\n  port: 9988\n  base_path: /minica\nruntime:\n  folder: ./runtime\nopenssl:\n  path: /usr/bin/openssl\n  working_root: ./w\n  keep_failed_workdirs: false\n  reap_after_hours: 24\n";

    fn load_with(yaml: &str, pairs: &'static [(&'static str, &'static str)]) -> Config {
        Config::from_yaml_with(yaml, lookup(pairs))
            .expect("config loads")
            .0
    }

    const AUTH_YAML: &str = "auth:\n  users:\n    - username: admin\n      password: x\n      role: admin\n";

    #[test]
    fn templates_section_is_optional_and_env_friendly() {
        let config = load_with(&format!("{BASE_YAML}{AUTH_YAML}"), &[]);
        assert_eq!(config.templates.defaults, FormTemplate::default());
        assert!(config.templates.ca.is_empty() && config.templates.certificate.is_empty());

        let yaml = format!(
            "{BASE_YAML}{AUTH_YAML}templates:\n  defaults:\n    country_code: {{{{ENV:CC:DE}}}}\n    organization: '{{{{ENV:ORG:}}}}'\n    valid_days: {{{{ENV:DAYS:398}}}}\n    key_profile: {{{{ENV:KP:ecdsa:prime256v1}}}}\n  certificate:\n    - name: Web server\n      valid_days: 365\n      organization_unit: Web\n    - name: Client\n      key_profile: rsa:2048\n      digest_algorithm: sha256\n"
        );
        let config = load_with(&yaml, &[("ORG", "Acme")]);
        let defaults = &config.templates.defaults;
        assert_eq!(defaults.country_code.as_deref(), Some("DE"));
        assert_eq!(defaults.organization.as_deref(), Some("Acme"));
        assert_eq!(defaults.valid_days, Some(398));
        assert_eq!(defaults.key_profile.as_deref(), Some("ecdsa:prime256v1"));
        assert_eq!(defaults.state, None, "unset stays unset");
        assert_eq!(config.templates.certificate.len(), 2);
        let web = config.templates.certificate[0].over(defaults);
        assert_eq!(web.name.as_deref(), Some("Web server"));
        assert_eq!(web.valid_days, Some(365), "preset wins");
        assert_eq!(web.country_code.as_deref(), Some("DE"), "defaults fill the rest");
        assert_eq!(web.organization_unit.as_deref(), Some("Web"));
        // An empty env value means "not set", so the built-in default applies.
        let config = load_with(&yaml, &[]);
        assert_eq!(config.templates.defaults.organization, None);
    }

    #[test]
    fn templates_are_validated() {
        for (fragment, expected) in [
            ("  certificate:\n    - valid_days: 10\n", "needs a name"),
            ("  certificate:\n    - name: a\n    - name: A\n", "duplicate preset name"),
            ("  ca:\n    - name: a\n      valid_days: 0\n", "valid_days must be in 1..7350"),
            ("  defaults:\n    country_code: DEU\n", "2-letter"),
            ("  defaults:\n    bogus: 1\n", "unknown field"),
        ] {
            let yaml = format!("{BASE_YAML}{AUTH_YAML}templates:\n{fragment}");
            let err = Config::from_yaml_with(&yaml, lookup(&[]))
                .err()
                .map(|err| format!("{err:#}"))
                .unwrap_or_default();
            assert!(err.contains(expected), "{fragment:?}: {err}");
        }
    }

    #[test]
    fn tricky_env_values_stay_single_string_scalars() {
        let yaml = format!(
            "{BASE_YAML}auth:\n  users:\n    - username: {{{{ENV:U:admin}}}}\n      password: {{{{ENV:P:x}}}}\n      role: admin\n"
        );
        for password in [
            "a: b",
            "x #comment",
            "*alias",
            "&anchor",
            "!tag",
            "@at",
            "line1\nline2\n  role: viewer",
            "{{not a token}}",
            "'quoted'",
            "- item",
            "12345",
            "true",
            "null",
        ] {
            let leaked: &'static str = Box::leak(password.to_string().into_boxed_str());
            let pairs: &'static [(&'static str, &'static str)] =
                Box::leak(vec![("P", leaked)].into_boxed_slice());
            let config = load_with(&yaml, pairs);
            let users = config.auth.basic_users();
            assert_eq!(users.len(), 1, "{password:?}");
            assert_eq!(users[0].password, password);
            assert_eq!(users[0].username, "admin");
            assert_eq!(users[0].role, Role::Admin);
        }
    }

    #[test]
    fn tokens_in_comments_are_not_resolved() {
        let yaml = format!(
            "# {{{{ENV:IN_COMMENT:x}}}}\n{BASE_YAML}auth:\n  users: [] # {{{{ENV:ALSO_COMMENT}}}}\n"
        );
        let (_, used) = Config::from_yaml_with(&yaml, lookup(&[])).expect("loads");
        assert!(used.is_empty(), "{used:?}");
    }

    #[test]
    fn whole_and_partial_tokens_coerce_to_target_types() {
        let yaml = "server:\n  host: '{{ENV:H:0.0.0.0}}'\n  port: {{ENV:PORT:9988}}\n  base_path: /pre{{ENV:BP:fix}}\nruntime:\n  folder: ./runtime\n  db_folder: {{ENV:DB:null}}\nopenssl:\n  path: /usr/bin/openssl\n  working_root: ./w\n  keep_failed_workdirs: {{ENV:KEEP:false}}\n  reap_after_hours: {{ENV:REAP:24}}\nauth:\n  users: []\n";
        let config = load_with(yaml, &[("PORT", " 8443 "), ("KEEP", "TRUE")]);
        assert_eq!(config.server.port, 8443);
        assert_eq!(config.server.base_path, "/prefix");
        assert!(config.openssl.keep_failed_workdirs);
        assert_eq!(config.openssl.reap_after_hours, 24);
        assert!(config.runtime.db_folder.is_none());

        let err = Config::from_yaml_with(yaml, lookup(&[("PORT", "nope")]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid number"), "{err}");
    }

    #[test]
    fn docker_template_loads_with_defaults() {
        let (config, used) =
            Config::from_yaml_with(include_str!("../config.yaml.docker"), lookup(&[]))
                .expect("docker template loads with no env vars");
        let example: Config = Config::from_yaml_with(SAMPLE_CONFIG, lookup(&[]))
            .expect("example loads")
            .0;
        assert_eq!(config.server.host, example.server.host);
        assert_eq!(config.server.port, example.server.port);
        assert_eq!(config.server.base_path, "/minica");
        assert_eq!(config.public_base_url, example.public_base_url);
        assert!(config.crl.enabled);
        assert_eq!(config.crl.next_update_days, 30);
        assert!(config.runtime.db_folder.is_none());
        assert_eq!(config.logging.rotate_size_bytes, 10_485_760);
        assert_eq!(config.logging.max_backups, 10);
        assert!(config.logging.compress);
        assert_eq!(config.openssl.timeout_seconds, 15);
        assert!(!config.openssl.keep_failed_workdirs);
        assert_eq!(config.openssl.reap_after_hours, 24);
        assert!(config.auth.active_headers().is_none());
        let users = config.auth.basic_users();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin");
        assert_eq!(users[0].password, "adminpass");
        assert!(used.contains("MINICA_PORT"));
        assert!(used.contains("MINICA_TRUSTED_REMOTE_10"));
    }

    #[test]
    fn docker_template_loads_with_tricky_env_values() {
        let (config, _) = Config::from_yaml_with(
            include_str!("../config.yaml.docker"),
            lookup(&[
                ("MINICA_PORT", "8443"),
                ("MINICA_BASE_PATH", "/"),
                ("MINICA_DB_FOLDER", "/data/db # not a comment"),
                ("MINICA_CRL_ENABLED", "false"),
                ("MINICA_LOG_COMPRESS", "no"),
                ("MINICA_ADMIN_PASSWORD", "p@ss: #word\n- injected"),
                ("MINICA_ADMIN_ROLE", "viewer"),
                ("MINICA_HEADER_AUTH_ENABLE", "true"),
                ("MINICA_TRUSTED_REMOTE_1", "10.0.0.7"),
                ("MINICA_TRUSTED_REMOTE_2", "172.16.0.0/12"),
                ("MINICA_TRUSTED_REMOTE_3", "::1"),
            ]),
        )
        .expect("docker template loads with env vars");
        assert_eq!(config.server.port, 8443);
        assert_eq!(config.server.base_path, "");
        assert_eq!(
            config.runtime.db_folder,
            Some(PathBuf::from("/data/db # not a comment"))
        );
        assert!(!config.crl.enabled);
        assert!(!config.logging.compress);
        let users = config.auth.basic_users();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].password, "p@ss: #word\n- injected");
        assert_eq!(users[0].role, Role::Viewer);
        let headers = config.auth.active_headers().expect("header auth on");
        assert_eq!(headers.trusted_networks.len(), 3);
    }

    #[test]
    fn docker_template_refuses_header_auth_without_trusted_remotes() {
        let err = Config::from_yaml_with(
            include_str!("../config.yaml.docker"),
            lookup(&[("MINICA_HEADER_AUTH_ENABLE", "true")]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("trust_all_remotes"), "{err:#}");
    }

    #[test]
    fn base_path_is_normalised_and_root_is_empty() {
        assert_eq!(normalize_base_path("/minica"), "/minica");
        assert_eq!(normalize_base_path("minica/"), "/minica");
        assert_eq!(normalize_base_path("/a/b/"), "/a/b");
        assert_eq!(normalize_base_path("/"), "");
        assert_eq!(normalize_base_path(""), "");
        assert_eq!(normalize_base_path("//"), "");
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
        let mut auth = parse("headers:\n  trust_all_remotes: true\n");
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
        // skipped too. All placeholders -> empty list, which needs the
        // explicit trust_all_remotes opt-in.
        let mut auth = parse(
            "headers:\n  trusted_remotes:\n    - '-'\n    - ''\n    - 10.0.0.0/8\n    - ' - '\n",
        );
        auth.validate().expect("valid");
        let networks = auth.headers.expect("headers config").trusted_networks;
        assert_eq!(networks.len(), 1);
        assert!(networks[0].contains(&"10.1.2.3".parse::<std::net::IpAddr>().expect("test ip")));

        let mut auth = parse("headers:\n  trusted_remotes:\n    - '-'\n    - '-'\n");
        let err = auth.validate().unwrap_err().to_string();
        assert!(err.contains("trust_all_remotes"), "{err}");

        let mut auth = parse(
            "headers:\n  trust_all_remotes: true\n  trusted_remotes:\n    - '-'\n    - '-'\n",
        );
        auth.validate().expect("valid with explicit opt-in");
        assert!(
            auth.headers
                .expect("headers config")
                .trusted_networks
                .is_empty()
        );
    }

    #[test]
    fn header_auth_with_no_trusted_remotes_is_refused() {
        let mut auth = parse("headers: {}\n");
        let err = auth.validate().unwrap_err().to_string();
        assert!(err.contains("trusted_remotes is empty"), "{err}");
        // a disabled headers section does not need a trusted list
        let mut auth = parse("users: []\nheaders:\n  enabled: false\n");
        auth.validate().expect("valid: header auth disabled");
    }

    #[test]
    fn typos_in_auth_sections_are_named() {
        let err = serde_yaml::from_str::<AuthConfig>("users:\n  enabld: true\n  list: []\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("enabld"), "{err}");
        let err = serde_yaml::from_str::<AuthConfig>("headers:\n  trusted_remote: [10.0.0.1]\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("trusted_remote"), "{err}");
        let err = serde_yaml::from_str::<AuthConfig>("users: admin\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("list of accounts"), "{err}");
    }

    #[test]
    fn malformed_trusted_remote_is_named_in_error() {
        let mut auth = parse("headers:\n  trusted_remotes:\n    - 10.0.0.0/33\n");
        let err = auth.validate().unwrap_err().to_string();
        assert!(err.contains("10.0.0.0/33"), "{err}");
    }
}
