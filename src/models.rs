use serde::{Deserialize, Deserializer, Serialize};

/// Deserialize a value, treating an explicit JSON `null` (as well as a missing
/// field, when combined with `#[serde(default)]`) as the type's default. The Go
/// CLI marshals empty slices to `null`, so requests can arrive with
/// `"dns_list": null` / `"ip_list": null`.
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Clone, Debug, Serialize)]
pub struct CertificateAuthority {
    pub id: String,
    pub common_name: String,
    pub country_code: String,
    pub state: String,
    pub city: String,
    pub organization: String,
    pub organization_unit: String,
    pub subject: String,
    pub issue_time: i64,
    pub valid_days: i64,
    pub key_profile: String,
    pub digest_algorithm: String,
    pub cert_count: i64,
    pub cert_pem: String,
    pub key_pem: String,
    pub crl_url: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Certificate {
    pub id: String,
    pub ca_id: String,
    pub common_name: String,
    pub country_code: String,
    pub state: String,
    pub city: String,
    pub organization: String,
    pub organization_unit: String,
    pub subject: String,
    pub issue_time: i64,
    pub valid_days: i64,
    pub dns_list: Vec<String>,
    pub ip_list: Vec<String>,
    pub key_profile: String,
    pub digest_algorithm: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub revoked_at: Option<i64>,
    pub revocation_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateCaRequest {
    pub common_name: String,
    pub country_code: String,
    pub state: String,
    pub city: String,
    pub organization: String,
    pub organization_unit: String,
    pub valid_days: i64,
    pub digest_algorithm: String,
    pub key_profile: String,
    pub password: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ImportCaRequest {
    pub cert_pem: String,
    pub key_pem: String,
    pub password: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ImportCertRequest {
    pub cert_pem: String,
    pub key_pem: String,
    pub password: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateCertRequest {
    pub common_name: String,
    pub country_code: String,
    pub state: String,
    pub city: String,
    pub organization: String,
    pub organization_unit: String,
    pub valid_days: i64,
    pub digest_algorithm: String,
    pub key_profile: String,
    pub password: Option<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub dns_list: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub ip_list: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct InspectRequest {
    pub cert_pem: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub role: String,
    pub created_at: i64,
}

/// Which creation forms a template is offered on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateScope {
    Both,
    Ca,
    Certificate,
}

impl TemplateScope {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "both" => Some(Self::Both),
            "ca" => Some(Self::Ca),
            "certificate" => Some(Self::Certificate),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Ca => "ca",
            Self::Certificate => "certificate",
        }
    }

    /// Whether a template with this scope belongs on the form of `kind`
    /// (`Ca` or `Certificate`).
    pub fn covers(self, kind: TemplateScope) -> bool {
        self == TemplateScope::Both || self == kind
    }

    /// Whether two scopes share at least one form (so only one of two
    /// default templates with overlapping scopes can apply).
    pub fn overlaps(self, other: TemplateScope) -> bool {
        self == TemplateScope::Both || other == TemplateScope::Both || self == other
    }
}

/// The form fields a template can pre-fill. `None` leaves the form's own
/// value alone, so a template only needs to carry what it changes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateValues {
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default)]
    pub organization_unit: Option<String>,
    #[serde(default)]
    pub valid_days: Option<i64>,
    #[serde(default)]
    pub digest_algorithm: Option<String>,
    #[serde(default)]
    pub key_profile: Option<String>,
}

impl TemplateValues {
    /// `self` with every unset field taken from `base`.
    pub fn over(&self, base: &TemplateValues) -> TemplateValues {
        TemplateValues {
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

    /// Trims every text field and turns blank ones into `None`.
    pub fn normalized(&self) -> TemplateValues {
        fn clean(value: &Option<String>) -> Option<String> {
            value
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        }
        TemplateValues {
            country_code: clean(&self.country_code).map(|code| code.to_uppercase()),
            state: clean(&self.state),
            city: clean(&self.city),
            organization: clean(&self.organization),
            organization_unit: clean(&self.organization_unit),
            valid_days: self.valid_days,
            digest_algorithm: clean(&self.digest_algorithm).map(|digest| digest.to_lowercase()),
            key_profile: clean(&self.key_profile).map(|profile| profile.to_lowercase()),
        }
    }
}

/// A global form template, managed in the web UI / API and stored in the
/// database. `scope` is `both`, `ca` or `certificate`; at most one default
/// template applies to each creation form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Template {
    pub id: String,
    pub name: String,
    pub scope: String,
    pub is_default: bool,
    #[serde(flatten)]
    pub values: TemplateValues,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Template {
    pub fn scope(&self) -> TemplateScope {
        TemplateScope::parse(&self.scope).unwrap_or(TemplateScope::Both)
    }
}

/// Create/update payload for a template. Blank strings count as unset.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TemplateRequest {
    pub name: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub is_default: bool,
    #[serde(flatten)]
    pub values: TemplateValues,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectResponse {
    pub info: Vec<(String, String)>,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub purposes: Vec<(String, String)>,
    pub raw_text: String,
}

#[cfg(test)]
mod null_list_tests {
    use super::*;

    #[test]
    fn create_cert_request_accepts_null_lists() {
        let json = r#"{
            "common_name": "example.com",
            "country_code": "US",
            "state": "CA",
            "city": "SF",
            "organization": "Org",
            "organization_unit": "Unit",
            "valid_days": 365,
            "digest_algorithm": "sha256",
            "key_profile": "rsa2048",
            "dns_list": null,
            "ip_list": null
        }"#;
        let req: CreateCertRequest =
            serde_json::from_str(json).expect("null lists should deserialize");
        assert!(req.dns_list.is_empty());
        assert!(req.ip_list.is_empty());
    }
}
