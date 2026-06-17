use serde::{Deserialize, Serialize};

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
    #[serde(default)]
    pub dns_list: Vec<String>,
    #[serde(default)]
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
