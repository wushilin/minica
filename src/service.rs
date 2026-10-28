use crate::{
    config::{CrlConfig, Role},
    db::{
        BackupCaRow, BackupCertRow, BackupSnapshot, CaMeta, CaSecrets, CertMeta, CertSecrets, Db,
        SCHEMA_VERSION, UserRecord,
    },
    models::{
        Certificate, CertificateAuthority, CreateCaRequest, CreateCertRequest, CreateUserRequest,
        ImportCaRequest, ImportCertRequest, InspectResponse, Template, TemplateRequest,
        TemplateScope, TemplateValues, UserView,
    },
    openssl::{
        OpenSsl, RenewalRequest, build_bundle, create_subject, escape_subject, normalize_digest,
        random_password,
    },
};
use anyhow::{Context, Result, bail};
use base64::Engine;
use chrono::{NaiveDateTime, TimeZone, Utc};
use rand::{Rng, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppService {
    db: Db,
    openssl: OpenSsl,
    public_base_url: Option<String>,
    crl: CrlConfig,
    /// Usernames of the config-file (bootstrap) accounts. DB users may not
    /// reuse them, or the two accounts would shadow each other at login.
    reserved_usernames: Vec<String>,
}

/// Password of every CA's truststore: Java's conventional default. The store
/// holds only the public CA certificate, so the password protects nothing and
/// is published alongside it.
pub const TRUSTSTORE_PASSWORD: &str = "changeit";

pub enum Download {
    CaCert,
    CaKey,
    CaPkcs12,
    CaPassword,
    CaTruststore,
    CaTruststorePassword,
    CertBundle,
    CertPem,
    CertCsr,
    CertKey,
    CertPkcs12,
    CertPassword,
}

struct KeySpec {
    profile: String,
    algorithm: String,
    attributes: Value,
}

const BACKUP_FORMAT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
pub struct BackupFile {
    pub format_version: u32,
    #[serde(default)]
    pub app_version: String,
    #[serde(default)]
    pub schema_version: u32,
    pub app: String,
    pub exported_at: i64,
    pub warning: String,
    #[serde(default)]
    pub users: Vec<BackupUser>,
    #[serde(default)]
    pub templates: Vec<BackupTemplate>,
    pub certificate_authorities: Vec<BackupCa>,
}

/// A form template in a backup (same shape as `models::Template`).
#[derive(Serialize, Deserialize)]
pub struct BackupTemplate {
    pub id: String,
    pub name: String,
    #[serde(default = "default_template_scope")]
    pub scope: String,
    #[serde(default)]
    pub is_default: bool,
    #[serde(flatten)]
    pub values: TemplateValues,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
}

fn default_template_scope() -> String {
    TemplateScope::Both.as_str().to_string()
}

impl From<Template> for BackupTemplate {
    fn from(template: Template) -> Self {
        Self {
            id: template.id,
            name: template.name,
            scope: template.scope,
            is_default: template.is_default,
            values: template.values,
            created_at: template.created_at,
            updated_at: template.updated_at,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BackupUser {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    #[serde(default)]
    pub created_at: i64,
}

#[derive(Serialize, Deserialize)]
pub struct BackupCa {
    pub meta: BackupCaMeta,
    pub secrets: BackupCaSecrets,
    pub certificates: Vec<BackupCert>,
}

#[derive(Serialize, Deserialize)]
pub struct BackupCaMeta {
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
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize)]
pub struct BackupCaSecrets {
    pub cert_pem_b64: String,
    pub key_pem_b64: String,
    pub pkcs12_b64: String,
    pub password_b64: String,
    pub index_txt_b64: String,
    pub serial_txt_b64: String,
    #[serde(default)]
    pub crl_der_b64: String,
    #[serde(default)]
    pub crl_updated_at: i64,
    /// Absent in backups made before CRL numbering; restores as "start at 1".
    #[serde(default)]
    pub crlnumber_txt_b64: String,
}

#[derive(Serialize, Deserialize)]
pub struct BackupCert {
    pub meta: BackupCertMeta,
    pub secrets: BackupCertSecrets,
}

#[derive(Serialize, Deserialize)]
pub struct BackupCertMeta {
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
    #[serde(default)]
    pub revoked_at: Option<i64>,
    #[serde(default)]
    pub revocation_reason: Option<String>,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize)]
pub struct BackupCertSecrets {
    pub cert_pem_b64: String,
    pub key_pem_b64: String,
    pub csr_pem_b64: String,
    pub pkcs12_b64: String,
    pub password_b64: String,
    pub bundle_zip_b64: String,
}

impl AppService {
    pub fn new(db: Db, openssl: OpenSsl, public_base_url: Option<String>, crl: CrlConfig) -> Self {
        Self {
            db,
            openssl,
            public_base_url,
            crl,
            reserved_usernames: Vec::new(),
        }
    }

    /// Registers the bootstrap (config-file) usernames so `create_user`
    /// refuses DB accounts with the same name.
    pub fn with_reserved_usernames<I, S>(mut self, usernames: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.reserved_usernames = usernames.into_iter().map(Into::into).collect();
        self
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id()))]
    pub fn list_cas(&self) -> Result<Vec<CertificateAuthority>> {
        let cas = self
            .db
            .list_cas()?
            .into_iter()
            .map(|ca| self.repair_ca_metadata_if_needed(ca))
            .map(|ca| ca.map(|ca| self.with_ca_crl_url(ca)))
            .collect::<Result<Vec<_>>>()?;
        tracing::info!(count = cas.len(), "listed certificate authorities");
        Ok(cas)
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id(), ca_id = %id))]
    pub fn get_ca(&self, id: &str) -> Result<CertificateAuthority> {
        let ca = self.with_ca_crl_url(self.repair_ca_metadata_if_needed(self.db.get_ca(id)?)?);
        tracing::info!(ca_id = %id, "read certificate authority");
        Ok(ca)
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id(), ca_id = %id))]
    pub fn delete_ca(&self, id: &str) -> Result<()> {
        tracing::info!(ca_id = %id, "deleting certificate authority");
        self.db.delete_ca(id)
    }

    #[tracing::instrument(
        skip(self, req),
        err,
        fields(
            span_id = %span_id(),
            common_name = %req.common_name,
            valid_days = req.valid_days,
            key_profile = %req.key_profile,
            digest_algorithm = %req.digest_algorithm
        )
    )]
    pub fn create_ca(&self, req: CreateCaRequest) -> Result<CertificateAuthority> {
        tracing::info!(
            common_name = %req.common_name,
            valid_days = req.valid_days,
            key_profile = %req.key_profile,
            digest_algorithm = %req.digest_algorithm,
            "creating certificate authority"
        );
        validate_days(req.valid_days)?;
        let key = key_spec(&req.key_profile)?;
        let digest = normalize_digest(&req.digest_algorithm)?;
        validate_password(req.password.as_deref())?;
        self.ensure_unique_ca_common_name(&req.common_name)?;
        let subject = create_subject(
            &req.common_name,
            &req.country_code,
            &req.organization,
            &req.state,
            &req.city,
            &req.organization_unit,
        )?;
        let password = req.password.unwrap_or_else(random_password);
        let id = short_id();
        let work = self.openssl.workdir()?;
        let mut secrets = self.openssl.create_ca_files(
            work.path(),
            &subject,
            req.valid_days,
            &digest,
            &key.algorithm,
            &key.attributes,
            &password,
        )?;
        self.attach_initial_crl(&mut secrets)?;
        let meta = CaMeta {
            id: id.clone(),
            common_name: req.common_name,
            country_code: req.country_code,
            state: req.state,
            city: req.city,
            organization: req.organization,
            organization_unit: req.organization_unit,
            subject,
            issue_time: Utc::now().timestamp_millis(),
            valid_days: req.valid_days,
            key_profile: key.profile,
            digest_algorithm: digest,
        };
        self.db.insert_ca(&meta, &secrets)?;
        self.prebuild_truststore(&id, &secrets.cert_pem);
        let ca = self.db.get_ca(&id)?;
        tracing::info!(
            ca_id = %id,
            common_name = %ca.common_name,
            cert_bytes = secrets.cert_pem.len(),
            key_bytes = secrets.key_pem.len(),
            pkcs12_bytes = secrets.pkcs12.len(),
            "created certificate authority"
        );
        Ok(self.with_ca_crl_url(ca))
    }

    #[tracing::instrument(skip(self, req), err, fields(span_id = %span_id()))]
    pub fn import_ca(&self, req: ImportCaRequest) -> Result<CertificateAuthority> {
        self.import_ca_with_id(None, req)
    }

    /// Imports a CA under a caller-chosen id (the legacy 1.0.x migration keeps
    /// the original directory names); `None` mints a fresh id. The subject,
    /// validity, key and digest are all read from the certificate itself.
    pub fn import_ca_with_id(
        &self,
        id: Option<String>,
        req: ImportCaRequest,
    ) -> Result<CertificateAuthority> {
        tracing::info!(
            cert_pem_bytes = req.cert_pem.len(),
            key_pem_bytes = req.key_pem.len(),
            "importing certificate authority"
        );
        validate_password(req.password.as_deref())?;
        let id = match id {
            Some(id) => validate_entity_id(&id)?,
            None => short_id(),
        };
        if self.db.ca_exists(&id)? {
            bail!("certificate authority id already exists: {id}");
        }
        let password = req.password.unwrap_or_else(random_password);
        let work = self.openssl.workdir()?;
        fs::write(work.path().join("ca-cert.pem"), req.cert_pem.as_bytes())?;
        fs::write(work.path().join("ca-key.pem"), req.key_pem.as_bytes())?;
        let info = self.openssl.inspect_cert(work.path(), &req.cert_pem)?;
        if !self.openssl.is_ca_cert(work.path(), &req.cert_pem)? {
            bail!("the certificate is not a certificate authority (basicConstraints CA:TRUE is missing)");
        }
        self.openssl
            .check_key_matches_cert(work.path(), "ca-cert.pem", "ca-key.pem")
            .context("the private key does not match the CA certificate")?;
        let text = self
            .openssl
            .inspect_cert_text(work.path(), &req.cert_pem)
            .unwrap_or_default();
        let derived = self.derive_subject(work.path(), &req.cert_pem, &info);
        let common_name = derived
            .common_name
            .clone()
            .unwrap_or_else(|| "Imported CA".to_string());
        self.ensure_unique_ca_common_name(&common_name)?;
        let (issue_time, valid_days) = validity_from_info(&info);
        let mut secrets = self.openssl.finish_ca_files(work.path(), &password)?;
        self.attach_initial_crl(&mut secrets)?;
        let meta = CaMeta {
            id: id.clone(),
            common_name,
            country_code: derived.country_code,
            state: derived.state,
            city: derived.city,
            organization: derived.organization,
            organization_unit: derived.organization_unit,
            subject: derived.subject,
            issue_time,
            valid_days,
            key_profile: parse_public_key_profile(&text),
            digest_algorithm: parse_signature_digest(&text)
                .unwrap_or_else(|| "imported".to_string()),
        };
        self.db.insert_ca(&meta, &secrets)?;
        self.prebuild_truststore(&id, &secrets.cert_pem);
        let ca = self.db.get_ca(&id)?;
        tracing::info!(
            ca_id = %id,
            common_name = %ca.common_name,
            key_profile = %ca.key_profile,
            digest_algorithm = %ca.digest_algorithm,
            cert_bytes = secrets.cert_pem.len(),
            key_bytes = secrets.key_pem.len(),
            pkcs12_bytes = secrets.pkcs12.len(),
            "imported certificate authority"
        );
        Ok(self.with_ca_crl_url(ca))
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id(), ca_id = %ca_id))]
    pub fn list_certs(&self, ca_id: &str) -> Result<Vec<Certificate>> {
        // Surface a "not found" for a missing or soft-deleted CA rather than an
        // empty list, so requests against a deleted CA fail consistently.
        self.db.get_ca(ca_id)?;
        let certs = self.db.list_certs(ca_id)?;
        tracing::info!(ca_id = %ca_id, count = certs.len(), "listed certificates");
        Ok(certs)
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id(), ca_id = %ca_id, cert_id = %cert_id))]
    pub fn get_cert(&self, ca_id: &str, cert_id: &str) -> Result<Certificate> {
        let cert = self.db.get_cert(ca_id, cert_id)?;
        tracing::info!(ca_id = %ca_id, cert_id = %cert_id, "read certificate");
        Ok(cert)
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id(), ca_id = %ca_id, cert_id = %cert_id))]
    pub fn delete_cert(&self, ca_id: &str, cert_id: &str) -> Result<()> {
        tracing::info!(ca_id = %ca_id, cert_id = %cert_id, "deleting certificate");
        self.db.delete_cert(ca_id, cert_id)
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id(), ca_id = %ca_id, cert_id = %cert_id, reason = %reason))]
    pub fn revoke_cert(&self, ca_id: &str, cert_id: &str, reason: &str) -> Result<Certificate> {
        if !self.crl.enabled {
            bail!("CRL support is disabled");
        }
        let reason = normalize_revocation_reason(reason)?;
        tracing::warn!(ca_id = %ca_id, cert_id = %cert_id, reason = %reason, "revoking certificate");
        if self.db.get_cert(ca_id, cert_id)?.revoked_at.is_some() {
            bail!("certificate is already revoked");
        }
        let owner = Uuid::new_v4().to_string();
        self.db.acquire_ca_lock(ca_id, &owner, 120_000)?;
        let revoked_at = Utc::now().timestamp_millis();
        let result = (|| -> Result<Certificate> {
            // Read the CA's openssl state only once the signing lock is held,
            // so a concurrent issue/revoke cannot be overwritten with stale data.
            if self.db.get_cert(ca_id, cert_id)?.revoked_at.is_some() {
                bail!("certificate is already revoked");
            }
            let ca_secrets = self.db.get_ca_secrets(ca_id)?;
            let cert_secrets = self.db.get_cert_secrets(ca_id, cert_id)?;
            let work = self.openssl.workdir()?;
            let refresh = self.openssl.revoke_cert_files(
                work.path(),
                &ca_secrets,
                &cert_secrets,
                &reason,
                self.crl.next_update_days,
            )?;
            self.db.revoke_cert_with_state(
                ca_id,
                cert_id,
                &reason,
                revoked_at,
                (&refresh.index_txt, &refresh.serial_txt),
                (&refresh.crl_der, &refresh.crlnumber_txt),
                &owner,
            )?;
            self.db.get_cert(ca_id, cert_id)
        })();
        if result.is_err() {
            tracing::warn!(ca_id = %ca_id, cert_id = %cert_id, owner_id = %owner, "certificate revocation failed; releasing CA lock");
            let _ = self.db.release_ca_lock(ca_id, &owner);
        }
        let cert = result?;
        tracing::warn!(ca_id = %ca_id, cert_id = %cert_id, reason = %reason, revoked_at, "revoked certificate");
        Ok(cert)
    }

    #[tracing::instrument(
        skip(self, req),
        err,
        fields(
            span_id = %span_id(),
            ca_id = %ca_id,
            common_name = %req.common_name,
            valid_days = req.valid_days,
            key_profile = %req.key_profile,
            digest_algorithm = %req.digest_algorithm,
            dns_count = req.dns_list.len(),
            ip_count = req.ip_list.len()
        )
    )]
    pub fn create_cert(&self, ca_id: &str, req: CreateCertRequest) -> Result<Certificate> {
        tracing::info!(
            ca_id = %ca_id,
            common_name = %req.common_name,
            valid_days = req.valid_days,
            key_profile = %req.key_profile,
            digest_algorithm = %req.digest_algorithm,
            dns_count = req.dns_list.len(),
            ip_count = req.ip_list.len(),
            "creating certificate"
        );
        validate_days(req.valid_days)?;
        let key = key_spec(&req.key_profile)?;
        let digest = normalize_digest(&req.digest_algorithm)?;
        validate_password(req.password.as_deref())?;
        let ip_list = req
            .ip_list
            .iter()
            .map(|ip| ip.trim())
            .filter(|ip| !ip.is_empty())
            .map(|ip| {
                ip.parse::<std::net::IpAddr>()
                    .map(|ip| ip.to_string())
                    .map_err(|_| anyhow::anyhow!("invalid IP SAN: {ip:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        // Every DNS SAN is strictly validated: these values are written into
        // an openssl config file, where `$`/newlines would otherwise expand
        // environment variables or inject extra SAN entries.
        let mut dns_list: Vec<String> = Vec::new();
        if is_valid_dns_name(&req.common_name) {
            dns_list.push(req.common_name.clone());
        }
        for dns in req.dns_list.iter().map(|dns| dns.trim()) {
            if dns.is_empty() {
                continue;
            }
            validate_dns_name(dns)?;
            if !dns_list.iter().any(|known| known.eq_ignore_ascii_case(dns)) {
                dns_list.push(dns.to_string());
            }
        }
        self.ensure_unique_cert_common_name(ca_id, &req.common_name)?;
        let ca = self.db.get_ca(ca_id)?;
        let valid_days = self.clamp_to_ca_validity(&ca.cert_pem, req.valid_days)?;
        let crl_url = self.issuing_crl_url(ca_id)?;
        let subject = create_subject(
            &req.common_name,
            &req.country_code,
            &req.organization,
            &req.state,
            &req.city,
            &req.organization_unit,
        )?;
        let cert_id = short_id();
        let owner = Uuid::new_v4().to_string();
        self.db.acquire_ca_lock(ca_id, &owner, 120_000)?;
        let result = (|| -> Result<Certificate> {
            // CA state is read under the lock so it cannot be stale.
            let ca_secrets = self.db.get_ca_secrets(ca_id)?;
            let work = self.openssl.workdir()?;
            let password = req.password.clone().unwrap_or_else(random_password);
            let (secrets, index_txt, serial_txt) = self.openssl.create_cert_files(
                work.path(),
                &ca_secrets,
                &subject,
                &req.common_name,
                valid_days,
                &digest,
                &key.algorithm,
                &key.attributes,
                &dns_list,
                &ip_list,
                &password,
                crl_url.as_deref(),
                self.crl.next_update_days,
            )?;
            let meta = CertMeta {
                id: cert_id.clone(),
                ca_id: ca_id.to_string(),
                common_name: req.common_name.clone(),
                country_code: req.country_code.clone(),
                state: req.state.clone(),
                city: req.city.clone(),
                organization: req.organization.clone(),
                organization_unit: req.organization_unit.clone(),
                subject,
                issue_time: Utc::now().timestamp_millis(),
                valid_days,
                dns_list: dns_list.clone(),
                ip_list: ip_list.clone(),
                key_profile: key.profile,
                digest_algorithm: digest.clone(),
                revoked_at: None,
                revocation_reason: None,
            };
            self.db.insert_cert_with_state(
                &meta,
                &secrets,
                Some((&index_txt, &serial_txt)),
                &owner,
            )?;
            self.db.get_cert(ca_id, &cert_id)
        })();
        if result.is_err() {
            tracing::warn!(ca_id = %ca_id, owner_id = %owner, "certificate creation failed; releasing CA lock");
            let _ = self.db.release_ca_lock(ca_id, &owner);
        }
        let cert = result?;
        tracing::info!(
            ca_id = %ca_id,
            cert_id = %cert.id,
            common_name = %cert.common_name,
            dns_count = cert.dns_list.len(),
            ip_count = cert.ip_list.len(),
            cert_bytes = cert.cert_pem.len(),
            key_bytes = cert.key_pem.len(),
            "created certificate"
        );
        Ok(cert)
    }

    #[tracing::instrument(skip(self, req), err, fields(span_id = %span_id(), ca_id = %ca_id))]
    pub fn import_cert(&self, ca_id: &str, req: ImportCertRequest) -> Result<Certificate> {
        self.import_cert_with(ca_id, None, req, None)
    }

    /// Imports a certificate under a caller-chosen id and, optionally, with
    /// the signing request it was originally issued from (the legacy 1.0.x
    /// migration has both). `None` mints an id / derives the CSR from the
    /// certificate.
    pub fn import_cert_with(
        &self,
        ca_id: &str,
        cert_id: Option<String>,
        req: ImportCertRequest,
        csr_pem: Option<&[u8]>,
    ) -> Result<Certificate> {
        tracing::info!(
            ca_id = %ca_id,
            cert_pem_bytes = req.cert_pem.len(),
            key_pem_bytes = req.key_pem.len(),
            "importing certificate"
        );
        validate_password(req.password.as_deref())?;
        let _ca = self.db.get_ca(ca_id)?;
        let cert_id = match cert_id {
            Some(id) => validate_entity_id(&id)?,
            None => short_id(),
        };
        if self.db.cert_exists(&cert_id)? {
            bail!("certificate id already exists: {cert_id}");
        }
        let owner = Uuid::new_v4().to_string();
        let work = self.openssl.workdir()?;
        let info = self
            .openssl
            .inspect_cert(work.path(), &req.cert_pem)
            .context("imported certificate PEM is not a valid certificate")?;
        self.db.acquire_ca_lock(ca_id, &owner, 120_000)?;
        let result = (|| -> Result<Certificate> {
            let ca_secrets = self.db.get_ca_secrets(ca_id)?;
            let password = req.password.clone().unwrap_or_else(random_password);
            let secrets = self
                .openssl
                .import_cert_files(
                    work.path(),
                    &ca_secrets,
                    &req.cert_pem,
                    &req.key_pem,
                    csr_pem,
                    &password,
                )
                .map_err(|err| {
                    let message = err.to_string();
                    if message.contains("imported certificate was not issued")
                        || message.contains("openssl verify failed")
                    {
                        anyhow::anyhow!(
                            "imported certificate was not issued by this CA or cannot be verified against it"
                        )
                    } else {
                        err
                    }
                })?;
            let derived = self.derive_subject(work.path(), &req.cert_pem, &info);
            let common_name = derived
                .common_name
                .clone()
                .unwrap_or_else(|| "Imported Certificate".to_string());
            self.ensure_unique_cert_common_name(ca_id, &common_name)?;
            let (mut dns_list, ip_list) = self
                .openssl
                .inspect_cert_sans(work.path(), &req.cert_pem)
                .unwrap_or_default();
            let text = self
                .openssl
                .inspect_cert_text(work.path(), &req.cert_pem)
                .unwrap_or_default();
            // Stored lists are ';'-joined, so drop entries that would corrupt
            // them (only possible with unusual imported certificates).
            dns_list.retain(|dns| !dns.contains(';') && !dns.chars().any(char::is_control));
            if is_valid_dns_name(&common_name) && !dns_list.contains(&common_name) {
                dns_list.insert(0, common_name.clone());
            }
            let (issue_time, valid_days) = validity_from_info(&info);
            let meta = CertMeta {
                id: cert_id.clone(),
                ca_id: ca_id.to_string(),
                common_name,
                country_code: derived.country_code,
                state: derived.state,
                city: derived.city,
                organization: derived.organization,
                organization_unit: derived.organization_unit,
                subject: derived.subject,
                issue_time,
                valid_days,
                dns_list,
                ip_list,
                key_profile: parse_public_key_profile(&text),
                digest_algorithm: parse_signature_digest(&text)
                    .unwrap_or_else(|| "imported".to_string()),
                revoked_at: None,
                revocation_reason: None,
            };
            // Importing does not sign anything, so the CA's index/serial
            // state is left untouched.
            self.db
                .insert_cert_with_state(&meta, &secrets, None, &owner)?;
            self.db.get_cert(ca_id, &cert_id)
        })();
        if result.is_err() {
            tracing::warn!(ca_id = %ca_id, owner_id = %owner, "certificate import failed; releasing CA lock");
            let _ = self.db.release_ca_lock(ca_id, &owner);
        }
        let cert = result?;
        tracing::info!(
            ca_id = %ca_id,
            cert_id = %cert.id,
            common_name = %cert.common_name,
            dns_count = cert.dns_list.len(),
            ip_count = cert.ip_list.len(),
            cert_bytes = cert.cert_pem.len(),
            key_bytes = cert.key_pem.len(),
            "imported certificate"
        );
        Ok(cert)
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id(), ca_id = %ca_id, cert_id = %cert_id, days))]
    pub fn renew_cert(&self, ca_id: &str, cert_id: &str, days: i64) -> Result<Certificate> {
        tracing::info!(ca_id = %ca_id, cert_id = %cert_id, days, "renewing certificate");
        validate_days(days)?;
        let cert = self.db.get_cert(ca_id, cert_id)?;
        if cert.revoked_at.is_some() {
            // Renewal reuses the key; a revoked (possibly compromised) key
            // must not be re-certified.
            bail!("certificate is revoked and cannot be renewed; issue a new certificate instead");
        }
        let ca = self.db.get_ca(ca_id)?;
        let requested_days = days;
        let days = self.clamp_to_ca_validity(&ca.cert_pem, days)?;
        let now = Utc::now().timestamp_millis();
        let current_expiry = cert.issue_time + cert.valid_days * 86_400_000;
        let proposed_expiry = now + days * 86_400_000;
        if proposed_expiry <= current_expiry {
            if days < requested_days {
                bail!(
                    "renewal would not extend the certificate expiry: the CA certificate expires first"
                );
            }
            let min_days = ((current_expiry - now).max(0) / 86_400_000) + 1;
            bail!(
                "renewal would not extend the certificate expiry; choose at least {min_days} days"
            );
        }
        // Imported certificates may carry a digest we don't sign with; fall
        // back to the historical default.
        let digest =
            normalize_digest(&cert.digest_algorithm).unwrap_or_else(|_| "sha512".to_string());
        let crl_url = self.issuing_crl_url(ca_id)?;
        // The renewal reproduces the current certificate: same subject and the
        // SANs it carries today (the stored metadata is the fallback when the
        // certificate has none).
        let work = self.openssl.workdir()?;
        let subject = self
            .openssl
            .inspect_cert_subject_rfc2253(work.path(), &cert.cert_pem)
            .ok()
            .and_then(|text| slash_subject(&subject_attributes(&text)));
        let (mut dns_list, mut ip_list) = self
            .openssl
            .inspect_cert_sans(work.path(), &cert.cert_pem)
            .unwrap_or_default();
        if dns_list.is_empty() && ip_list.is_empty() {
            dns_list = cert
                .dns_list
                .iter()
                .filter(|name| is_valid_dns_name(name))
                .cloned()
                .collect();
            ip_list = cert
                .ip_list
                .iter()
                .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
                .cloned()
                .collect();
        }
        drop(work);
        let owner = Uuid::new_v4().to_string();
        self.db.acquire_ca_lock(ca_id, &owner, 120_000)?;
        let result = (|| -> Result<Certificate> {
            // CA state is read under the lock so it cannot be stale.
            let ca_secrets = self.db.get_ca_secrets(ca_id)?;
            let cert_secrets = self.db.get_cert_secrets(ca_id, cert_id)?;
            let work = self.openssl.workdir()?;
            let (cert_pem, pkcs12, bundle, index_txt) = self.openssl.renew_cert_files(
                work.path(),
                &ca_secrets,
                &cert_secrets,
                &RenewalRequest {
                    subject: subject.as_deref(),
                    dns_list: &dns_list,
                    ip_list: &ip_list,
                },
                days,
                &digest,
                crl_url.as_deref(),
                self.crl.next_update_days,
            )?;
            let serial_txt = fs::read(work.path().join("serial.txt"))?;
            self.db.update_cert_with_state(
                ca_id,
                cert_id,
                &cert_pem,
                &pkcs12,
                &bundle,
                now,
                days,
                (&index_txt, &serial_txt),
                &owner,
            )?;
            self.db.get_cert(ca_id, &cert.id)
        })();
        if result.is_err() {
            tracing::warn!(ca_id = %ca_id, cert_id = %cert_id, owner_id = %owner, "certificate renewal failed; releasing CA lock");
            let _ = self.db.release_ca_lock(ca_id, &owner);
        }
        let cert = result?;
        tracing::info!(
            ca_id = %ca_id,
            cert_id = %cert_id,
            days,
            issue_time = cert.issue_time,
            valid_days = cert.valid_days,
            cert_bytes = cert.cert_pem.len(),
            "renewed certificate"
        );
        Ok(cert)
    }

    /// Re-issues a root CA's certificate with the same key and subject (and so
    /// the same SKI), a new serial and `days` of validity from now. Existing
    /// certificates keep verifying against the renewed CA certificate.
    #[tracing::instrument(skip(self), err, fields(span_id = %span_id(), ca_id = %ca_id, days))]
    pub fn renew_ca(&self, ca_id: &str, days: i64) -> Result<CertificateAuthority> {
        tracing::info!(ca_id = %ca_id, days, "renewing certificate authority");
        validate_days(days)?;
        let ca = self.db.get_ca(ca_id)?;
        // Imported CAs may carry a digest we don't sign with; fall back to the
        // historical default.
        let digest =
            normalize_digest(&ca.digest_algorithm).unwrap_or_else(|_| "sha512".to_string());
        let owner = Uuid::new_v4().to_string();
        self.db.acquire_ca_lock(ca_id, &owner, 120_000)?;
        let result = (|| -> Result<()> {
            // CA state is read under the lock so it cannot be stale.
            let mut ca_secrets = self.db.get_ca_secrets(ca_id)?;
            let work = self.openssl.workdir()?;
            let now = Utc::now().timestamp_millis();
            let current_pem = String::from_utf8_lossy(&ca_secrets.cert_pem).to_string();
            let info = self.openssl.inspect_cert(work.path(), &current_pem)?;
            let current_expiry = info_value(&info, "notAfter")
                .and_then(|v| parse_openssl_date(&v))
                .unwrap_or(ca.issue_time + ca.valid_days * 86_400_000);
            if now + days * 86_400_000 <= current_expiry {
                let min_days = ((current_expiry - now).max(0) / 86_400_000) + 1;
                bail!(
                    "renewal would not extend the CA certificate expiry; choose at least {min_days} days"
                );
            }
            let (cert_pem, pkcs12) =
                self.openssl
                    .renew_ca_files(work.path(), &ca_secrets, days, &digest)?;
            ca_secrets.cert_pem = cert_pem;
            ca_secrets.pkcs12 = pkcs12;
            // Same key, so the CRL could stay; it is re-signed anyway so its
            // issuer is the current certificate and the CRL number advances.
            let crl = if self.crl.enabled {
                let crl_work = self.openssl.workdir()?;
                Some(self.openssl.generate_crl(
                    crl_work.path(),
                    &ca_secrets,
                    self.crl.next_update_days,
                )?)
            } else {
                None
            };
            // Certificate bundles embed the CA certificate as `ca.pem`.
            let bundles = self
                .db
                .list_cert_secrets_for_ca(ca_id)?
                .into_iter()
                .map(|(cert_id, cert)| {
                    build_bundle(&cert, &ca_secrets.cert_pem).map(|bundle| (cert_id, bundle))
                })
                .collect::<Result<Vec<_>>>()?;
            self.db.renew_ca_with_state(
                ca_id,
                &ca_secrets.cert_pem,
                &ca_secrets.pkcs12,
                now,
                days,
                crl.as_ref()
                    .map(|c| (c.crl_der.as_slice(), c.crlnumber_txt.as_slice())),
                &bundles,
                &owner,
            )
        })();
        if result.is_err() {
            tracing::warn!(ca_id = %ca_id, owner_id = %owner, "certificate authority renewal failed; releasing CA lock");
            let _ = self.db.release_ca_lock(ca_id, &owner);
        }
        result?;
        let ca = self.get_ca(ca_id)?;
        self.prebuild_truststore(ca_id, ca.cert_pem.as_bytes());
        tracing::info!(
            ca_id = %ca_id,
            days,
            issue_time = ca.issue_time,
            valid_days = ca.valid_days,
            cert_bytes = ca.cert_pem.len(),
            "renewed certificate authority"
        );
        Ok(ca)
    }

    /// Whether a CA certificate is self-signed (a root), i.e. renewable with
    /// `renew_ca`.
    pub fn ca_is_self_signed(&self, cert_pem: &str) -> Result<bool> {
        let work = self.openssl.workdir()?;
        self.openssl
            .is_self_issued(work.path(), cert_pem.as_bytes())
    }

    #[tracing::instrument(skip(self, pem), err, fields(span_id = %span_id(), pem_bytes = pem.len()))]
    pub fn cert_purposes(&self, pem: &str) -> Result<Vec<(String, String)>> {
        tracing::info!("inspecting certificate purposes");
        let work = self.openssl.workdir()?;
        let purposes = self.openssl.inspect_cert_purposes(work.path(), pem)?;
        tracing::info!(
            purpose_count = purposes.len(),
            "inspected certificate purposes"
        );
        Ok(purposes)
    }

    #[tracing::instrument(skip(self, pem), err, fields(span_id = %span_id(), pem_bytes = pem.len()))]
    pub fn inspect_cert(&self, pem: &str) -> Result<InspectResponse> {
        tracing::info!("inspecting certificate");
        let work = self.openssl.workdir()?;
        let (dns_names, ip_addresses) = self
            .openssl
            .inspect_cert_sans(work.path(), pem)
            .unwrap_or_default();
        let info = self.openssl.inspect_cert(work.path(), pem)?;
        let purposes = self
            .openssl
            .inspect_cert_purposes(work.path(), pem)
            .unwrap_or_default();
        let raw_text = self.openssl.inspect_cert_text(work.path(), pem)?;
        tracing::info!(
            info_count = info.len(),
            dns_count = dns_names.len(),
            ip_count = ip_addresses.len(),
            purpose_count = purposes.len(),
            raw_text_bytes = raw_text.len(),
            "inspected certificate"
        );
        Ok(InspectResponse {
            info,
            dns_names,
            ip_addresses,
            purposes,
            raw_text,
        })
    }

    #[tracing::instrument(skip(self, kind), err, fields(span_id = %span_id(), ca_id = %ca_id, kind = download_kind_name(&kind)))]
    pub fn download_ca(&self, ca_id: &str, kind: Download) -> Result<(String, Vec<u8>)> {
        let kind_name = download_kind_name(&kind);
        tracing::info!(ca_id = %ca_id, kind = kind_name, "downloading certificate authority artifact");
        let secrets = self.db.get_ca_secrets(ca_id)?;
        // Files are named after the common name (falling back to the id), so
        // several downloads stay tellable apart; see `artifact_basename`.
        let name = artifact_basename(
            self.db.ca_common_name(ca_id).as_deref().unwrap_or_default(),
            ca_id,
        );
        let artifact = match kind {
            Download::CaCert => (format!("{name}.pem"), secrets.cert_pem),
            Download::CaKey => (format!("{name}.key"), secrets.key_pem),
            Download::CaPkcs12 => (format!("{name}.p12"), secrets.pkcs12),
            Download::CaPassword => (format!("{name}-p12-password.txt"), secrets.password),
            Download::CaTruststore => (
                format!("{name}-truststore.p12"),
                self.truststore(ca_id, &secrets.cert_pem)?,
            ),
            Download::CaTruststorePassword => (
                format!("{name}-truststore-password.txt"),
                TRUSTSTORE_PASSWORD.as_bytes().to_vec(),
            ),
            _ => bail!("invalid CA download kind"),
        };
        tracing::info!(
            ca_id = %ca_id,
            kind = kind_name,
            filename = %artifact.0,
            bytes = artifact.1.len(),
            "downloaded certificate authority artifact"
        );
        Ok(artifact)
    }

    /// The CA's stored truststore, built and stored on first use when it is
    /// missing (CAs from before truststores existed, restored backups, or a
    /// failed build at creation or renewal).
    fn truststore(&self, ca_id: &str, cert_pem: &[u8]) -> Result<Vec<u8>> {
        let stored = self.db.get_ca_truststore(ca_id)?;
        if !stored.is_empty() {
            return Ok(stored);
        }
        self.build_truststore(ca_id, cert_pem)
    }

    /// Builds the truststore for `cert_pem` and stores it.
    fn build_truststore(&self, ca_id: &str, cert_pem: &[u8]) -> Result<Vec<u8>> {
        let work = self.openssl.workdir()?;
        let truststore = self.openssl.truststore_pkcs12(
            work.path(),
            cert_pem,
            &format!("minica-{ca_id}"),
            TRUSTSTORE_PASSWORD,
        )?;
        let stored = self.db.set_ca_truststore(ca_id, cert_pem, &truststore)?;
        tracing::info!(ca_id = %ca_id, bytes = truststore.len(), stored, "built CA truststore");
        Ok(truststore)
    }

    /// Builds the truststore right after the CA certificate is created or
    /// changed. A failure only logs: the download path retries.
    fn prebuild_truststore(&self, ca_id: &str, cert_pem: &[u8]) {
        if let Err(err) = self.build_truststore(ca_id, cert_pem) {
            tracing::warn!(ca_id = %ca_id, error = %err, "CA truststore build failed; will retry on download");
        }
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id(), ca_id = %ca_id))]
    pub fn crl_der(&self, ca_id: &str) -> Result<Vec<u8>> {
        if !self.crl.enabled {
            bail!("CRL support is disabled");
        }
        let bytes = self.db.get_ca_crl(ca_id)?;
        if bytes.is_empty() {
            bail!("CRL is not available for CA: {ca_id}");
        }
        tracing::info!(ca_id = %ca_id, bytes = bytes.len(), "read certificate revocation list");
        Ok(bytes)
    }

    #[tracing::instrument(
        skip(self, kind),
        err,
        fields(span_id = %span_id(), ca_id = %ca_id, cert_id = %cert_id, kind = download_kind_name(&kind))
    )]
    pub fn download_cert(
        &self,
        ca_id: &str,
        cert_id: &str,
        kind: Download,
    ) -> Result<(String, Vec<u8>)> {
        let kind_name = download_kind_name(&kind);
        tracing::info!(
            ca_id = %ca_id,
            cert_id = %cert_id,
            kind = kind_name,
            "downloading certificate artifact"
        );
        let secrets = self.db.get_cert_secrets(ca_id, cert_id)?;
        let name = artifact_basename(&self.db.get_cert(ca_id, cert_id)?.common_name, cert_id);
        let artifact = match kind {
            Download::CertBundle => (format!("{name}.zip"), secrets.bundle_zip),
            Download::CertPem => (format!("{name}.pem"), secrets.cert_pem),
            Download::CertCsr => (format!("{name}.csr"), secrets.csr_pem),
            Download::CertKey => (format!("{name}.key"), secrets.key_pem),
            Download::CertPkcs12 => (format!("{name}.p12"), secrets.pkcs12),
            Download::CertPassword => (format!("{name}-p12-password.txt"), secrets.password),
            _ => bail!("invalid certificate download kind"),
        };
        tracing::info!(
            ca_id = %ca_id,
            cert_id = %cert_id,
            kind = kind_name,
            filename = %artifact.0,
            bytes = artifact.1.len(),
            "downloaded certificate artifact"
        );
        Ok(artifact)
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id()))]
    pub fn export_backup_yaml(&self) -> Result<String> {
        tracing::info!("exporting backup YAML");
        // One consistent snapshot (single lock + read transaction).
        let snapshot = self.db.backup_snapshot()?;
        let users: Vec<BackupUser> = snapshot.users.into_iter().map(BackupUser::from).collect();
        let user_count = users.len();
        let templates: Vec<BackupTemplate> = snapshot
            .templates
            .into_iter()
            .map(BackupTemplate::from)
            .collect();
        let template_count = templates.len();
        let mut cas_out = Vec::new();
        for (ca, certs) in snapshot.cas {
            let mut certs_out = Vec::new();
            for cert in certs {
                certs_out.push(BackupCert {
                    meta: BackupCertMeta {
                        id: cert.meta.id,
                        ca_id: cert.meta.ca_id,
                        common_name: cert.meta.common_name,
                        country_code: cert.meta.country_code,
                        state: cert.meta.state,
                        city: cert.meta.city,
                        organization: cert.meta.organization,
                        organization_unit: cert.meta.organization_unit,
                        subject: cert.meta.subject,
                        issue_time: cert.meta.issue_time,
                        valid_days: cert.meta.valid_days,
                        dns_list: cert.meta.dns_list,
                        ip_list: cert.meta.ip_list,
                        key_profile: cert.meta.key_profile,
                        digest_algorithm: cert.meta.digest_algorithm,
                        revoked_at: cert.revoked_at,
                        revocation_reason: cert.revocation_reason,
                        deleted: cert.deleted,
                        created_at: cert.created_at,
                        updated_at: cert.updated_at,
                    },
                    secrets: BackupCertSecrets::from(cert.secrets),
                });
            }
            cas_out.push(BackupCa {
                meta: BackupCaMeta {
                    id: ca.meta.id,
                    common_name: ca.meta.common_name,
                    country_code: ca.meta.country_code,
                    state: ca.meta.state,
                    city: ca.meta.city,
                    organization: ca.meta.organization,
                    organization_unit: ca.meta.organization_unit,
                    subject: ca.meta.subject,
                    issue_time: ca.meta.issue_time,
                    valid_days: ca.meta.valid_days,
                    key_profile: ca.meta.key_profile,
                    digest_algorithm: ca.meta.digest_algorithm,
                    deleted: ca.deleted,
                    created_at: ca.created_at,
                    updated_at: ca.updated_at,
                },
                secrets: BackupCaSecrets::from(ca.secrets),
                certificates: certs_out,
            });
        }
        let ca_count = cas_out.len();
        let cert_count: usize = cas_out.iter().map(|ca| ca.certificates.len()).sum();
        let yaml = serde_yaml::to_string(&BackupFile {
            format_version: BACKUP_FORMAT_VERSION,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            schema_version: SCHEMA_VERSION,
            app: "minica-rust".to_string(),
            exported_at: Utc::now().timestamp_millis(),
            warning: "This backup includes private keys and passwords.".to_string(),
            users,
            templates,
            certificate_authorities: cas_out,
        })
        .map_err(anyhow::Error::from)?;
        tracing::info!(
            ca_count,
            cert_count,
            user_count,
            template_count,
            bytes = yaml.len(),
            "exported backup YAML"
        );
        Ok(yaml)
    }

    #[tracing::instrument(skip(self, yaml), fields(span_id = %span_id(), yaml_bytes = yaml.len()))]
    pub fn import_backup_yaml(&self, yaml: &str) -> Result<()> {
        tracing::warn!(bytes = yaml.len(), "importing backup YAML");
        let outcome = (|| -> Result<(usize, usize, usize)> {
            let backup: BackupFile =
                serde_yaml::from_str(yaml).context("failed to parse backup YAML")?;
            if backup.format_version != BACKUP_FORMAT_VERSION {
                bail!(
                    "unsupported backup format version {}",
                    backup.format_version
                );
            }
            let user_count = backup.users.len();
            let ca_count = backup.certificate_authorities.len();
            let cert_count: usize = backup
                .certificate_authorities
                .iter()
                .map(|ca| ca.certificates.len())
                .sum();
            tracing::info!(
                format_version = backup.format_version,
                schema_version = backup.schema_version,
                app_version = %backup.app_version,
                user_count,
                ca_count,
                cert_count,
                "parsed backup YAML"
            );
            // Validate and decode everything up front, then restore in a
            // single transaction (which also re-checks the DB is empty).
            let snapshot = backup_to_snapshot(backup)?;
            self.db.restore_backup(&snapshot)?;
            // Backups from older versions may carry fabricated import metadata.
            if let Err(err) = self.repair_stale_metadata() {
                tracing::warn!(error = %err, "metadata repair after restore failed");
            }
            Ok((user_count, ca_count, cert_count))
        })();
        match outcome {
            Ok((user_count, ca_count, cert_count)) => {
                tracing::warn!(user_count, ca_count, cert_count, "imported backup YAML");
                Ok(())
            }
            Err(err) => {
                tracing::error!(error = %err, "failed to import backup YAML");
                Err(err)
            }
        }
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id()))]
    pub fn nuke_all(&self) -> Result<()> {
        tracing::warn!("nuking all database entities by admin request");
        self.db.nuke_all()?;
        tracing::warn!("nuked all database entities by admin request");
        Ok(())
    }
}

impl AppService {
    #[tracing::instrument(skip(self), err, fields(span_id = %span_id(), ca_id = %id))]
    pub fn restore_ca(&self, id: &str) -> Result<()> {
        tracing::info!(ca_id = %id, "restoring certificate authority");
        self.db.restore_ca(id)?;
        tracing::info!(ca_id = %id, "restored certificate authority");
        Ok(())
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id(), ca_id = %ca_id, cert_id = %cert_id))]
    pub fn restore_cert(&self, ca_id: &str, cert_id: &str) -> Result<()> {
        tracing::info!(ca_id = %ca_id, cert_id = %cert_id, "restoring certificate");
        self.db.restore_cert(ca_id, cert_id)?;
        tracing::info!(ca_id = %ca_id, cert_id = %cert_id, "restored certificate");
        Ok(())
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id()))]
    pub fn list_deleted_cas(&self) -> Result<Vec<CertificateAuthority>> {
        let cas = self.db.list_deleted_cas()?;
        tracing::info!(count = cas.len(), "listed deleted certificate authorities");
        Ok(cas)
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id()))]
    pub fn list_deleted_certs(&self) -> Result<Vec<Certificate>> {
        let certs = self.db.list_deleted_certs()?;
        tracing::info!(count = certs.len(), "listed deleted certificates");
        Ok(certs)
    }

    /// Common name of any CA (including deleted), for display in the admin UI.
    pub fn ca_display_name(&self, id: &str) -> String {
        self.db
            .ca_common_name(id)
            .unwrap_or_else(|| "(unknown CA)".to_string())
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id()))]
    pub fn list_users(&self) -> Result<Vec<UserView>> {
        let users = self
            .db
            .list_users()?
            .into_iter()
            .map(|u| UserView {
                id: u.id,
                username: u.username,
                role: u.role,
                created_at: u.created_at,
            })
            .collect::<Vec<_>>();
        tracing::info!(count = users.len(), "listed users");
        Ok(users)
    }

    #[tracing::instrument(skip(self, req), err, fields(span_id = %span_id(), username = %req.username, role = %req.role))]
    pub fn create_user(&self, req: CreateUserRequest) -> Result<()> {
        let username = req.username.trim();
        if username.is_empty() {
            bail!("username must not be empty");
        }
        if req.password.len() < 6 {
            bail!("password must be at least 6 characters");
        }
        let role = Role::parse(&req.role).context("role must be 'admin' or 'viewer'")?;
        tracing::info!(username = %username, role = %role.as_str(), "creating user");
        if self
            .reserved_usernames
            .iter()
            .any(|reserved| reserved == username)
        {
            bail!("username is reserved by a bootstrap account: {username}");
        }
        if self.db.find_user(username)?.is_some() {
            bail!("username already exists: {username}");
        }
        let hash =
            bcrypt::hash(&req.password, bcrypt::DEFAULT_COST).context("failed to hash password")?;
        let id = Uuid::new_v4().to_string();
        self.db.insert_user(&id, username, &hash, role.as_str())?;
        tracing::info!(user_id = %id, username = %username, role = %role.as_str(), "created user");
        Ok(())
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id(), user_id = %id))]
    pub fn delete_user(&self, id: &str) -> Result<()> {
        tracing::info!(user_id = %id, "deleting user");
        self.db.delete_user(id)?;
        tracing::info!(user_id = %id, "deleted user");
        Ok(())
    }

    pub fn list_templates(&self) -> Result<Vec<Template>> {
        self.db.list_templates()
    }

    pub fn get_template(&self, id: &str) -> Result<Template> {
        self.db
            .get_template(id)?
            .ok_or_else(|| anyhow::anyhow!("template not found: {id}"))
    }

    /// The templates offered on the creation form of `kind`: the default one
    /// (applied automatically) and every applicable template, by name.
    pub fn templates_for(&self, kind: TemplateScope) -> Result<(Option<Template>, Vec<Template>)> {
        let presets: Vec<Template> = self
            .db
            .list_templates()?
            .into_iter()
            .filter(|template| template.scope().covers(kind))
            .collect();
        let default = presets.iter().find(|template| template.is_default).cloned();
        Ok((default, presets))
    }

    #[tracing::instrument(skip(self, req), err, fields(span_id = %span_id(), name = %req.name))]
    pub fn create_template(&self, req: TemplateRequest) -> Result<Template> {
        let now = Utc::now().timestamp_millis();
        let template = self.validate_template(req, Uuid::new_v4().to_string(), now, now)?;
        self.db.save_template(&template, true)?;
        tracing::info!(template_id = %template.id, name = %template.name, "created template");
        Ok(template)
    }

    #[tracing::instrument(skip(self, req), err, fields(span_id = %span_id(), template_id = %id))]
    pub fn update_template(&self, id: &str, req: TemplateRequest) -> Result<Template> {
        let existing = self.get_template(id)?;
        let now = Utc::now().timestamp_millis();
        let template = self.validate_template(req, existing.id, existing.created_at, now)?;
        self.db.save_template(&template, false)?;
        tracing::info!(template_id = %template.id, name = %template.name, "updated template");
        Ok(template)
    }

    #[tracing::instrument(skip(self), err, fields(span_id = %span_id(), template_id = %id))]
    pub fn delete_template(&self, id: &str) -> Result<()> {
        self.db.delete_template(id)
    }

    fn validate_template(
        &self,
        req: TemplateRequest,
        id: String,
        created_at: i64,
        updated_at: i64,
    ) -> Result<Template> {
        let name = req.name.trim().to_string();
        if name.is_empty() {
            bail!("template name must not be empty");
        }
        if name.chars().count() > 100 || name.chars().any(char::is_control) {
            bail!("template name must be at most 100 characters without control characters");
        }
        if self.db.template_name_taken(&name, Some(&id))? {
            bail!("template name already exists: {name}");
        }
        let scope = match req.scope.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            None => TemplateScope::Both,
            Some(scope) => TemplateScope::parse(scope)
                .ok_or_else(|| anyhow::anyhow!("scope must be 'both', 'ca' or 'certificate'"))?,
        };
        let values = validate_template_values(&req.values)?;
        Ok(Template {
            id,
            name,
            scope: scope.as_str().to_string(),
            is_default: req.is_default,
            values,
            created_at,
            updated_at,
        })
    }

    /// CA common names are unique among CAs (not checked against cert CNs).
    fn ensure_unique_ca_common_name(&self, common_name: &str) -> Result<()> {
        if self.db.ca_common_name_exists(common_name)? {
            bail!("common name already exists: {}", common_name.trim());
        }
        Ok(())
    }

    /// Cert common names are unique within their CA; the same CN may be reused
    /// under a different CA.
    fn ensure_unique_cert_common_name(&self, ca_id: &str, common_name: &str) -> Result<()> {
        if self.db.cert_common_name_exists(ca_id, common_name)? {
            bail!("common name already exists: {}", common_name.trim());
        }
        Ok(())
    }

    /// Returns the id of the non-deleted certificate under `ca_id` whose common
    /// name matches (case- and whitespace-insensitively), if any.
    pub fn find_cert_id_by_cn(&self, ca_id: &str, common_name: &str) -> Result<Option<String>> {
        self.db.find_cert_id_by_cn(ca_id, common_name)
    }

    pub fn crl_url(&self, ca_id: &str) -> Option<String> {
        if !self.crl.enabled {
            return None;
        }
        self.public_base_url
            .as_ref()
            .map(|base| format!("{}/crl/{ca_id}", base.trim_end_matches('/')))
    }

    /// Long-form public download URL of the CA certificate; serves the same
    /// PEM as [`Self::public_ca_cert_url`].
    pub fn public_ca_cert_download_url(&self, ca_id: &str) -> Option<String> {
        self.public_base_url
            .as_ref()
            .map(|base| format!("{}/download/ca/{ca_id}/cert", base.trim_end_matches('/')))
    }

    /// Public (unauthenticated) download URL of the CA certificate.
    pub fn public_ca_cert_url(&self, ca_id: &str) -> Option<String> {
        self.public_base_url
            .as_ref()
            .map(|base| format!("{}/{ca_id}/download", base.trim_end_matches('/')))
    }

    /// The CRL distribution point to embed in a newly signed certificate,
    /// validated because it is written into the openssl config file.
    fn issuing_crl_url(&self, ca_id: &str) -> Result<Option<String>> {
        let Some(url) = self.crl_url(ca_id) else {
            return Ok(None);
        };
        validate_crl_url(&url)?;
        Ok(Some(url))
    }

    /// Generates the CA's first (empty) CRL before the CA row is inserted, so
    /// a CRL failure cannot leave behind a CA that reported an error.
    fn attach_initial_crl(&self, secrets: &mut CaSecrets) -> Result<()> {
        if !self.crl.enabled {
            return Ok(());
        }
        let work = self.openssl.workdir()?;
        let refresh = self
            .openssl
            .generate_crl(work.path(), secrets, self.crl.next_update_days)?;
        secrets.crl_der = refresh.crl_der;
        secrets.index_txt = refresh.index_txt;
        secrets.crlnumber_txt = refresh.crlnumber_txt;
        secrets.crl_updated_at = Utc::now().timestamp_millis();
        Ok(())
    }

    /// Caps a leaf validity so it never outlives the issuing CA certificate.
    /// Returns the effective number of days (recorded as the cert's
    /// `valid_days`).
    fn clamp_to_ca_validity(&self, ca_cert_pem: &str, days: i64) -> Result<i64> {
        let work = self.openssl.workdir()?;
        let info = self.openssl.inspect_cert(work.path(), ca_cert_pem)?;
        let Some(not_after) = info_value(&info, "notAfter").and_then(|v| parse_openssl_date(&v))
        else {
            tracing::warn!("could not read CA notAfter; leaf validity not clamped");
            return Ok(days);
        };
        let max_days = (not_after - Utc::now().timestamp_millis()) / 86_400_000;
        if max_days < 1 {
            bail!("the CA certificate expires within a day; it can no longer issue certificates");
        }
        if days > max_days {
            tracing::warn!(
                requested_days = days,
                effective_days = max_days,
                "clamping certificate validity to the CA certificate's expiry"
            );
            return Ok(max_days);
        }
        Ok(days)
    }

    /// The subject of `pem` as the certificate states it: the full DN in
    /// `/C=..../CN=...` form plus the individual attributes MiniCA tracks
    /// (empty when the certificate does not carry them — nothing is invented).
    /// RFC 2253 output is used when available, else openssl's default
    /// rendering.
    fn derive_subject(
        &self,
        dir: &std::path::Path,
        pem: &str,
        info: &[(String, String)],
    ) -> DerivedSubject {
        let text = self
            .openssl
            .inspect_cert_subject_rfc2253(dir, pem)
            .ok()
            .filter(|subject| !subject.is_empty())
            .or_else(|| info_value(info, "subject"))
            .unwrap_or_default();
        DerivedSubject::from_rfc2253(&text)
    }

    /// One-time re-derivation of stored metadata from the certificates
    /// themselves, for rows written by versions that fabricated it: imported
    /// CAs used to be recorded as issued "now" for 3650 days, and imported CAs
    /// and certificates without a country or organization were given `XX` /
    /// `Imported`. Rows are checked once (`meta_version`), so this costs one
    /// openssl call per unchecked CA (and per marked certificate) after an
    /// upgrade or restore, then nothing. Returns the number of CAs and
    /// certificates whose metadata changed.
    pub fn repair_stale_metadata(&self) -> Result<(usize, usize)> {
        let mut repaired_cas = 0;
        for (mut meta, cert_pem) in self.db.list_cas_for_repair()? {
            let pem = String::from_utf8_lossy(&cert_pem).to_string();
            let work = self.openssl.workdir()?;
            let info = match self.openssl.inspect_cert(work.path(), &pem) {
                Ok(info) => info,
                Err(err) => {
                    tracing::warn!(ca_id = %meta.id, error = %err, "could not inspect CA certificate; metadata left as is");
                    self.db.mark_ca_meta_checked(&meta.id)?;
                    continue;
                }
            };
            let before = meta.clone();
            // Natively created CAs record issue_time a moment after openssl
            // set notBefore; only a real discrepancy (an import recorded as
            // issued at import time, or a made-up validity) is corrected.
            let (issue_time, valid_days) = validity_from_info(&info);
            if (issue_time - meta.issue_time).abs() > 86_400_000 || valid_days != meta.valid_days {
                meta.issue_time = issue_time;
                meta.valid_days = valid_days;
            }
            if has_fabricated_subject(&meta.country_code, &meta.organization) {
                let derived = self.derive_subject(work.path(), &pem, &info);
                apply_derived_subject(&mut meta, derived);
            }
            let changed = meta.subject != before.subject
                || meta.issue_time != before.issue_time
                || meta.valid_days != before.valid_days
                || meta.country_code != before.country_code
                || meta.organization != before.organization;
            if changed {
                tracing::info!(
                    ca_id = %meta.id,
                    old_subject = %before.subject,
                    new_subject = %meta.subject,
                    old_issue_time = before.issue_time,
                    new_issue_time = meta.issue_time,
                    old_valid_days = before.valid_days,
                    new_valid_days = meta.valid_days,
                    "repaired certificate authority metadata from its certificate"
                );
                repaired_cas += 1;
            }
            self.db.update_ca_meta_repaired(&meta)?;
        }
        let mut repaired_certs = 0;
        for (mut meta, cert_pem) in self.db.list_certs_for_repair()? {
            if !has_fabricated_subject(&meta.country_code, &meta.organization) {
                self.db.mark_cert_meta_checked(&meta.id)?;
                continue;
            }
            let pem = String::from_utf8_lossy(&cert_pem).to_string();
            let work = self.openssl.workdir()?;
            let info = self
                .openssl
                .inspect_cert(work.path(), &pem)
                .unwrap_or_default();
            let derived = self.derive_subject(work.path(), &pem, &info);
            let before_subject = meta.subject.clone();
            if !derived.subject.is_empty() {
                meta.country_code = derived.country_code;
                meta.state = derived.state;
                meta.city = derived.city;
                meta.organization = derived.organization;
                meta.organization_unit = derived.organization_unit;
                meta.subject = derived.subject;
            }
            if meta.subject != before_subject {
                tracing::info!(
                    ca_id = %meta.ca_id,
                    cert_id = %meta.id,
                    old_subject = %before_subject,
                    new_subject = %meta.subject,
                    "repaired certificate subject from its certificate"
                );
                repaired_certs += 1;
            }
            self.db.update_cert_meta_repaired(&meta)?;
        }
        if repaired_cas + repaired_certs > 0 {
            tracing::warn!(repaired_cas, repaired_certs, "repaired stale metadata");
        }
        Ok((repaired_cas, repaired_certs))
    }

    fn with_ca_crl_url(&self, mut ca: CertificateAuthority) -> CertificateAuthority {
        ca.crl_url = self.crl_url(&ca.id);
        ca
    }

    fn repair_ca_metadata_if_needed(
        &self,
        mut ca: CertificateAuthority,
    ) -> Result<CertificateAuthority> {
        if is_supported_key_profile(&ca.key_profile)
            && !ca.digest_algorithm.eq_ignore_ascii_case("imported")
        {
            return Ok(ca);
        }
        let work = self.openssl.workdir()?;
        let text = self
            .openssl
            .inspect_cert_text(work.path(), &ca.cert_pem)
            .unwrap_or_default();
        let key_profile = parse_public_key_profile(&text);
        let digest_algorithm =
            parse_signature_digest(&text).unwrap_or_else(|| ca.digest_algorithm.clone());
        if key_profile != ca.key_profile || digest_algorithm != ca.digest_algorithm {
            tracing::info!(
                ca_id = %ca.id,
                old_key_profile = %ca.key_profile,
                new_key_profile = %key_profile,
                old_digest_algorithm = %ca.digest_algorithm,
                new_digest_algorithm = %digest_algorithm,
                "repairing imported certificate authority metadata"
            );
            self.db
                .update_ca_metadata(&ca.id, &key_profile, &digest_algorithm)?;
            ca.key_profile = key_profile;
            ca.digest_algorithm = digest_algorithm;
        }
        Ok(ca)
    }
}

impl From<CaSecrets> for BackupCaSecrets {
    fn from(value: CaSecrets) -> Self {
        Self {
            cert_pem_b64: b64(&value.cert_pem),
            key_pem_b64: b64(&value.key_pem),
            pkcs12_b64: b64(&value.pkcs12),
            password_b64: b64(&value.password),
            index_txt_b64: b64(&value.index_txt),
            serial_txt_b64: b64(&value.serial_txt),
            crl_der_b64: b64(&value.crl_der),
            crl_updated_at: value.crl_updated_at,
            crlnumber_txt_b64: b64(&value.crlnumber_txt),
        }
    }
}

impl From<UserRecord> for BackupUser {
    fn from(value: UserRecord) -> Self {
        Self {
            id: value.id,
            username: value.username,
            password_hash: value.password_hash,
            role: value.role,
            created_at: value.created_at,
        }
    }
}

impl TryFrom<BackupCaSecrets> for CaSecrets {
    type Error = anyhow::Error;

    fn try_from(value: BackupCaSecrets) -> Result<Self> {
        Ok(Self {
            cert_pem: b64d(&value.cert_pem_b64)?,
            key_pem: b64d(&value.key_pem_b64)?,
            pkcs12: b64d(&value.pkcs12_b64)?,
            password: b64d(&value.password_b64)?,
            index_txt: b64d(&value.index_txt_b64)?,
            serial_txt: b64d(&value.serial_txt_b64)?,
            crl_der: if value.crl_der_b64.is_empty() {
                Vec::new()
            } else {
                b64d(&value.crl_der_b64)?
            },
            crl_updated_at: value.crl_updated_at,
            crlnumber_txt: b64d(&value.crlnumber_txt_b64)?,
        })
    }
}

impl From<CertSecrets> for BackupCertSecrets {
    fn from(value: CertSecrets) -> Self {
        Self {
            cert_pem_b64: b64(&value.cert_pem),
            key_pem_b64: b64(&value.key_pem),
            csr_pem_b64: b64(&value.csr_pem),
            pkcs12_b64: b64(&value.pkcs12),
            password_b64: b64(&value.password),
            bundle_zip_b64: b64(&value.bundle_zip),
        }
    }
}

impl TryFrom<BackupCertSecrets> for CertSecrets {
    type Error = anyhow::Error;

    fn try_from(value: BackupCertSecrets) -> Result<Self> {
        Ok(Self {
            cert_pem: b64d(&value.cert_pem_b64)?,
            key_pem: b64d(&value.key_pem_b64)?,
            csr_pem: b64d(&value.csr_pem_b64)?,
            pkcs12: b64d(&value.pkcs12_b64)?,
            password: b64d(&value.password_b64)?,
            bundle_zip: b64d(&value.bundle_zip_b64)?,
        })
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64d(input: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(Into::into)
}

fn short_id() -> String {
    rand::rng()
        .sample_iter(Alphanumeric)
        .take(12)
        .map(char::from)
        .collect()
}

fn span_id() -> String {
    Uuid::new_v4().to_string()
}

fn normalize_revocation_reason(reason: &str) -> Result<String> {
    let normalized = reason.trim();
    let normalized = if normalized.is_empty() {
        "unspecified"
    } else {
        normalized
    };
    let allowed = [
        "unspecified",
        "keyCompromise",
        "CACompromise",
        "affiliationChanged",
        "superseded",
        "cessationOfOperation",
        "certificateHold",
        "removeFromCRL",
        "privilegeWithdrawn",
        "AACompromise",
    ];
    if allowed.iter().any(|value| *value == normalized) {
        Ok(normalized.to_string())
    } else {
        bail!("unsupported revocation reason: {normalized}");
    }
}

fn download_kind_name(kind: &Download) -> &'static str {
    match kind {
        Download::CaCert => "ca_cert",
        Download::CaKey => "ca_key",
        Download::CaPkcs12 => "ca_pkcs12",
        Download::CaPassword => "ca_password",
        Download::CaTruststore => "ca_truststore",
        Download::CaTruststorePassword => "ca_truststore_password",
        Download::CertBundle => "cert_bundle",
        Download::CertPem => "cert_pem",
        Download::CertCsr => "cert_csr",
        Download::CertKey => "cert_key",
        Download::CertPkcs12 => "cert_pkcs12",
        Download::CertPassword => "cert_password",
    }
}

fn validate_days(days: i64) -> Result<()> {
    if !(1..=7350).contains(&days) {
        bail!("valid days must be in 1..7350");
    }
    Ok(())
}

fn validate_key_length(key_length: i64) -> Result<()> {
    if ![2048, 4096, 8192].contains(&key_length) {
        bail!("key length must be 2048, 4096, or 8192");
    }
    Ok(())
}

fn key_spec(profile: &str) -> Result<KeySpec> {
    let (algorithm, attribute) = parse_key_profile(profile)?;
    let attributes = match algorithm.as_str() {
        "rsa" => json!({ "bits": attribute.parse::<i64>()? }),
        "ecdsa" => json!({ "curve": attribute }),
        _ => unreachable!("parse_key_profile only returns supported algorithms"),
    };
    Ok(KeySpec {
        profile: format!("{algorithm}:{attribute}"),
        algorithm,
        attributes,
    })
}

fn validate_curve(curve: &str) -> Result<()> {
    if !["prime256v1", "secp384r1", "secp521r1"].contains(&curve) {
        bail!("ECDSA curve must be prime256v1, secp384r1, or secp521r1");
    }
    Ok(())
}

fn parse_key_profile(profile: &str) -> Result<(String, String)> {
    let profile = profile.trim().to_ascii_lowercase();
    let (algorithm, attribute) = profile.split_once(':').ok_or_else(|| {
        anyhow::anyhow!("key profile must look like rsa:4096 or ecdsa:prime256v1")
    })?;
    match algorithm {
        "rsa" => {
            let bits = attribute
                .parse::<i64>()
                .with_context(|| format!("invalid RSA key profile: {profile}"))?;
            validate_key_length(bits)?;
            Ok(("rsa".to_string(), bits.to_string()))
        }
        "ecdsa" => {
            validate_curve(attribute)?;
            Ok(("ecdsa".to_string(), attribute.to_string()))
        }
        _ => bail!("key profile algorithm must be rsa or ecdsa"),
    }
}

fn parse_public_key_bits(text: &str) -> Option<i64> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("Public-Key:") {
            let value = value.trim().strip_prefix('(')?;
            let bits = value.split_whitespace().next()?;
            if let Ok(bits) = bits.parse::<i64>() {
                return Some(bits);
            }
        }
    }
    None
}

fn parse_public_key_algorithm(text: &str) -> String {
    for line in text.lines() {
        if let Some(value) = line.trim().strip_prefix("Public Key Algorithm:") {
            let value = value.trim().to_ascii_lowercase();
            if value.contains("id-ecpublickey") || value.contains("ec public") {
                return "ecdsa".to_string();
            }
            if value.contains("rsa") {
                return "rsa".to_string();
            }
        }
    }
    "unknown".to_string()
}

fn parse_public_key_profile(text: &str) -> String {
    match parse_public_key_algorithm(text).as_str() {
        "rsa" => parse_public_key_bits(text)
            .map(|bits| format!("rsa:{bits}"))
            .unwrap_or_else(|| "rsa:4096".to_string()),
        "ecdsa" => parse_ec_curve(text)
            .map(|curve| format!("ecdsa:{curve}"))
            .unwrap_or_else(|| "ecdsa:prime256v1".to_string()),
        _ => "rsa:4096".to_string(),
    }
}

fn is_supported_key_profile(profile: &str) -> bool {
    parse_key_profile(profile).is_ok()
}

fn parse_ec_curve(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        for prefix in ["ASN1 OID:", "NIST CURVE:"] {
            if let Some(value) = line.strip_prefix(prefix) {
                let curve = value.trim();
                if !curve.is_empty() {
                    return Some(curve.to_string());
                }
            }
        }
    }
    None
}

fn parse_signature_digest(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(value) = line.trim().strip_prefix("Signature Algorithm:") {
            let value = value.trim();
            let lower = value.to_ascii_lowercase();
            for digest in ["sha512", "sha384", "sha256", "sha224", "sha1"] {
                if lower.starts_with(digest) {
                    return Some(digest.to_string());
                }
            }
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Subject data read from a certificate (see `AppService::derive_subject`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DerivedSubject {
    /// The whole DN in `openssl -subj` form, DER order, e.g. `/C=DE/CN=x`.
    pub subject: String,
    pub common_name: Option<String>,
    pub country_code: String,
    pub state: String,
    pub city: String,
    pub organization: String,
    pub organization_unit: String,
}

impl DerivedSubject {
    /// Parses an RFC 2253 rendering (`C=DE,O=Acme\, Inc,CN=x`, DER order)
    /// or openssl's default one (`C = DE, O = Acme, CN = x`).
    pub fn from_rfc2253(text: &str) -> Self {
        let attributes = subject_attributes(text);
        let first = |key: &str| {
            attributes
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
        };
        Self {
            subject: slash_subject(&attributes).unwrap_or_default(),
            common_name: first("CN").filter(|value| !value.trim().is_empty()),
            country_code: first("C").unwrap_or_default(),
            state: first("ST").unwrap_or_default(),
            city: first("L").unwrap_or_default(),
            organization: first("O").unwrap_or_default(),
            organization_unit: first("OU").unwrap_or_default(),
        }
    }
}

/// All `key=value` attributes of a distinguished name in the order written,
/// with RFC 2253 escapes decoded. Multi-valued RDNs (`OU=a+OU=b`) become
/// consecutive attributes.
fn subject_attributes(subject: &str) -> Vec<(String, String)> {
    split_unescaped(subject, &[',', '+'])
        .into_iter()
        .filter_map(|part| {
            let mut pieces = split_unescaped(&part, &['=']).into_iter();
            let key = pieces.next()?.trim().to_string();
            if key.is_empty() {
                return None;
            }
            let value = unescape_dn_value(pieces.collect::<Vec<_>>().join("=").trim());
            Some((key, value))
        })
        .collect()
}

/// Renders attributes as an `openssl -subj` string (`/C=DE/O=Acme/CN=x`),
/// escaping the separators inside values. `None` when there is nothing to
/// render.
fn slash_subject(attributes: &[(String, String)]) -> Option<String> {
    if attributes.is_empty() {
        return None;
    }
    Some(
        attributes
            .iter()
            .map(|(key, value)| format!("/{key}={}", escape_subject(value)))
            .collect(),
    )
}

/// The placeholders older versions stored when an imported certificate had
/// no country or organization.
fn has_fabricated_subject(country_code: &str, organization: &str) -> bool {
    country_code == "XX" || organization == "Imported"
}

fn apply_derived_subject(meta: &mut CaMeta, derived: DerivedSubject) {
    if derived.subject.is_empty() {
        return;
    }
    meta.country_code = derived.country_code;
    meta.state = derived.state;
    meta.city = derived.city;
    meta.organization = derived.organization;
    meta.organization_unit = derived.organization_unit;
    meta.subject = derived.subject;
}

/// `(issue_time, valid_days)` from a certificate's `notBefore`/`notAfter`;
/// now / one day when the dates cannot be read.
fn validity_from_info(info: &[(String, String)]) -> (i64, i64) {
    let not_before = info_value(info, "notBefore")
        .and_then(|value| parse_openssl_date(&value))
        .unwrap_or_else(|| Utc::now().timestamp_millis());
    let not_after = info_value(info, "notAfter")
        .and_then(|value| parse_openssl_date(&value))
        .unwrap_or(not_before);
    let valid_days = ((not_after - not_before).max(0) + 86_399_999) / 86_400_000;
    (not_before, valid_days.max(1))
}

/// Ids chosen by callers (legacy migration) must be safe in URLs, file
/// names and log lines: 1-64 characters of `[A-Za-z0-9._-]`, not starting
/// with a dot.
fn validate_entity_id(id: &str) -> Result<String> {
    let id = id.trim();
    if id.is_empty()
        || id.len() > 64
        || id.starts_with('.')
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("invalid id {id:?}: use 1-64 letters, digits, '-', '_' or '.'");
    }
    Ok(id.to_string())
}

/// File name stem for a download: the common name reduced to
/// `[A-Za-z0-9._-]` (runs of anything else become one `_`, a leading `*.`
/// wildcard label becomes `wildcard.`), or the id when nothing usable is
/// left. Common names are unique per CA, so names stay distinct.
pub fn artifact_basename(common_name: &str, id: &str) -> String {
    let name = common_name.trim();
    let name = name
        .strip_prefix("*.")
        .map(|rest| format!("wildcard.{rest}"))
        .unwrap_or_else(|| name.to_string());
    let mut out = String::with_capacity(name.len());
    let mut last_sep = true;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-') {
            out.push(ch);
            last_sep = false;
        } else if !last_sep {
            out.push('_');
            last_sep = true;
        }
    }
    let out = out.trim_matches(['_', '.']).to_string();
    if out.is_empty() || out.chars().all(|c| matches!(c, '.' | '_' | '-')) {
        id.to_string()
    } else {
        out
    }
}

/// Finds the first `key=value` attribute of a distinguished name (see
/// `subject_attributes` for the splitting rules).
#[cfg(test)]
fn parse_subject_part(subject: &str, key: &str) -> Option<String> {
    subject_attributes(subject)
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value)
}

/// Splits on unescaped separator characters, keeping escape sequences intact
/// in the pieces for later decoding.
fn split_unescaped(input: &str, separators: &[char]) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in input.chars() {
        if escaped {
            current.push('\\');
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if separators.contains(&ch) {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    if escaped {
        current.push('\\');
    }
    parts.push(current);
    parts
}

/// Decodes RFC 2253 value escapes: `\X` is a literal X, `\XX` a hex byte.
fn unescape_dn_value(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|pair| std::str::from_utf8(pair).ok())
                .and_then(|pair| u8::from_str_radix(pair, 16).ok());
            if let Some(byte) = hex {
                out.push(byte);
                i += 3;
            } else {
                out.push(bytes[i + 1]);
                i += 2;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// True for a DNS name `validate_dns_name` accepts.
fn is_valid_dns_name(name: &str) -> bool {
    validate_dns_name(name).is_ok()
}

/// Strict DNS SAN validation: LDH labels of 1-63 characters (no leading or
/// trailing '-'), an optional leading `*.` wildcard label, at most 253
/// characters, and a non-numeric last label (so IPs go in the IP list).
/// Anything else — whitespace, control characters, `$`, `\`, `=`, quotes —
/// is rejected before it can reach an openssl config file.
fn validate_dns_name(name: &str) -> Result<()> {
    let invalid = |why: &str| anyhow::anyhow!("invalid DNS name {name:?}: {why}");
    if name.is_empty() || name.len() > 253 {
        return Err(invalid("must be 1-253 characters"));
    }
    let host = name.strip_prefix("*.").unwrap_or(name);
    if host.is_empty() {
        return Err(invalid("wildcard needs a domain after '*.'"));
    }
    let labels: Vec<&str> = host.split('.').collect();
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err(invalid("each label must be 1-63 characters"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(invalid(
                "only letters, digits and '-' are allowed (plus a leading '*.' wildcard)",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid("labels must not start or end with '-'"));
        }
    }
    if labels
        .last()
        .is_some_and(|label| label.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(invalid("looks like an IP address; put it in the IP list"));
    }
    Ok(())
}

/// PKCS#12 passwords are handed to openssl through a file whose first line
/// is the password, so line breaks (and other control characters) cannot be
/// represented and are rejected.
fn validate_password(password: Option<&str>) -> Result<()> {
    if password.is_some_and(|p| p.chars().any(char::is_control)) {
        bail!("password must not contain control characters or newlines");
    }
    Ok(())
}

/// The CRL URL is embedded in an openssl config file as `URI:<url>`; allow
/// only http(s) URLs made of printable ASCII without whitespace, quotes,
/// backslashes or commas (a comma would start another GeneralName).
fn validate_crl_url(url: &str) -> Result<()> {
    let lower = url.to_ascii_lowercase();
    let scheme_ok = lower.starts_with("http://") || lower.starts_with("https://");
    let chars_ok = url
        .chars()
        .all(|c| c.is_ascii_graphic() && !matches!(c, '"' | '\'' | '\\' | ',' | '<' | '>' | '`'));
    if !scheme_ok || !chars_ok {
        bail!(
            "invalid CRL URL {url:?}: public_base_url must be an http(s) URL without whitespace, quotes, backslashes or commas"
        );
    }
    Ok(())
}

/// Validates an untrusted backup and decodes it into rows ready for a single
/// restore transaction.
fn backup_to_snapshot(backup: BackupFile) -> Result<BackupSnapshot> {
    let mut snapshot = BackupSnapshot::default();
    for user in backup.users {
        let role = Role::parse(&user.role).with_context(|| {
            format!(
                "backup user {:?} has unknown role {:?}",
                user.username, user.role
            )
        })?;
        if user.username.trim().is_empty() || user.username.chars().any(char::is_control) {
            bail!("backup user {:?} has an invalid username", user.id);
        }
        snapshot.users.push(UserRecord {
            id: user.id,
            username: user.username,
            password_hash: user.password_hash,
            role: role.as_str().to_string(),
            created_at: user.created_at,
        });
    }
    for template in backup.templates {
        validate_backup_id(&template.id)?;
        let scope = TemplateScope::parse(&template.scope).with_context(|| {
            format!(
                "backup template {:?} has unknown scope {:?}",
                template.name, template.scope
            )
        })?;
        let values = validate_template_values(&template.values)
            .with_context(|| format!("backup template {:?} is invalid", template.name))?;
        let name = template.name.trim().to_string();
        if name.is_empty() || name.chars().any(char::is_control) {
            bail!("backup template {:?} has an invalid name", template.id);
        }
        snapshot.templates.push(Template {
            id: template.id,
            name,
            scope: scope.as_str().to_string(),
            is_default: template.is_default,
            values,
            created_at: template.created_at,
            updated_at: template.updated_at,
        });
    }
    for ca in backup.certificate_authorities {
        let ca_id = ca.meta.id.clone();
        validate_backup_id(&ca_id)?;
        let secrets: CaSecrets = ca
            .secrets
            .try_into()
            .with_context(|| format!("backup CA {ca_id} has invalid base64 data"))?;
        require_pem(
            &secrets.cert_pem,
            &["CERTIFICATE"],
            &format!("CA {ca_id} certificate"),
        )?;
        require_pem(
            &secrets.key_pem,
            &["PRIVATE KEY"],
            &format!("CA {ca_id} private key"),
        )?;
        require_hex_state(&secrets.serial_txt, false, &format!("CA {ca_id} serial"))?;
        require_hex_state(
            &secrets.crlnumber_txt,
            true,
            &format!("CA {ca_id} CRL number"),
        )?;
        let mut certs = Vec::new();
        for cert in ca.certificates {
            let cert_id = cert.meta.id.clone();
            validate_backup_id(&cert_id)?;
            if cert.meta.ca_id != ca_id {
                bail!(
                    "backup certificate {cert_id} claims CA {} but is listed under CA {ca_id}",
                    cert.meta.ca_id
                );
            }
            for entry in cert.meta.dns_list.iter().chain(&cert.meta.ip_list) {
                if entry.contains(';') || entry.chars().any(char::is_control) {
                    bail!("backup certificate {cert_id} has an invalid SAN entry {entry:?}");
                }
            }
            if let Some(reason) = cert.meta.revocation_reason.as_deref() {
                normalize_revocation_reason(reason).with_context(|| {
                    format!("backup certificate {cert_id} has an invalid revocation reason")
                })?;
            }
            let cert_secrets: CertSecrets = cert
                .secrets
                .try_into()
                .with_context(|| format!("backup certificate {cert_id} has invalid base64 data"))?;
            let label = format!("certificate {cert_id}");
            require_pem(&cert_secrets.cert_pem, &["CERTIFICATE"], &label)?;
            require_pem(
                &cert_secrets.key_pem,
                &["PRIVATE KEY"],
                &format!("{label} private key"),
            )?;
            require_pem(
                &cert_secrets.csr_pem,
                &["CERTIFICATE REQUEST"],
                &format!("{label} CSR"),
            )?;
            certs.push(BackupCertRow {
                meta: CertMeta {
                    id: cert.meta.id,
                    ca_id: cert.meta.ca_id,
                    common_name: cert.meta.common_name,
                    country_code: cert.meta.country_code,
                    state: cert.meta.state,
                    city: cert.meta.city,
                    organization: cert.meta.organization,
                    organization_unit: cert.meta.organization_unit,
                    subject: cert.meta.subject,
                    issue_time: cert.meta.issue_time,
                    valid_days: cert.meta.valid_days,
                    dns_list: cert.meta.dns_list,
                    ip_list: cert.meta.ip_list,
                    key_profile: cert.meta.key_profile,
                    digest_algorithm: cert.meta.digest_algorithm,
                    revoked_at: cert.meta.revoked_at,
                    revocation_reason: cert.meta.revocation_reason.clone(),
                },
                secrets: cert_secrets,
                deleted: cert.meta.deleted,
                revoked_at: cert.meta.revoked_at,
                revocation_reason: cert.meta.revocation_reason,
                created_at: cert.meta.created_at,
                updated_at: cert.meta.updated_at,
            });
        }
        snapshot.cas.push((
            BackupCaRow {
                meta: CaMeta {
                    id: ca.meta.id,
                    common_name: ca.meta.common_name,
                    country_code: ca.meta.country_code,
                    state: ca.meta.state,
                    city: ca.meta.city,
                    organization: ca.meta.organization,
                    organization_unit: ca.meta.organization_unit,
                    subject: ca.meta.subject,
                    issue_time: ca.meta.issue_time,
                    valid_days: ca.meta.valid_days,
                    key_profile: ca.meta.key_profile,
                    digest_algorithm: ca.meta.digest_algorithm,
                },
                secrets,
                deleted: ca.meta.deleted,
                created_at: ca.meta.created_at,
                updated_at: ca.meta.updated_at,
            },
            certs,
        ));
    }
    Ok(snapshot)
}

/// Ids end up in URLs and download file names; accept only what `short_id`
/// produces (plus '-'/'_').
/// Normalises template values and rejects anything the creation forms would
/// not accept. Blank fields become unset.
fn validate_template_values(values: &TemplateValues) -> Result<TemplateValues> {
    let values = values.normalized();
    if let Some(days) = values.valid_days.filter(|days| !(1..=7350).contains(days)) {
        bail!("valid_days must be in 1..7350, got {days}");
    }
    if let Some(code) = values
        .country_code
        .as_deref()
        .filter(|code| code.chars().count() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic()))
    {
        bail!("country_code must be a 2-letter code, got {code:?}");
    }
    if let Some(digest) = values
        .digest_algorithm
        .as_deref()
        .filter(|digest| !["sha256", "sha384", "sha512"].contains(digest))
    {
        bail!("digest_algorithm must be sha256, sha384 or sha512, got {digest:?}");
    }
    if let Some(profile) = values.key_profile.as_deref().filter(|profile| {
        ![
            "rsa:2048",
            "rsa:4096",
            "rsa:8192",
            "ecdsa:prime256v1",
            "ecdsa:secp384r1",
            "ecdsa:secp521r1",
        ]
        .contains(profile)
    }) {
        bail!("key_profile is not supported: {profile:?}");
    }
    for (field, value) in [
        ("country_code", &values.country_code),
        ("state", &values.state),
        ("city", &values.city),
        ("organization", &values.organization),
        ("organization_unit", &values.organization_unit),
    ] {
        if value.as_deref().is_some_and(|value| {
            value.chars().any(char::is_control) || value.chars().count() > 200
        }) {
            bail!("{field} must be at most 200 characters without control characters");
        }
    }
    Ok(values)
}

fn validate_backup_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("backup contains an invalid id {id:?}");
    }
    Ok(())
}

/// Requires a PEM block whose BEGIN line ends with one of `labels` (so
/// "PRIVATE KEY" also accepts "RSA PRIVATE KEY" / "EC PRIVATE KEY").
fn require_pem(bytes: &[u8], labels: &[&str], what: &str) -> Result<()> {
    let text = String::from_utf8_lossy(bytes);
    let ok = text.lines().any(|line| {
        let line = line.trim();
        line.starts_with("-----BEGIN ")
            && labels
                .iter()
                .any(|label| line.ends_with(&format!("{label}-----")))
    });
    if !ok {
        bail!("backup {what} is not a PEM {}", labels.join("/"));
    }
    Ok(())
}

/// openssl serial / crlnumber files hold a single hex number.
fn require_hex_state(bytes: &[u8], allow_empty: bool, what: &str) -> Result<()> {
    let text = String::from_utf8_lossy(bytes);
    let value = text.trim();
    if value.is_empty() && allow_empty {
        return Ok(());
    }
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("backup {what} is not a hex number");
    }
    Ok(())
}

fn info_value(info: &[(String, String)], key: &str) -> Option<String> {
    info.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.to_string())
}

fn parse_openssl_date(value: &str) -> Option<i64> {
    NaiveDateTime::parse_from_str(value.trim(), "%b %e %H:%M:%S %Y GMT")
        .ok()
        .map(|dt| Utc.from_utc_datetime(&dt).timestamp_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OpenSslConfig;
    use std::path::PathBuf;

    fn temp_service() -> (AppService, PathBuf) {
        let root = std::env::temp_dir().join(format!("minica-service-test-{}", Uuid::new_v4()));
        let db = Db::open(&root.join("db/db.sqlite")).expect("open temp db");
        let openssl = OpenSsl::new(OpenSslConfig {
            path: PathBuf::from("/usr/bin/openssl"),
            timeout_seconds: 60,
            working_root: root.join("work"),
            keep_failed_workdirs: false,
            reap_after_hours: 24,
        });
        let service = AppService::new(
            db,
            openssl,
            Some("http://localhost/minica".to_string()),
            CrlConfig::default(),
        );
        (service, root)
    }

    fn ca_request(common_name: &str, valid_days: i64) -> CreateCaRequest {
        CreateCaRequest {
            common_name: common_name.to_string(),
            country_code: "SG".to_string(),
            state: String::new(),
            city: String::new(),
            organization: "Org".to_string(),
            organization_unit: String::new(),
            valid_days,
            digest_algorithm: "sha256".to_string(),
            key_profile: "ecdsa:prime256v1".to_string(),
            password: None,
        }
    }

    fn cert_request(common_name: &str, valid_days: i64, dns: &[&str]) -> CreateCertRequest {
        CreateCertRequest {
            common_name: common_name.to_string(),
            country_code: "SG".to_string(),
            state: String::new(),
            city: String::new(),
            organization: "Org".to_string(),
            organization_unit: String::new(),
            valid_days,
            digest_algorithm: "sha384".to_string(),
            key_profile: "ecdsa:prime256v1".to_string(),
            password: None,
            dns_list: dns.iter().map(|d| d.to_string()).collect(),
            ip_list: vec!["10.0.0.7".to_string()],
        }
    }

    fn openssl_text(service: &AppService, args: &[&str], input: (&str, &[u8])) -> String {
        let work = service.openssl.workdir().unwrap();
        fs::write(work.path().join(input.0), input.1).unwrap();
        let out = service
            .openssl
            .run_in(work.path(), args, std::time::Duration::from_secs(30))
            .unwrap();
        assert_eq!(out.exit_code, 0, "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    #[test]
    fn dns_validation_is_strict() {
        for good in [
            "example.com",
            "a-b.example.com",
            "*.example.com",
            "localhost",
            "x1.internal",
        ] {
            assert!(validate_dns_name(good).is_ok(), "{good} should be valid");
        }
        for bad in [
            "",
            "a..b",
            "-a.com",
            "a-.com",
            "*.",
            "a.*.com",
            "a b.com",
            "a\nDNS.9 = evil.com",
            "a${ENV::HOME}.com",
            "a\\b.com",
            "a=b.com",
            "a\"b.com",
            "10.0.0.1",
            "under_score.com",
            &"a".repeat(64),
            &format!("{}.com", vec!["a".repeat(60); 5].join(".")),
        ] {
            assert!(
                validate_dns_name(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn crl_url_and_password_validation() {
        assert!(validate_crl_url("https://ca.example.com/minica/crl/abc").is_ok());
        assert!(validate_crl_url("http://localhost:8080/crl/x?y=1").is_ok());
        for bad in [
            "ftp://x/crl",
            "http://x/crl y",
            "http://x/crl\nDNS:evil",
            "http://x/a,DNS:evil",
            "http://x/\"q",
        ] {
            assert!(validate_crl_url(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(validate_password(None).is_ok());
        assert!(validate_password(Some("p@ss word")).is_ok());
        assert!(validate_password(Some("a\nb")).is_err());
    }

    #[test]
    fn parse_subject_part_handles_rfc2253_escapes() {
        let subject = r"C=SG,ST=S\, x,O=Org\, Inc\+y,OU=u1+OU=u2,CN=n=1";
        assert_eq!(parse_subject_part(subject, "C").as_deref(), Some("SG"));
        assert_eq!(parse_subject_part(subject, "ST").as_deref(), Some("S, x"));
        assert_eq!(
            parse_subject_part(subject, "O").as_deref(),
            Some("Org, Inc+y")
        );
        assert_eq!(parse_subject_part(subject, "OU").as_deref(), Some("u1"));
        assert_eq!(parse_subject_part(subject, "CN").as_deref(), Some("n=1"));
        assert_eq!(
            parse_subject_part(r"CN=caf\C3\A9", "CN").as_deref(),
            Some("café")
        );
        assert_eq!(
            parse_subject_part("C = SG, O = Org", "O").as_deref(),
            Some("Org")
        );
        assert_eq!(parse_subject_part(subject, "L"), None);
    }

    fn backup_yaml_fixture() -> BackupFile {
        let pem = |label: &str| {
            b64(format!("-----BEGIN {label}-----\nAA==\n-----END {label}-----\n").as_bytes())
        };
        BackupFile {
            format_version: BACKUP_FORMAT_VERSION,
            app_version: String::new(),
            schema_version: SCHEMA_VERSION,
            app: "minica-rust".to_string(),
            exported_at: 0,
            warning: String::new(),
            templates: vec![],
            users: vec![BackupUser {
                id: "u1".to_string(),
                username: "alice".to_string(),
                password_hash: "$2b$12$x".to_string(),
                role: "viewer".to_string(),
                created_at: 0,
            }],
            certificate_authorities: vec![BackupCa {
                meta: BackupCaMeta {
                    id: "ca1".to_string(),
                    common_name: "CA".to_string(),
                    country_code: "SG".to_string(),
                    state: String::new(),
                    city: String::new(),
                    organization: "Org".to_string(),
                    organization_unit: String::new(),
                    subject: "/CN=CA".to_string(),
                    issue_time: 0,
                    valid_days: 1,
                    key_profile: "rsa:2048".to_string(),
                    digest_algorithm: "sha256".to_string(),
                    deleted: false,
                    created_at: 0,
                    updated_at: 0,
                },
                secrets: BackupCaSecrets {
                    cert_pem_b64: pem("CERTIFICATE"),
                    key_pem_b64: pem("EC PRIVATE KEY"),
                    pkcs12_b64: String::new(),
                    password_b64: String::new(),
                    index_txt_b64: String::new(),
                    serial_txt_b64: b64(b"3A5F\n"),
                    crl_der_b64: String::new(),
                    crl_updated_at: 0,
                    // Pre-CRL-number backups have no such field.
                    crlnumber_txt_b64: String::new(),
                },
                certificates: vec![BackupCert {
                    meta: BackupCertMeta {
                        id: "c1".to_string(),
                        ca_id: "ca1".to_string(),
                        common_name: "web".to_string(),
                        country_code: "SG".to_string(),
                        state: String::new(),
                        city: String::new(),
                        organization: "Org".to_string(),
                        organization_unit: String::new(),
                        subject: "/CN=web".to_string(),
                        issue_time: 0,
                        valid_days: 1,
                        dns_list: vec!["web".to_string()],
                        ip_list: Vec::new(),
                        key_profile: "rsa:2048".to_string(),
                        digest_algorithm: "sha256".to_string(),
                        revoked_at: None,
                        revocation_reason: None,
                        deleted: false,
                        created_at: 0,
                        updated_at: 0,
                    },
                    secrets: BackupCertSecrets {
                        cert_pem_b64: pem("CERTIFICATE"),
                        key_pem_b64: pem("PRIVATE KEY"),
                        csr_pem_b64: pem("CERTIFICATE REQUEST"),
                        pkcs12_b64: String::new(),
                        password_b64: String::new(),
                        bundle_zip_b64: String::new(),
                    },
                }],
            }],
        }
    }

    #[test]
    fn backup_validation_rejects_untrusted_input() {
        assert!(backup_to_snapshot(backup_yaml_fixture()).is_ok());

        let mut backup = backup_yaml_fixture();
        backup.certificate_authorities[0].certificates[0].meta.ca_id = "other".to_string();
        assert!(
            backup_to_snapshot(backup).is_err(),
            "cert under the wrong CA"
        );

        let mut backup = backup_yaml_fixture();
        backup.users[0].role = "superuser".to_string();
        assert!(backup_to_snapshot(backup).is_err(), "unknown role");

        let mut backup = backup_yaml_fixture();
        backup.certificate_authorities[0].secrets.key_pem_b64 = b64(b"not a key");
        assert!(backup_to_snapshot(backup).is_err(), "bad key PEM");

        let mut backup = backup_yaml_fixture();
        backup.certificate_authorities[0].certificates[0]
            .meta
            .dns_list = vec!["a;b".to_string()];
        assert!(backup_to_snapshot(backup).is_err(), "list separator in SAN");

        let mut backup = backup_yaml_fixture();
        backup.certificate_authorities[0].secrets.serial_txt_b64 = b64(b"zz");
        assert!(backup_to_snapshot(backup).is_err(), "non-hex serial");

        // An older backup without the crlnumber field still parses.
        let yaml = serde_yaml::to_string(&backup_yaml_fixture())
            .unwrap()
            .lines()
            .filter(|line| !line.contains("crlnumber_txt_b64"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!yaml.contains("crlnumber_txt_b64"));
        let parsed: BackupFile = serde_yaml::from_str(&yaml).unwrap();
        assert!(backup_to_snapshot(parsed).is_ok());
    }

    /// Runs openssl in a fresh workdir and returns the files it wrote, for
    /// building certificates the way other tools (or minica 1.0.x) do.
    fn openssl_make(service: &AppService, steps: &[&[&str]], outputs: &[&str]) -> Vec<Vec<u8>> {
        let work = service.openssl.workdir().unwrap();
        for args in steps {
            let out = service
                .openssl
                .run_in(work.path(), args, std::time::Duration::from_secs(60))
                .unwrap();
            assert_eq!(out.exit_code, 0, "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        }
        outputs
            .iter()
            .map(|name| fs::read(work.path().join(name)).unwrap())
            .collect()
    }

    /// A self-signed CA with only a common name (as many home-lab CAs are).
    fn cn_only_ca(service: &AppService, cn: &str, days: &str) -> (String, String) {
        let files = openssl_make(
            service,
            &[
                &["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "k.pem"],
                &["req", "-new", "-x509", "-nodes", "-days", days, "-key", "k.pem", "-sha256",
                  "-out", "c.pem", "-subj", &format!("/CN={cn}"),
                  "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=keyCertSign,cRLSign"],
            ],
            &["c.pem", "k.pem"],
        );
        (
            String::from_utf8(files[0].clone()).unwrap(),
            String::from_utf8(files[1].clone()).unwrap(),
        )
    }

    #[test]
    fn imported_ca_keeps_its_real_subject_and_validity() {
        let (service, root) = temp_service();
        let (cert_pem, key_pem) = cn_only_ca(&service, "Homelab CA", "3650");
        let ca = service
            .import_ca(ImportCaRequest {
                cert_pem: cert_pem.clone(),
                key_pem: key_pem.clone(),
                password: Some("secret".to_string()),
            })
            .unwrap();
        // No invented country/organization (issue #21).
        assert_eq!(ca.subject, "/CN=Homelab CA");
        assert_eq!(ca.common_name, "Homelab CA");
        assert_eq!(ca.country_code, "");
        assert_eq!(ca.organization, "");
        // Validity comes from the certificate, not "now + 3650 days".
        assert_eq!(ca.valid_days, 3650);
        let now = Utc::now().timestamp_millis();
        assert!((now - ca.issue_time).abs() < 120_000, "{}", ca.issue_time);
        assert_eq!(ca.key_profile, "rsa:2048");
        assert_eq!(ca.digest_algorithm, "sha256");
        // Fresh rows are already marked as checked by the metadata repair.
        assert_eq!(service.db.meta_versions().unwrap().0, vec![1]);

        // A leaf certificate is refused as a CA, a mismatched key is refused too.
        let leaf = service
            .create_cert(&ca.id, cert_request("leaf.example.com", 10, &[]))
            .unwrap();
        let err = service
            .import_ca(ImportCaRequest {
                cert_pem: leaf.cert_pem.clone(),
                key_pem: leaf.key_pem.clone(),
                password: None,
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a certificate authority"), "{err}");
        let (other_cert, _) = cn_only_ca(&service, "Other CA", "30");
        let err = service
            .import_ca(ImportCaRequest {
                cert_pem: other_cert,
                key_pem,
                password: None,
            })
            .unwrap_err();
        assert!(format!("{err:#}").contains("does not match"), "{err:#}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn renewal_reproduces_sans_even_when_the_stored_csr_has_none() {
        let (service, root) = temp_service();
        let ca = service.create_ca(ca_request("SAN CA", 3650)).unwrap();
        let cert = service
            .create_cert(&ca.id, cert_request("web.home.lan", 10, &["www.home.lan"]))
            .unwrap();
        // Certificates imported before SAN copying existed have a CSR without
        // SANs: reproduce that by importing with a plain x509toreq CSR.
        let work = service.openssl.workdir().unwrap();
        fs::write(work.path().join("c.pem"), &cert.cert_pem).unwrap();
        fs::write(work.path().join("k.pem"), &cert.key_pem).unwrap();
        let out = service
            .openssl
            .run_in(
                work.path(),
                &["x509", "-x509toreq", "-in", "c.pem", "-signkey", "k.pem", "-out", "r.csr"],
                std::time::Duration::from_secs(60),
            )
            .unwrap();
        assert_eq!(out.exit_code, 0, "{}", String::from_utf8_lossy(&out.stderr));
        let plain_csr = fs::read(work.path().join("r.csr")).unwrap();
        drop(work);
        let csr_text = openssl_text(
            &service,
            &["req", "-in", "r.csr", "-noout", "-text"],
            ("r.csr", &plain_csr),
        );
        assert!(!csr_text.contains("Subject Alternative Name"), "{csr_text}");

        service.delete_cert(&ca.id, &cert.id).unwrap();
        let imported = service
            .import_cert_with(
                &ca.id,
                Some("legacy-cert-1".to_string()),
                ImportCertRequest {
                    cert_pem: cert.cert_pem.clone(),
                    key_pem: cert.key_pem.clone(),
                    password: Some("p12pass".to_string()),
                },
                Some(&plain_csr),
            )
            .unwrap();
        assert_eq!(imported.id, "legacy-cert-1");
        assert_eq!(imported.subject, "/C=SG/O=Org/CN=web.home.lan");
        let stored = service.db.get_cert_secrets(&ca.id, &imported.id).unwrap();
        assert_eq!(stored.csr_pem, plain_csr, "the supplied CSR is kept");
        assert_eq!(stored.password, b"p12pass");

        let renewed = service.renew_cert(&ca.id, &imported.id, 20).unwrap();
        let work = service.openssl.workdir().unwrap();
        let (dns, ips) = service
            .openssl
            .inspect_cert_sans(work.path(), &renewed.cert_pem)
            .unwrap();
        assert_eq!(dns, vec!["web.home.lan", "www.home.lan"]);
        assert_eq!(ips, vec!["10.0.0.7"]);
        let subject = service
            .openssl
            .inspect_cert_subject_rfc2253(work.path(), &renewed.cert_pem)
            .unwrap();
        assert_eq!(subject, "C=SG,O=Org,CN=web.home.lan");
        assert_eq!(renewed.valid_days, 20);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn renewal_is_capped_at_the_ca_expiry_and_reports_the_effective_days() {
        let (service, root) = temp_service();
        let ca = service.create_ca(ca_request("Short CA", 40)).unwrap();
        let cert = service
            .create_cert(&ca.id, cert_request("leaf.short.test", 10, &[]))
            .unwrap();
        let renewed = service.renew_cert(&ca.id, &cert.id, 3650).unwrap();
        assert!(renewed.valid_days <= 40 && renewed.valid_days >= 38, "{}", renewed.valid_days);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_metadata_is_repaired_from_the_certificates_once() {
        let (service, root) = temp_service();
        let ca = service.create_ca(ca_request("Repair CA", 30)).unwrap();
        let cert = service
            .create_cert(&ca.id, cert_request("leaf.repair.test", 10, &[]))
            .unwrap();
        // Nothing to do for rows written by this version.
        assert_eq!(service.repair_stale_metadata().unwrap(), (0, 0));

        // What an import by 1.2.2 or older left behind.
        let fake_issue = Utc::now().timestamp_millis() - 93 * 86_400_000;
        service
            .db
            .fake_legacy_ca_meta(&ca.id, "XX", "Imported", "/C=XX/O=Imported/CN=Repair CA", fake_issue, 3650)
            .unwrap();
        service
            .db
            .fake_legacy_cert_meta(&cert.id, "XX", "Imported", "/C=XX/O=Imported/CN=leaf.repair.test")
            .unwrap();
        assert_eq!(service.db.meta_versions().unwrap(), (vec![0], vec![0]));
        assert_eq!(service.get_ca(&ca.id).unwrap().subject, "/C=XX/O=Imported/CN=Repair CA");

        assert_eq!(service.repair_stale_metadata().unwrap(), (1, 1));
        let repaired = service.get_ca(&ca.id).unwrap();
        assert_eq!(repaired.subject, "/C=SG/O=Org/CN=Repair CA");
        assert_eq!(repaired.country_code, "SG");
        assert_eq!(repaired.organization, "Org");
        assert_eq!(repaired.valid_days, 30);
        assert!((repaired.issue_time - ca.issue_time).abs() < 2_000, "{} vs {}", repaired.issue_time, ca.issue_time);
        let repaired_cert = service.get_cert(&ca.id, &cert.id).unwrap();
        assert_eq!(repaired_cert.subject, "/C=SG/O=Org/CN=leaf.repair.test");
        assert_eq!(service.db.meta_versions().unwrap(), (vec![1], vec![1]));
        // Checked rows are not inspected again.
        assert_eq!(service.repair_stale_metadata().unwrap(), (0, 0));

        // A backup restored into an empty database is checked as well.
        let yaml = service.export_backup_yaml().unwrap();
        service.nuke_all().unwrap();
        service.import_backup_yaml(&yaml).unwrap();
        assert_eq!(service.db.meta_versions().unwrap(), (vec![1], vec![1]));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_tree_import_keeps_ids_passwords_and_sans() {
        let (service, root) = temp_service();
        // Build a 1.0.x data directory the way the Kotlin version did.
        let legacy = root.join("legacy-root");
        let ca_dir = legacy.join("CAs").join("6f1c2b4e-0000-4000-8000-00000000c0de");
        let cert_dir = ca_dir.join("9a8b7c6d-0000-4000-8000-0000000c3a7f");
        fs::create_dir_all(&cert_dir).unwrap();
        fs::create_dir_all(ca_dir.join("certs")).unwrap();
        let (ca_cert, ca_key) = cn_only_ca(&service, "Legacy Root", "3650");
        fs::write(ca_dir.join("ca-cert.pem"), &ca_cert).unwrap();
        fs::write(ca_dir.join("ca-key.pem"), &ca_key).unwrap();
        fs::write(ca_dir.join("password.txt"), "caP4ss").unwrap();
        fs::write(ca_dir.join("CA.complete"), "Done!").unwrap();
        fs::write(ca_dir.join("meta.properties"), "#Generated by MiniCA\ncommonName=Legacy Root\n").unwrap();
        // A leaf signed by that CA with SANs, through openssl ca like 1.0.x.
        let ca_conf = format!(
            "[ ca ]\ndefault_ca = CA_default\n[ CA_default ]\ndefault_days = 7300\ndefault_md = sha256\n\
             unique_subject = no\nbase_dir = {base}\ncertificate = $base_dir/ca-cert.pem\n\
             private_key = $base_dir/ca-key.pem\nnew_certs_dir = $base_dir/certs\n\
             database = $base_dir/index.txt\nserial = $base_dir/serial.txt\n\
             x509_extensions = ca_extensions\ncopy_extensions = copy\n[ ca_extensions ]\n\
             basicConstraints = CA:FALSE\n[ signing_policy ]\ncountryName = optional\n\
             stateOrProvinceName = optional\nlocalityName = optional\norganizationName = optional\n\
             organizationalUnitName = optional\ncommonName = supplied\n[ signing_req ]\n\
             subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n\
             basicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\n\
             extendedKeyUsage = serverAuth, clientAuth\n",
            base = ca_dir.display()
        );
        fs::write(ca_dir.join("openssl-ca.conf"), ca_conf).unwrap();
        fs::write(ca_dir.join("index.txt"), "").unwrap();
        fs::write(ca_dir.join("serial.txt"), "00\n").unwrap();
        let req_conf = "[ req ]\ndistinguished_name = dn\nreq_extensions = ext\n[ dn ]\ncommonName = CN\n\
                        [ ext ]\nsubjectAltName = @alt\n[ alt ]\nDNS.1 = web.home.lan\nDNS.2 = www.home.lan\nIP.1 = 10.0.0.5\n";
        fs::write(cert_dir.join("req.conf"), req_conf).unwrap();
        let run = |args: &[&str]| {
            let out = std::process::Command::new("/usr/bin/openssl")
                .args(args)
                .current_dir(&ca_dir)
                .output()
                .unwrap();
            assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        };
        let cert_base = cert_dir.display().to_string();
        run(&["req", "-config", &format!("{cert_base}/req.conf"), "-newkey", "rsa:2048", "-sha256", "-nodes",
              "-keyout", &format!("{cert_base}/cert.key"), "-out", &format!("{cert_base}/cert.csr"),
              "-subj", "/C=DE/ST=BW/O=Homelab/CN=web.home.lan"]);
        run(&["ca", "-config", "openssl-ca.conf", "-days", "365", "-batch", "-policy", "signing_policy",
              "-extensions", "signing_req", "-notext", "-out", &format!("{cert_base}/cert.pem"),
              "-infiles", &format!("{cert_base}/cert.csr")]);
        fs::write(cert_dir.join("password.txt"), "leafP4ss").unwrap();
        fs::write(cert_dir.join("CERT.complete"), "Done!").unwrap();
        // An incomplete certificate directory (no CERT.complete) is ignored,
        // and a broken one is reported without stopping the run.
        fs::create_dir_all(ca_dir.join("abandoned")).unwrap();
        fs::write(ca_dir.join("abandoned").join("cert.pem"), "junk").unwrap();
        let broken = ca_dir.join("broken-cert");
        fs::create_dir_all(&broken).unwrap();
        fs::write(broken.join("cert.pem"), "not a certificate").unwrap();
        fs::write(broken.join("cert.key"), "not a key").unwrap();
        fs::write(broken.join("CERT.complete"), "Done!").unwrap();

        let report = crate::legacy::import_tree(&service, &legacy).unwrap();
        assert_eq!(report.cas_imported, 1, "{report:?}");
        assert_eq!(report.certs_imported, 1, "{report:?}");
        assert_eq!(report.failures.len(), 1, "{report:?}");
        assert!(report.failures[0].contains("broken-cert"), "{report:?}");
        assert!(report.skipped.is_empty(), "{report:?}");

        let ca = service.get_ca("6f1c2b4e-0000-4000-8000-00000000c0de").unwrap();
        assert_eq!(ca.common_name, "Legacy Root");
        assert_eq!(ca.subject, "/CN=Legacy Root");
        assert_eq!(ca.valid_days, 3650);
        assert_eq!(service.db.get_ca_secrets(&ca.id).unwrap().password, b"caP4ss");
        let cert = service.get_cert(&ca.id, "9a8b7c6d-0000-4000-8000-0000000c3a7f").unwrap();
        assert_eq!(cert.subject, "/C=DE/ST=BW/O=Homelab/CN=web.home.lan");
        assert_eq!(cert.dns_list, vec!["web.home.lan", "www.home.lan"]);
        assert_eq!(cert.ip_list, vec!["10.0.0.5"]);
        assert_eq!(cert.valid_days, 365);
        let secrets = service.db.get_cert_secrets(&ca.id, &cert.id).unwrap();
        assert_eq!(secrets.password, b"leafP4ss");
        assert_eq!(secrets.csr_pem, fs::read(cert_dir.join("cert.csr")).unwrap());
        // The imported CA keeps working: it can issue, and the legacy leaf renews with its SANs.
        service
            .create_cert(&ca.id, cert_request("new.home.lan", 10, &[]))
            .unwrap();
        let renewed = service.renew_cert(&ca.id, &cert.id, 400).unwrap();
        assert_eq!(renewed.dns_list, vec!["web.home.lan", "www.home.lan"]);
        let work = service.openssl.workdir().unwrap();
        let (dns, _) = service
            .openssl
            .inspect_cert_sans(work.path(), &renewed.cert_pem)
            .unwrap();
        assert_eq!(dns, vec!["web.home.lan", "www.home.lan"]);

        // A second run is a no-op apart from the still-broken directory.
        let again = crate::legacy::import_tree(&service, &legacy).unwrap();
        assert_eq!((again.cas_imported, again.certs_imported), (0, 0));
        assert_eq!(again.skipped.len(), 2, "{again:?}");
        assert_eq!(again.failures.len(), 1);
        // The CAs directory itself is accepted too; anything else is not.
        assert!(crate::legacy::import_tree(&service, &legacy.join("CAs")).is_ok());
        assert!(crate::legacy::import_tree(&service, &root).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn subject_helpers() {
        let derived = DerivedSubject::from_rfc2253(r"C=DE,ST=BW,O=Home\, Lab,CN=web/home");
        assert_eq!(derived.subject, r"/C=DE/ST=BW/O=Home, Lab/CN=web\/home");
        assert_eq!(derived.common_name.as_deref(), Some("web/home"));
        assert_eq!(derived.organization, "Home, Lab");
        assert_eq!(derived.organization_unit, "");
        // openssl's default rendering (fallback) and multi-valued RDNs.
        let derived = DerivedSubject::from_rfc2253("C = SG, O = Org, OU = a+OU = b, CN = x");
        assert_eq!(derived.subject, "/C=SG/O=Org/OU=a/OU=b/CN=x");
        assert_eq!(DerivedSubject::from_rfc2253("").subject, "");
        assert_eq!(DerivedSubject::from_rfc2253("CN=Homelab CA").subject, "/CN=Homelab CA");

        assert_eq!(artifact_basename("Homelab CA", "id1"), "Homelab_CA");
        assert_eq!(artifact_basename("*.example.com", "id1"), "wildcard.example.com");
        assert_eq!(artifact_basename("web.home.lan", "id1"), "web.home.lan");
        assert_eq!(artifact_basename("  a  b/c\\d:e  ", "id1"), "a_b_c_d_e");
        assert_eq!(artifact_basename("日本語", "id1"), "id1");
        assert_eq!(artifact_basename("...", "id1"), "id1");
        assert_eq!(artifact_basename("", "id1"), "id1");

        assert!(validate_entity_id("6f1c2b4e-0000-4000-8000-00000000c0de").is_ok());
        assert!(validate_entity_id("a_b.c").is_ok());
        for bad in ["", ".hidden", "a/b", "a b", &"x".repeat(65)] {
            assert!(validate_entity_id(bad).is_err(), "{bad:?}");
        }

        let info = vec![
            ("notBefore".to_string(), "Oct 25 04:24:20 2026 GMT".to_string()),
            ("notAfter".to_string(), "Oct 22 04:24:20 2036 GMT".to_string()),
        ];
        let (issue, days) = validity_from_info(&info);
        assert_eq!(days, 3650);
        assert_eq!(issue, parse_openssl_date("Oct 25 04:24:20 2026 GMT").unwrap());
        assert!(has_fabricated_subject("XX", "Org"));
        assert!(has_fabricated_subject("DE", "Imported"));
        assert!(!has_fabricated_subject("DE", "Org"));
    }

    #[test]
    fn create_user_rejects_bootstrap_username() {
        let (service, root) = temp_service();
        let service = service.with_reserved_usernames(["admin"]);
        let err = service
            .create_user(CreateUserRequest {
                username: "admin".to_string(),
                password: "secret123".to_string(),
                role: "viewer".to_string(),
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("reserved"), "{err}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn certificate_lifecycle_hardening() {
        let (service, root) = temp_service();
        assert!(
            service
                .create_ca(CreateCaRequest {
                    digest_algorithm: "md5".to_string(),
                    ..ca_request("bad digest", 30)
                })
                .is_err()
        );
        let ca = service.create_ca(ca_request("Hardening CA", 30)).unwrap();

        // New CA: random positive serial, and a v2 CRL carrying a CRL number.
        let secrets = service.db.get_ca_secrets(&ca.id).unwrap();
        let serial = String::from_utf8_lossy(&secrets.serial_txt)
            .trim()
            .to_string();
        assert_eq!(serial.len(), 32, "{serial}");
        assert_ne!(serial, "00");
        let crl = openssl_text(
            &service,
            &["crl", "-inform", "DER", "-in", "c.crl", "-noout", "-text"],
            ("c.crl", &secrets.crl_der),
        );
        assert!(
            crl.contains("Version 2") && crl.contains("CRL Number"),
            "{crl}"
        );

        // Injection attempts are rejected before reaching openssl.
        for dns in ["a\nDNS.9 = evil.com", "${ENV::HOME}.example.com"] {
            let err = service
                .create_cert(&ca.id, cert_request("leaf.example.com", 10, &[dns]))
                .unwrap_err()
                .to_string();
            assert!(err.contains("invalid DNS name"), "{err}");
        }
        assert!(
            service
                .create_cert(&ca.id, cert_request("leaf\n", 10, &[]))
                .is_err()
        );

        // Leaf validity is clamped to the CA's expiry; -md is honoured.
        let cert = service
            .create_cert(
                &ca.id,
                cert_request("leaf.example.com", 400, &["alt.example.com"]),
            )
            .unwrap();
        assert!(cert.valid_days < 30, "valid_days {}", cert.valid_days);
        assert_eq!(cert.dns_list, vec!["leaf.example.com", "alt.example.com"]);
        let text = openssl_text(
            &service,
            &["x509", "-in", "c.pem", "-noout", "-text"],
            ("c.pem", cert.cert_pem.as_bytes()),
        );
        assert!(text.contains("ecdsa-with-SHA384"), "{text}");

        // Renewal keeps SANs (imported certs too) and reissues a new serial.
        let renewed = service.renew_cert(&ca.id, &cert.id, 29).unwrap();
        assert_ne!(renewed.cert_pem, cert.cert_pem);
        service.delete_cert(&ca.id, &cert.id).unwrap();
        let imported = service
            .import_cert(
                &ca.id,
                ImportCertRequest {
                    cert_pem: renewed.cert_pem.clone(),
                    key_pem: renewed.key_pem.clone(),
                    password: None,
                },
            )
            .unwrap();
        let renewed_import = service.renew_cert(&ca.id, &imported.id, 29).unwrap();
        let sans = openssl_text(
            &service,
            &["x509", "-in", "c.pem", "-noout", "-ext", "subjectAltName"],
            ("c.pem", renewed_import.cert_pem.as_bytes()),
        );
        assert!(
            sans.contains("DNS:alt.example.com") && sans.contains("10.0.0.7"),
            "{sans}"
        );
        // A mismatched key is reported as such.
        let other = service
            .create_cert(&ca.id, cert_request("other.example.com", 10, &[]))
            .unwrap();
        let err = service
            .import_cert(
                &ca.id,
                ImportCertRequest {
                    cert_pem: renewed.cert_pem.clone(),
                    key_pem: other.key_pem.clone(),
                    password: None,
                },
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match"), "{err}");

        // Revoking revokes every serial issued for the same subject, and a
        // revoked certificate cannot be renewed.
        service
            .revoke_cert(&ca.id, &imported.id, "keyCompromise")
            .unwrap();
        let index = String::from_utf8_lossy(&service.db.get_ca_secrets(&ca.id).unwrap().index_txt)
            .to_string();
        let leaf_lines: Vec<&str> = index
            .lines()
            .filter(|l| l.ends_with("CN=leaf.example.com"))
            .collect();
        assert!(leaf_lines.len() >= 3, "{index}");
        assert!(leaf_lines.iter().all(|l| l.starts_with('R')), "{index}");
        let err = service
            .renew_cert(&ca.id, &imported.id, 29)
            .unwrap_err()
            .to_string();
        assert!(err.contains("revoked"), "{err}");
        assert!(
            service
                .get_cert(&ca.id, &imported.id)
                .unwrap()
                .revoked_at
                .is_some()
        );

        // Restoring the original from trash would duplicate the active CN.
        assert!(service.restore_cert(&ca.id, &cert.id).is_err());
        let _ = fs::remove_dir_all(root);
    }

    /// Runs openssl in a fresh workdir holding `files`; returns the exit code
    /// and combined stdout/stderr.
    fn openssl_files(
        service: &AppService,
        files: &[(&str, &[u8])],
        args: &[&str],
    ) -> (i32, String) {
        let work = service.openssl.workdir().unwrap();
        for (name, bytes) in files {
            fs::write(work.path().join(name), bytes).unwrap();
        }
        let out = service
            .openssl
            .run_in(work.path(), args, std::time::Duration::from_secs(30))
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.exit_code, text)
    }

    fn x509_field(service: &AppService, pem: &str, args: &[&str]) -> String {
        let mut full = vec!["x509", "-in", "c.pem", "-noout"];
        full.extend_from_slice(args);
        openssl_text(service, &full, ("c.pem", pem.as_bytes()))
    }

    #[test]
    fn ca_renewal_keeps_key_subject_and_trust_chain() {
        let (service, root) = temp_service();
        let ca = service.create_ca(ca_request("Renewal CA", 30)).unwrap();
        let before = service
            .create_cert(&ca.id, cert_request("before.example.com", 10, &[]))
            .unwrap();
        let old_pem = ca.cert_pem.clone();

        // Days are validated and the expiry must move forward.
        for days in [0, 7351] {
            assert!(service.renew_ca(&ca.id, days).is_err());
        }
        let err = service.renew_ca(&ca.id, 10).unwrap_err().to_string();
        assert!(err.contains("would not extend"), "{err}");
        assert!(service.renew_ca("missing", 365).is_err());

        let renewed = service.renew_ca(&ca.id, 400).unwrap();
        let new_pem = renewed.cert_pem.clone();
        assert_ne!(new_pem, old_pem);
        assert_eq!(renewed.valid_days, 400);
        assert!(renewed.issue_time >= ca.issue_time);

        // Byte-identical subject (DER of every attribute), same SKI/AKI and
        // extensions, new serial, later notAfter.
        for args in [
            &["-subject", "-nameopt", "RFC2253,dump_all,dump_der"][..],
            &["-subject_hash", "-issuer_hash"][..],
            &[
                "-ext",
                "subjectKeyIdentifier,authorityKeyIdentifier,basicConstraints,keyUsage",
            ][..],
            &["-pubkey"][..],
        ] {
            assert_eq!(
                x509_field(&service, &old_pem, args),
                x509_field(&service, &new_pem, args),
                "{args:?}"
            );
        }
        let ski = x509_field(&service, &new_pem, &["-ext", "subjectKeyIdentifier"]);
        assert!(ski.contains("Subject Key Identifier"), "{ski}");
        assert_ne!(
            x509_field(&service, &old_pem, &["-serial"]),
            x509_field(&service, &new_pem, &["-serial"])
        );
        let not_after = |pem: &str| {
            let text = x509_field(&service, pem, &["-enddate"]);
            parse_openssl_date(text.trim().trim_start_matches("notAfter=")).unwrap()
        };
        assert!(not_after(&new_pem) > not_after(&old_pem) + 300 * 86_400_000);

        // Leaves issued before renewal verify against the renewed CA, and
        // leaves issued after it verify against the old CA certificate.
        let after = service
            .create_cert(&ca.id, cert_request("after.example.com", 200, &[]))
            .unwrap();
        assert_eq!(after.valid_days, 200, "no longer clamped to the old expiry");
        for (ca_pem, leaf) in [(&new_pem, &before), (&old_pem, &after), (&new_pem, &after)] {
            let (code, out) = openssl_files(
                &service,
                &[
                    ("ca.pem", ca_pem.as_bytes()),
                    ("leaf.pem", leaf.cert_pem.as_bytes()),
                ],
                &["verify", "-CAfile", "ca.pem", "leaf.pem"],
            );
            assert_eq!(code, 0, "{out}");
        }

        // Derived artifacts follow: PKCS12, existing bundles, and the CRL.
        let secrets = service.db.get_ca_secrets(&ca.id).unwrap();
        let (code, p12) = openssl_files(
            &service,
            &[("ca.p12", &secrets.pkcs12), ("pass", &secrets.password)],
            &["pkcs12", "-in", "ca.p12", "-nokeys", "-passin", "file:pass"],
        );
        assert_eq!(code, 0, "{p12}");
        let p12_cert = p12
            .find("-----BEGIN CERTIFICATE-----")
            .map(|i| &p12[i..])
            .unwrap();
        assert_eq!(p12_cert.trim(), new_pem.trim());
        let bundle = service
            .db
            .get_cert_secrets(&ca.id, &before.id)
            .unwrap()
            .bundle_zip;
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bundle)).unwrap();
        let mut bundled_ca = String::new();
        std::io::Read::read_to_string(&mut zip.by_name("ca.pem").unwrap(), &mut bundled_ca)
            .unwrap();
        assert_eq!(bundled_ca, new_pem);
        let (code, out) = openssl_files(
            &service,
            &[("c.crl", &secrets.crl_der), ("ca.pem", new_pem.as_bytes())],
            &[
                "crl", "-inform", "DER", "-in", "c.crl", "-CAfile", "ca.pem", "-noout",
            ],
        );
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("verify OK"), "{out}");

        // A backup round-trips the renewed CA unchanged.
        let yaml = service.export_backup_yaml().unwrap();
        let (restored, restored_root) = temp_service();
        restored.import_backup_yaml(&yaml).unwrap();
        let restored_ca = restored.get_ca(&ca.id).unwrap();
        assert_eq!(restored_ca.cert_pem, new_pem);
        assert_eq!(restored_ca.valid_days, 400);
        assert_eq!(
            restored.db.get_ca_secrets(&ca.id).unwrap().pkcs12,
            secrets.pkcs12
        );
        let _ = fs::remove_dir_all(restored_root);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ca_renewal_refuses_intermediate_ca() {
        let (service, root) = temp_service();
        let parent = service.create_ca(ca_request("Parent CA", 60)).unwrap();
        let parent_key = parent.key_pem.clone();

        // Build an intermediate signed by the parent, then import it.
        let work = service.openssl.workdir().unwrap();
        let dir = work.path();
        fs::write(dir.join("parent.pem"), &parent.cert_pem).unwrap();
        fs::write(dir.join("parent.key"), &parent_key).unwrap();
        fs::write(
            dir.join("ext.cnf"),
            "[v3]\nbasicConstraints = critical, CA:true\nkeyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n",
        )
        .unwrap();
        for args in [
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                "int.key",
            ][..],
            &[
                "req",
                "-new",
                "-key",
                "int.key",
                "-subj",
                "/C=SG/O=Org/CN=Intermediate CA",
                "-out",
                "int.csr",
            ][..],
            &[
                "x509",
                "-req",
                "-in",
                "int.csr",
                "-CA",
                "parent.pem",
                "-CAkey",
                "parent.key",
                "-set_serial",
                "0x1001",
                "-days",
                "30",
                "-extfile",
                "ext.cnf",
                "-extensions",
                "v3",
                "-out",
                "int.pem",
            ][..],
        ] {
            let out = service
                .openssl
                .run_in(dir, args, std::time::Duration::from_secs(30))
                .unwrap();
            assert_eq!(out.exit_code, 0, "{}", String::from_utf8_lossy(&out.stderr));
        }
        let int_pem = fs::read_to_string(dir.join("int.pem")).unwrap();
        let intermediate = service
            .import_ca(ImportCaRequest {
                cert_pem: int_pem.clone(),
                key_pem: fs::read_to_string(dir.join("int.key")).unwrap(),
                password: None,
            })
            .unwrap();
        assert!(!service.ca_is_self_signed(&intermediate.cert_pem).unwrap());
        assert!(service.ca_is_self_signed(&parent.cert_pem).unwrap());
        let err = service
            .renew_ca(&intermediate.id, 365)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("intermediate CA must be re-issued by its parent"),
            "{err}"
        );
        // Nothing changed, and the CA lock was released.
        assert_eq!(service.get_ca(&intermediate.id).unwrap().cert_pem, int_pem);
        service.renew_ca(&parent.id, 365).unwrap();
        let _ = fs::remove_dir_all(root);
    }
}
