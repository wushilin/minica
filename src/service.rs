use crate::{
    config::{CrlConfig, Role},
    db::{CaMeta, CaSecrets, CertMeta, CertSecrets, Db, SCHEMA_VERSION, UserRecord},
    models::{
        Certificate, CertificateAuthority, CreateCaRequest, CreateCertRequest, CreateUserRequest,
        ImportCaRequest, ImportCertRequest, InspectResponse, UserView,
    },
    openssl::{OpenSsl, create_subject, random_password},
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
}

pub enum Download {
    CaCert,
    CaKey,
    CaPkcs12,
    CaPassword,
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
    pub certificate_authorities: Vec<BackupCa>,
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
        }
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
        let secrets = self.openssl.create_ca_files(
            work.path(),
            &subject,
            req.valid_days,
            &req.digest_algorithm,
            &key.algorithm,
            &key.attributes,
            &password,
        )?;
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
            digest_algorithm: req.digest_algorithm.to_lowercase(),
        };
        self.db.insert_ca(&meta, &secrets)?;
        let ca = self.db.get_ca(&id)?;
        if self.crl.enabled {
            let work = self.openssl.workdir()?;
            let refresh =
                self.openssl
                    .generate_crl(work.path(), &secrets, self.crl.next_update_days)?;
            self.db
                .update_ca_crl(&id, &refresh.crl_der, &refresh.index_txt)?;
        }
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
        tracing::info!(
            cert_pem_bytes = req.cert_pem.len(),
            key_pem_bytes = req.key_pem.len(),
            "importing certificate authority"
        );
        let id = short_id();
        let password = req.password.unwrap_or_else(random_password);
        let work = self.openssl.workdir()?;
        fs::write(work.path().join("ca-cert.pem"), req.cert_pem.as_bytes())?;
        fs::write(work.path().join("ca-key.pem"), req.key_pem.as_bytes())?;
        let info = self.openssl.inspect_cert(work.path(), &req.cert_pem)?;
        let text = self
            .openssl
            .inspect_cert_text(work.path(), &req.cert_pem)
            .unwrap_or_default();
        let subject_text = info
            .iter()
            .find(|(k, _)| k == "subject")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "Imported CA".to_string());
        let common_name =
            parse_subject_part(&subject_text, "CN").unwrap_or_else(|| "Imported CA".to_string());
        self.ensure_unique_ca_common_name(&common_name)?;
        let country_code =
            parse_subject_part(&subject_text, "C").unwrap_or_else(|| "XX".to_string());
        let organization =
            parse_subject_part(&subject_text, "O").unwrap_or_else(|| "Imported".to_string());
        let state = parse_subject_part(&subject_text, "ST").unwrap_or_default();
        let city = parse_subject_part(&subject_text, "L").unwrap_or_default();
        let organization_unit = parse_subject_part(&subject_text, "OU").unwrap_or_default();
        let subject = create_subject(
            &common_name,
            &country_code,
            &organization,
            &state,
            &city,
            &organization_unit,
        )?;
        let secrets = self.openssl.finish_ca_files(work.path(), &password)?;
        let meta = CaMeta {
            id: id.clone(),
            common_name,
            country_code,
            state,
            city,
            organization,
            organization_unit,
            subject,
            issue_time: Utc::now().timestamp_millis(),
            valid_days: 3650,
            key_profile: parse_public_key_profile(&text),
            digest_algorithm: parse_signature_digest(&text)
                .unwrap_or_else(|| "imported".to_string()),
        };
        self.db.insert_ca(&meta, &secrets)?;
        let ca = self.db.get_ca(&id)?;
        if self.crl.enabled {
            let work = self.openssl.workdir()?;
            let refresh =
                self.openssl
                    .generate_crl(work.path(), &secrets, self.crl.next_update_days)?;
            self.db
                .update_ca_crl(&id, &refresh.crl_der, &refresh.index_txt)?;
        }
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
        let _cert = self.db.get_cert(ca_id, cert_id)?;
        if _cert.revoked_at.is_some() {
            bail!("certificate is already revoked");
        }
        let ca_secrets = self.db.get_ca_secrets(ca_id)?;
        let cert_secrets = self.db.get_cert_secrets(ca_id, cert_id)?;
        let owner = Uuid::new_v4().to_string();
        self.db.acquire_ca_lock(ca_id, &owner, 120_000)?;
        let revoked_at = Utc::now().timestamp_millis();
        let result = (|| -> Result<Certificate> {
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
                &refresh.crl_der,
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
        for ip in &req.ip_list {
            ip.parse::<std::net::IpAddr>()
                .with_context(|| format!("invalid IP SAN: {ip}"))?;
        }
        self.ensure_unique_cert_common_name(ca_id, &req.common_name)?;
        let _ca = self.db.get_ca(ca_id)?;
        let ca_secrets = self.db.get_ca_secrets(ca_id)?;
        let crl_url = self.crl_url(ca_id);
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
            let work = self.openssl.workdir()?;
            let password = req.password.clone().unwrap_or_else(random_password);
            let (secrets, index_txt, serial_txt) = self.openssl.create_cert_files(
                work.path(),
                &ca_secrets,
                &subject,
                &req.common_name,
                req.valid_days,
                &req.digest_algorithm,
                &key.algorithm,
                &key.attributes,
                &req.dns_list,
                &req.ip_list,
                &password,
                crl_url.as_deref(),
                self.crl.next_update_days,
            )?;
            let mut dns_list = vec![req.common_name.clone()];
            for dns in &req.dns_list {
                if !dns_list.contains(dns) {
                    dns_list.push(dns.clone());
                }
            }
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
                valid_days: req.valid_days,
                dns_list,
                ip_list: req.ip_list.clone(),
                key_profile: key.profile,
                digest_algorithm: req.digest_algorithm.to_lowercase(),
                revoked_at: None,
                revocation_reason: None,
            };
            self.db
                .insert_cert_with_state(&meta, &secrets, (&index_txt, &serial_txt), &owner)?;
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
        tracing::info!(
            ca_id = %ca_id,
            cert_pem_bytes = req.cert_pem.len(),
            key_pem_bytes = req.key_pem.len(),
            "importing certificate"
        );
        let _ca = self.db.get_ca(ca_id)?;
        let ca_secrets = self.db.get_ca_secrets(ca_id)?;
        let cert_id = short_id();
        let owner = Uuid::new_v4().to_string();
        let work = self.openssl.workdir()?;
        let info = self
            .openssl
            .inspect_cert(work.path(), &req.cert_pem)
            .context("imported certificate PEM is not a valid certificate")?;
        self.db.acquire_ca_lock(ca_id, &owner, 120_000)?;
        let result = (|| -> Result<Certificate> {
            let password = req.password.clone().unwrap_or_else(random_password);
            let secrets = self
                .openssl
                .import_cert_files(work.path(), &ca_secrets, &req.cert_pem, &req.key_pem, &password)
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
            let subject_text = info_value(&info, "subject").unwrap_or_default();
            let common_name = parse_subject_part(&subject_text, "CN")
                .unwrap_or_else(|| "Imported Certificate".to_string());
            self.ensure_unique_cert_common_name(ca_id, &common_name)?;
            let country_code =
                parse_subject_part(&subject_text, "C").unwrap_or_else(|| "XX".to_string());
            let organization =
                parse_subject_part(&subject_text, "O").unwrap_or_else(|| "Imported".to_string());
            let state = parse_subject_part(&subject_text, "ST").unwrap_or_default();
            let city = parse_subject_part(&subject_text, "L").unwrap_or_default();
            let organization_unit = parse_subject_part(&subject_text, "OU").unwrap_or_default();
            let (mut dns_list, ip_list) = self
                .openssl
                .inspect_cert_sans(work.path(), &req.cert_pem)
                .unwrap_or_default();
            let text = self
                .openssl
                .inspect_cert_text(work.path(), &req.cert_pem)
                .unwrap_or_default();
            if !dns_list.contains(&common_name) {
                dns_list.insert(0, common_name.clone());
            }
            let not_before = info_value(&info, "notBefore")
                .and_then(|value| parse_openssl_date(&value))
                .unwrap_or_else(|| Utc::now().timestamp_millis());
            let not_after = info_value(&info, "notAfter")
                .and_then(|value| parse_openssl_date(&value))
                .unwrap_or(not_before);
            let valid_days = ((not_after - not_before).max(0) / 86_400_000).max(1);
            let subject = create_subject(
                &common_name,
                &country_code,
                &organization,
                &state,
                &city,
                &organization_unit,
            )?;
            let meta = CertMeta {
                id: cert_id.clone(),
                ca_id: ca_id.to_string(),
                common_name,
                country_code,
                state,
                city,
                organization,
                organization_unit,
                subject,
                issue_time: not_before,
                valid_days,
                dns_list,
                ip_list,
                key_profile: parse_public_key_profile(&text),
                digest_algorithm: parse_signature_digest(&text)
                    .unwrap_or_else(|| "imported".to_string()),
                revoked_at: None,
                revocation_reason: None,
            };
            self.db.insert_cert_with_state(
                &meta,
                &secrets,
                (&ca_secrets.index_txt, &ca_secrets.serial_txt),
                &owner,
            )?;
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
        let now = Utc::now().timestamp_millis();
        let current_expiry = cert.issue_time + cert.valid_days * 86_400_000;
        let proposed_expiry = now + days * 86_400_000;
        if proposed_expiry <= current_expiry {
            let min_days = ((current_expiry - now).max(0) / 86_400_000) + 1;
            bail!(
                "renewal would not extend the certificate expiry; choose at least {min_days} days"
            );
        }
        let ca_secrets = self.db.get_ca_secrets(ca_id)?;
        let cert_secrets = self.db.get_cert_secrets(ca_id, cert_id)?;
        let crl_url = self.crl_url(ca_id);
        let owner = Uuid::new_v4().to_string();
        self.db.acquire_ca_lock(ca_id, &owner, 120_000)?;
        let result = (|| -> Result<Certificate> {
            let work = self.openssl.workdir()?;
            let (cert_pem, pkcs12, bundle, index_txt) = self.openssl.renew_cert_files(
                work.path(),
                &ca_secrets,
                &cert_secrets,
                days,
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
        let artifact = match kind {
            Download::CaCert => (format!("ca-{ca_id}-cert.pem"), secrets.cert_pem),
            Download::CaKey => (format!("ca-{ca_id}-key.pem"), secrets.key_pem),
            Download::CaPkcs12 => (format!("ca-{ca_id}.p12"), secrets.pkcs12),
            Download::CaPassword => (format!("ca-{ca_id}-password.txt"), secrets.password),
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
        let artifact = match kind {
            Download::CertBundle => (format!("cert-{cert_id}.zip"), secrets.bundle_zip),
            Download::CertPem => (format!("cert-{cert_id}.pem"), secrets.cert_pem),
            Download::CertCsr => (format!("cert-{cert_id}.csr"), secrets.csr_pem),
            Download::CertKey => (format!("cert-{cert_id}.key"), secrets.key_pem),
            Download::CertPkcs12 => (format!("cert-{cert_id}.p12"), secrets.pkcs12),
            Download::CertPassword => (
                format!("cert-{cert_id}-pkcs12-password.txt"),
                secrets.password,
            ),
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
        let users: Vec<BackupUser> = self
            .db
            .list_users()?
            .into_iter()
            .map(BackupUser::from)
            .collect();
        let user_count = users.len();
        let mut cas_out = Vec::new();
        for ca in self.db.list_backup_cas()? {
            let mut certs_out = Vec::new();
            for cert in self.db.list_backup_certs(&ca.meta.id)? {
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
            certificate_authorities: cas_out,
        })
        .map_err(anyhow::Error::from)?;
        tracing::info!(
            ca_count,
            cert_count,
            user_count,
            bytes = yaml.len(),
            "exported backup YAML"
        );
        Ok(yaml)
    }

    #[tracing::instrument(skip(self, yaml), fields(span_id = %span_id(), yaml_bytes = yaml.len()))]
    pub fn import_backup_yaml(&self, yaml: &str) -> Result<()> {
        tracing::warn!(bytes = yaml.len(), "importing backup YAML");
        let outcome = (|| -> Result<(usize, usize, usize)> {
            if !self.db.is_empty()? {
                bail!("backup restore requires an empty database");
            }
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
            for user in backup.users {
                tracing::info!(user_id = %user.id, username = %user.username, role = %user.role, "restoring backup user");
                self.db.insert_user_restore(
                    &user.id,
                    &user.username,
                    &user.password_hash,
                    &user.role,
                    user.created_at,
                )?;
            }
            for ca in backup.certificate_authorities {
                tracing::info!(ca_id = %ca.meta.id, common_name = %ca.meta.common_name, deleted = ca.meta.deleted, cert_count = ca.certificates.len(), "restoring backup certificate authority");
                let meta = CaMeta {
                    id: ca.meta.id.clone(),
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
                };
                self.db.insert_ca_restore_full(
                    &meta,
                    &ca.secrets.try_into()?,
                    ca.meta.deleted,
                    ca.meta.created_at,
                    ca.meta.updated_at,
                )?;
                for cert in ca.certificates {
                    tracing::info!(
                        ca_id = %cert.meta.ca_id,
                        cert_id = %cert.meta.id,
                        common_name = %cert.meta.common_name,
                        deleted = cert.meta.deleted,
                        "restoring backup certificate"
                    );
                    let meta = CertMeta {
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
                        revocation_reason: cert.meta.revocation_reason,
                    };
                    self.db.insert_cert_restore_full(
                        &meta,
                        &cert.secrets.try_into()?,
                        cert.meta.deleted,
                        cert.meta.created_at,
                        cert.meta.updated_at,
                    )?;
                }
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

fn parse_subject_part(subject: &str, key: &str) -> Option<String> {
    for part in subject.split(',') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().to_string());
            }
        }
    }
    None
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
