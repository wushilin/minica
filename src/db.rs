use crate::models::{Certificate, CertificateAuthority};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use rand::{Rng, distr::Alphanumeric};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

#[derive(Clone)]
pub struct CaSecrets {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub pkcs12: Vec<u8>,
    pub password: Vec<u8>,
    pub index_txt: Vec<u8>,
    pub serial_txt: Vec<u8>,
    pub crl_der: Vec<u8>,
    pub crl_updated_at: i64,
}

#[derive(Clone)]
pub struct CertSecrets {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub csr_pem: Vec<u8>,
    pub pkcs12: Vec<u8>,
    pub password: Vec<u8>,
    pub bundle_zip: Vec<u8>,
}

#[derive(Clone)]
pub struct CaMeta {
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
}

#[derive(Clone)]
pub struct UserRecord {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub created_at: i64,
}

#[derive(Clone)]
pub struct BackupCaRow {
    pub meta: CaMeta,
    pub secrets: CaSecrets,
    pub deleted: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone)]
pub struct BackupCertRow {
    pub meta: CertMeta,
    pub secrets: CertSecrets,
    pub deleted: bool,
    pub revoked_at: Option<i64>,
    pub revocation_reason: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone)]
pub struct CertMeta {
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
    pub revoked_at: Option<i64>,
    pub revocation_reason: Option<String>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        tracing::info!(db_path = %path.display(), "opening sqlite database");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create db folder {}", parent.display()))?;
        }
        let db_existed = path.exists();
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open sqlite db {}", path.display()))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let migration_needed = !schema_is_current(&conn)?;
        let backup = if db_existed && migration_needed {
            Some(copy_db_backup(path)?)
        } else {
            None
        };
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        if migration_needed {
            if let Err(err) = db.migrate() {
                tracing::error!(db_path = %path.display(), error = %err, "database migration failed");
                drop(db);
                if let Some(backup) = backup.as_ref() {
                    match fs::copy(backup, path) {
                        Ok(_) => tracing::warn!(
                            db_path = %path.display(),
                            backup_path = %backup.display(),
                            "restored sqlite database from pre-migration backup"
                        ),
                        Err(restore_err) => tracing::error!(
                            db_path = %path.display(),
                            backup_path = %backup.display(),
                            error = %restore_err,
                            "failed to restore sqlite database from pre-migration backup"
                        ),
                    }
                }
                return Err(err);
            }
        } else {
            tracing::debug!(db_path = %path.display(), "sqlite schema is current; skipping migrations");
        }
        tracing::info!(db_path = %path.display(), "sqlite database ready");
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        tracing::info!(
            schema_version = SCHEMA_VERSION,
            "running database migrations"
        );
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS certificate_authorities (
                id TEXT PRIMARY KEY,
                common_name TEXT NOT NULL,
                country_code TEXT NOT NULL,
                state TEXT NOT NULL,
                city TEXT NOT NULL,
                organization TEXT NOT NULL,
                organization_unit TEXT NOT NULL,
                subject TEXT NOT NULL,
                issue_time INTEGER NOT NULL,
                valid_days INTEGER NOT NULL,
                key_profile TEXT NOT NULL DEFAULT 'rsa:4096',
                digest_algorithm TEXT NOT NULL,
                cert_pem BLOB NOT NULL,
                key_pem BLOB NOT NULL,
                pkcs12 BLOB NOT NULL,
                password BLOB NOT NULL,
                index_txt BLOB NOT NULL,
                serial_txt BLOB NOT NULL,
                crl_der BLOB NOT NULL DEFAULT X'',
                crl_updated_at INTEGER NOT NULL DEFAULT 0,
                deleted INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS certificates (
                id TEXT PRIMARY KEY,
                ca_id TEXT NOT NULL REFERENCES certificate_authorities(id) ON DELETE CASCADE,
                common_name TEXT NOT NULL,
                country_code TEXT NOT NULL,
                state TEXT NOT NULL,
                city TEXT NOT NULL,
                organization TEXT NOT NULL,
                organization_unit TEXT NOT NULL,
                subject TEXT NOT NULL,
                issue_time INTEGER NOT NULL,
                valid_days INTEGER NOT NULL,
                dns_list TEXT NOT NULL,
                ip_list TEXT NOT NULL,
                key_profile TEXT NOT NULL DEFAULT 'rsa:4096',
                digest_algorithm TEXT NOT NULL,
                cert_pem BLOB NOT NULL,
                key_pem BLOB NOT NULL,
                csr_pem BLOB NOT NULL,
                pkcs12 BLOB NOT NULL,
                password BLOB NOT NULL,
                bundle_zip BLOB NOT NULL,
                revoked_at INTEGER,
                revocation_reason TEXT,
                deleted INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ca_locks (
                ca_id TEXT PRIMARY KEY REFERENCES certificate_authorities(id) ON DELETE CASCADE,
                owner_id TEXT NOT NULL,
                locked_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            -- certificates.ca_id is filtered on every CA view (list_cas' LEFT
            -- JOIN, the per-CA cert listings, and the dashboard/trash COUNT
            -- subqueries) and walked by ON DELETE CASCADE. Without an index each
            -- of those is a full scan of the (growing) certificates table. The
            -- trailing created_at lets the index also satisfy the ORDER BY.
            CREATE INDEX IF NOT EXISTS idx_certificates_ca_id
                ON certificates(ca_id, created_at);

            -- Partial index for the soft-delete "trash" listing
            -- (WHERE deleted = 1 ORDER BY updated_at DESC). Only indexes deleted
            -- rows, so it stays tiny while making that view index-driven.
            CREATE INDEX IF NOT EXISTS idx_certificates_trash
                ON certificates(updated_at) WHERE deleted = 1;
            "#,
        )?;
        // Add the soft-delete columns to databases created before they existed.
        // Errors (e.g. the column already exists) are intentionally ignored.
        let _ = conn.execute(
            "ALTER TABLE certificate_authorities ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE certificates ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE certificate_authorities ADD COLUMN key_profile TEXT NOT NULL DEFAULT 'rsa:4096'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE certificates ADD COLUMN key_profile TEXT NOT NULL DEFAULT 'rsa:4096'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE certificate_authorities ADD COLUMN crl_der BLOB NOT NULL DEFAULT X''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE certificate_authorities ADD COLUMN crl_updated_at INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute("ALTER TABLE certificates ADD COLUMN revoked_at INTEGER", []);
        let _ = conn.execute(
            "ALTER TABLE certificates ADD COLUMN revocation_reason TEXT",
            [],
        );
        conn.execute("DELETE FROM schema_version", [])?;
        conn.execute(
            "INSERT INTO schema_version(version) VALUES (?)",
            params![SCHEMA_VERSION],
        )?;
        tracing::info!(
            schema_version = SCHEMA_VERSION,
            "database migrations complete"
        );
        Ok(())
    }

    pub fn insert_ca(&self, meta: &CaMeta, secrets: &CaSecrets) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("db mutex poisoned");
        let rows = conn.execute(
            r#"
            INSERT INTO certificate_authorities (
                id, common_name, country_code, state, city, organization, organization_unit,
                subject, issue_time, valid_days, key_profile, digest_algorithm,
                cert_pem, key_pem, pkcs12, password, index_txt, serial_txt, crl_der, crl_updated_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                meta.id,
                meta.common_name,
                meta.country_code,
                meta.state,
                meta.city,
                meta.organization,
                meta.organization_unit,
                meta.subject,
                meta.issue_time,
                meta.valid_days,
                meta.key_profile,
                meta.digest_algorithm,
                secrets.cert_pem,
                secrets.key_pem,
                secrets.pkcs12,
                secrets.password,
                secrets.index_txt,
                secrets.serial_txt,
                secrets.crl_der,
                secrets.crl_updated_at,
                now,
                now
            ],
        )?;
        tracing::info!(
            ca_id = %meta.id,
            common_name = %meta.common_name,
            key_profile = %meta.key_profile,
            digest_algorithm = %meta.digest_algorithm,
            rows_affected = rows,
            "inserted certificate authority"
        );
        Ok(())
    }

    pub fn list_cas(&self) -> Result<Vec<CertificateAuthority>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            r#"
            SELECT ca.id, ca.common_name, ca.country_code, ca.state, ca.city, ca.organization,
                   ca.organization_unit, ca.subject, ca.issue_time, ca.valid_days,
                   ca.key_profile, ca.digest_algorithm, ca.cert_pem, ca.key_pem, COUNT(c.id)
            FROM certificate_authorities ca
            LEFT JOIN certificates c ON c.ca_id = ca.id
            WHERE ca.deleted = 0
            GROUP BY ca.id
            ORDER BY ca.created_at DESC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(CertificateAuthority {
                id: row.get(0)?,
                common_name: row.get(1)?,
                country_code: row.get(2)?,
                state: row.get(3)?,
                city: row.get(4)?,
                organization: row.get(5)?,
                organization_unit: row.get(6)?,
                subject: row.get(7)?,
                issue_time: row.get(8)?,
                valid_days: row.get(9)?,
                key_profile: row.get(10)?,
                digest_algorithm: row.get(11)?,
                cert_pem: blob_string(row.get(12)?),
                key_pem: blob_string(row.get(13)?),
                crl_url: None,
                cert_count: row.get(14)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn get_ca(&self, id: &str) -> Result<CertificateAuthority> {
        self.list_cas()?
            .into_iter()
            .find(|ca| ca.id == id)
            .with_context(|| format!("CA not found: {id}"))
    }

    pub fn update_ca_metadata(
        &self,
        id: &str,
        key_profile: &str,
        digest_algorithm: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let now = Utc::now().timestamp_millis();
        let count = conn.execute(
            "UPDATE certificate_authorities SET key_profile = ?, digest_algorithm = ?, updated_at = ? WHERE id = ?",
            params![key_profile, digest_algorithm, now, id],
        )?;
        if count == 0 {
            bail!("CA not found: {id}");
        }
        tracing::info!(ca_id = %id, rows_affected = count, "updated certificate authority metadata");
        Ok(())
    }

    pub fn get_ca_secrets(&self, id: &str) -> Result<CaSecrets> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.query_row(
            r#"
            SELECT cert_pem, key_pem, pkcs12, password, index_txt, serial_txt, crl_der, crl_updated_at
            FROM certificate_authorities
            WHERE id = ? AND deleted = 0
            "#,
            params![id],
            |row| {
                Ok(CaSecrets {
                    cert_pem: row.get(0)?,
                    key_pem: row.get(1)?,
                    pkcs12: row.get(2)?,
                    password: row.get(3)?,
                    index_txt: row.get(4)?,
                    serial_txt: row.get(5)?,
                    crl_der: row.get(6)?,
                    crl_updated_at: row.get(7)?,
                })
            },
        )
        .optional()?
        .with_context(|| format!("CA not found: {id}"))
    }

    pub fn delete_ca(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let now = Utc::now().timestamp_millis();
        let count = conn.execute(
            "UPDATE certificate_authorities SET deleted = 1, updated_at = ? WHERE id = ? AND deleted = 0",
            params![now, id],
        )?;
        if count == 0 {
            bail!("CA not found: {id}");
        }
        tracing::info!(ca_id = %id, rows_affected = count, "soft-deleted certificate authority");
        Ok(())
    }

    pub fn restore_ca(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let now = Utc::now().timestamp_millis();
        let count = conn.execute(
            "UPDATE certificate_authorities SET deleted = 0, updated_at = ? WHERE id = ? AND deleted = 1",
            params![now, id],
        )?;
        if count == 0 {
            bail!("deleted CA not found: {id}");
        }
        tracing::info!(ca_id = %id, rows_affected = count, "restored certificate authority");
        Ok(())
    }

    /// Lists soft-deleted CAs for the admin console. `cert_count` only counts
    /// the CA's own non-deleted certificates.
    pub fn list_deleted_cas(&self) -> Result<Vec<CertificateAuthority>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            r#"
            SELECT ca.id, ca.common_name, ca.country_code, ca.state, ca.city, ca.organization,
                   ca.organization_unit, ca.subject, ca.issue_time, ca.valid_days,
                   ca.key_profile, ca.digest_algorithm, ca.cert_pem, ca.key_pem,
                   (SELECT COUNT(*) FROM certificates c WHERE c.ca_id = ca.id AND c.deleted = 0)
            FROM certificate_authorities ca
            WHERE ca.deleted = 1
            ORDER BY ca.updated_at DESC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(CertificateAuthority {
                id: row.get(0)?,
                common_name: row.get(1)?,
                country_code: row.get(2)?,
                state: row.get(3)?,
                city: row.get(4)?,
                organization: row.get(5)?,
                organization_unit: row.get(6)?,
                subject: row.get(7)?,
                issue_time: row.get(8)?,
                valid_days: row.get(9)?,
                key_profile: row.get(10)?,
                digest_algorithm: row.get(11)?,
                cert_pem: blob_string(row.get(12)?),
                key_pem: blob_string(row.get(13)?),
                crl_url: None,
                cert_count: row.get(14)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Returns the common name of any CA (deleted or not), for display.
    pub fn ca_common_name(&self, id: &str) -> Option<String> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.query_row(
            "SELECT common_name FROM certificate_authorities WHERE id = ?",
            params![id],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn insert_cert_with_state(
        &self,
        meta: &CertMeta,
        secrets: &CertSecrets,
        ca_state: (&[u8], &[u8]),
        lock_owner: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        let tx = conn.transaction()?;
        verify_lock_tx(&tx, &meta.ca_id, lock_owner)?;
        let cert_rows = tx.execute(
            r#"
            INSERT INTO certificates (
                id, ca_id, common_name, country_code, state, city, organization, organization_unit,
                subject, issue_time, valid_days, dns_list, ip_list, key_profile, digest_algorithm,
                cert_pem, key_pem, csr_pem, pkcs12, password, bundle_zip, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                meta.id,
                meta.ca_id,
                meta.common_name,
                meta.country_code,
                meta.state,
                meta.city,
                meta.organization,
                meta.organization_unit,
                meta.subject,
                meta.issue_time,
                meta.valid_days,
                meta.dns_list.join(";"),
                meta.ip_list.join(";"),
                meta.key_profile,
                meta.digest_algorithm,
                secrets.cert_pem,
                secrets.key_pem,
                secrets.csr_pem,
                secrets.pkcs12,
                secrets.password,
                secrets.bundle_zip,
                now,
                now
            ],
        )?;
        let ca_rows = tx.execute(
            "UPDATE certificate_authorities SET index_txt = ?, serial_txt = ?, updated_at = ? WHERE id = ?",
            params![ca_state.0, ca_state.1, now, meta.ca_id],
        )?;
        let lock_rows = tx.execute(
            "DELETE FROM ca_locks WHERE ca_id = ? AND owner_id = ?",
            params![meta.ca_id, lock_owner],
        )?;
        tx.commit()?;
        tracing::info!(
            ca_id = %meta.ca_id,
            cert_id = %meta.id,
            common_name = %meta.common_name,
            key_profile = %meta.key_profile,
            digest_algorithm = %meta.digest_algorithm,
            cert_rows_affected = cert_rows,
            ca_rows_affected = ca_rows,
            lock_rows_affected = lock_rows,
            "inserted certificate and persisted CA signing state"
        );
        Ok(())
    }

    pub fn insert_cert_restore(&self, meta: &CertMeta, secrets: &CertSecrets) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("db mutex poisoned");
        let rows = conn.execute(
            r#"
            INSERT INTO certificates (
                id, ca_id, common_name, country_code, state, city, organization, organization_unit,
                subject, issue_time, valid_days, dns_list, ip_list, key_profile, digest_algorithm,
                cert_pem, key_pem, csr_pem, pkcs12, password, bundle_zip, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                meta.id,
                meta.ca_id,
                meta.common_name,
                meta.country_code,
                meta.state,
                meta.city,
                meta.organization,
                meta.organization_unit,
                meta.subject,
                meta.issue_time,
                meta.valid_days,
                meta.dns_list.join(";"),
                meta.ip_list.join(";"),
                meta.key_profile,
                meta.digest_algorithm,
                secrets.cert_pem,
                secrets.key_pem,
                secrets.csr_pem,
                secrets.pkcs12,
                secrets.password,
                secrets.bundle_zip,
                now,
                now
            ],
        )?;
        tracing::info!(
            ca_id = %meta.ca_id,
            cert_id = %meta.id,
            rows_affected = rows,
            "restored certificate"
        );
        Ok(())
    }

    pub fn list_backup_cas(&self) -> Result<Vec<BackupCaRow>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            r#"
            SELECT id, common_name, country_code, state, city, organization, organization_unit,
                   subject, issue_time, valid_days, key_profile, digest_algorithm,
                   cert_pem, key_pem, pkcs12, password, index_txt, serial_txt, crl_der, crl_updated_at,
                   deleted, created_at, updated_at
            FROM certificate_authorities
            ORDER BY created_at ASC, id ASC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(BackupCaRow {
                meta: CaMeta {
                    id: row.get(0)?,
                    common_name: row.get(1)?,
                    country_code: row.get(2)?,
                    state: row.get(3)?,
                    city: row.get(4)?,
                    organization: row.get(5)?,
                    organization_unit: row.get(6)?,
                    subject: row.get(7)?,
                    issue_time: row.get(8)?,
                    valid_days: row.get(9)?,
                    key_profile: row.get(10)?,
                    digest_algorithm: row.get(11)?,
                },
                secrets: CaSecrets {
                    cert_pem: row.get(12)?,
                    key_pem: row.get(13)?,
                    pkcs12: row.get(14)?,
                    password: row.get(15)?,
                    index_txt: row.get(16)?,
                    serial_txt: row.get(17)?,
                    crl_der: row.get(18)?,
                    crl_updated_at: row.get(19)?,
                },
                deleted: row.get::<_, i64>(20)? != 0,
                created_at: row.get(21)?,
                updated_at: row.get(22)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn list_backup_certs(&self, ca_id: &str) -> Result<Vec<BackupCertRow>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            r#"
            SELECT id, ca_id, common_name, country_code, state, city, organization, organization_unit,
                   subject, issue_time, valid_days, dns_list, ip_list, key_profile, digest_algorithm,
                   cert_pem, key_pem, csr_pem, pkcs12, password, bundle_zip,
                   deleted, revoked_at, revocation_reason, created_at, updated_at
            FROM certificates
            WHERE ca_id = ?1
            ORDER BY created_at ASC, id ASC
            "#,
        )?;
        let rows = stmt.query_map(params![ca_id], |row| {
            let dns: String = row.get(11)?;
            let ips: String = row.get(12)?;
            Ok(BackupCertRow {
                meta: CertMeta {
                    id: row.get(0)?,
                    ca_id: row.get(1)?,
                    common_name: row.get(2)?,
                    country_code: row.get(3)?,
                    state: row.get(4)?,
                    city: row.get(5)?,
                    organization: row.get(6)?,
                    organization_unit: row.get(7)?,
                    subject: row.get(8)?,
                    issue_time: row.get(9)?,
                    valid_days: row.get(10)?,
                    dns_list: split_list(&dns),
                    ip_list: split_list(&ips),
                    key_profile: row.get(13)?,
                    digest_algorithm: row.get(14)?,
                    revoked_at: row.get(22)?,
                    revocation_reason: row.get(23)?,
                },
                secrets: CertSecrets {
                    cert_pem: row.get(15)?,
                    key_pem: row.get(16)?,
                    csr_pem: row.get(17)?,
                    pkcs12: row.get(18)?,
                    password: row.get(19)?,
                    bundle_zip: row.get(20)?,
                },
                deleted: row.get::<_, i64>(21)? != 0,
                revoked_at: row.get(22)?,
                revocation_reason: row.get(23)?,
                created_at: row.get(24)?,
                updated_at: row.get(25)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn insert_ca_restore_full(
        &self,
        meta: &CaMeta,
        secrets: &CaSecrets,
        deleted: bool,
        created_at: i64,
        updated_at: i64,
    ) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let created_at = if created_at == 0 { now } else { created_at };
        let updated_at = if updated_at == 0 {
            created_at
        } else {
            updated_at
        };
        let conn = self.conn.lock().expect("db mutex poisoned");
        let rows = conn.execute(
            r#"
            INSERT INTO certificate_authorities (
                id, common_name, country_code, state, city, organization, organization_unit,
                subject, issue_time, valid_days, key_profile, digest_algorithm,
                cert_pem, key_pem, pkcs12, password, index_txt, serial_txt, crl_der, crl_updated_at,
                deleted, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                meta.id,
                meta.common_name,
                meta.country_code,
                meta.state,
                meta.city,
                meta.organization,
                meta.organization_unit,
                meta.subject,
                meta.issue_time,
                meta.valid_days,
                meta.key_profile,
                meta.digest_algorithm,
                secrets.cert_pem,
                secrets.key_pem,
                secrets.pkcs12,
                secrets.password,
                secrets.index_txt,
                secrets.serial_txt,
                secrets.crl_der,
                secrets.crl_updated_at,
                if deleted { 1 } else { 0 },
                created_at,
                updated_at
            ],
        )?;
        tracing::info!(ca_id = %meta.id, deleted, rows_affected = rows, "restored certificate authority from backup");
        Ok(())
    }

    pub fn insert_cert_restore_full(
        &self,
        meta: &CertMeta,
        secrets: &CertSecrets,
        deleted: bool,
        created_at: i64,
        updated_at: i64,
    ) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let created_at = if created_at == 0 { now } else { created_at };
        let updated_at = if updated_at == 0 {
            created_at
        } else {
            updated_at
        };
        let conn = self.conn.lock().expect("db mutex poisoned");
        let rows = conn.execute(
            r#"
            INSERT INTO certificates (
                id, ca_id, common_name, country_code, state, city, organization, organization_unit,
                subject, issue_time, valid_days, dns_list, ip_list, key_profile, digest_algorithm,
                cert_pem, key_pem, csr_pem, pkcs12, password, bundle_zip,
                deleted, revoked_at, revocation_reason, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                meta.id,
                meta.ca_id,
                meta.common_name,
                meta.country_code,
                meta.state,
                meta.city,
                meta.organization,
                meta.organization_unit,
                meta.subject,
                meta.issue_time,
                meta.valid_days,
                meta.dns_list.join(";"),
                meta.ip_list.join(";"),
                meta.key_profile,
                meta.digest_algorithm,
                secrets.cert_pem,
                secrets.key_pem,
                secrets.csr_pem,
                secrets.pkcs12,
                secrets.password,
                secrets.bundle_zip,
                if deleted { 1 } else { 0 },
                meta.revoked_at,
                meta.revocation_reason,
                created_at,
                updated_at
            ],
        )?;
        tracing::info!(
            ca_id = %meta.ca_id,
            cert_id = %meta.id,
            deleted,
            rows_affected = rows,
            "restored certificate from backup"
        );
        Ok(())
    }

    pub fn insert_user_restore(
        &self,
        id: &str,
        username: &str,
        password_hash: &str,
        role: &str,
        created_at: i64,
    ) -> Result<()> {
        let created_at = if created_at == 0 {
            Utc::now().timestamp_millis()
        } else {
            created_at
        };
        let conn = self.conn.lock().expect("db mutex poisoned");
        let rows = conn.execute(
            "INSERT INTO users(id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            params![id, username, password_hash, role, created_at],
        )?;
        tracing::info!(user_id = %id, username = %username, role = %role, rows_affected = rows, "restored user from backup");
        Ok(())
    }

    pub fn nuke_all(&self) -> Result<()> {
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        let tx = conn.transaction()?;
        let lock_rows = tx.execute("DELETE FROM ca_locks", [])?;
        let cert_rows = tx.execute("DELETE FROM certificates", [])?;
        let ca_rows = tx.execute("DELETE FROM certificate_authorities", [])?;
        let user_rows = tx.execute("DELETE FROM users", [])?;
        tx.commit()?;
        tracing::warn!(
            lock_rows_affected = lock_rows,
            cert_rows_affected = cert_rows,
            ca_rows_affected = ca_rows,
            user_rows_affected = user_rows,
            total_rows_affected = lock_rows + cert_rows + ca_rows + user_rows,
            "nuked all database entities"
        );
        Ok(())
    }

    pub fn is_empty(&self) -> Result<bool> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let count: i64 = conn.query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM certificate_authorities) +
                (SELECT COUNT(*) FROM certificates) +
                (SELECT COUNT(*) FROM users)
            "#,
            [],
            |row| row.get(0),
        )?;
        Ok(count == 0)
    }

    /// True when a non-deleted CA already uses this common name. CA common
    /// names are unique among CAs only; they are not checked against cert CNs.
    pub fn ca_common_name_exists(&self, common_name: &str) -> Result<bool> {
        let normalized = common_name.trim();
        let conn = self.conn.lock().expect("db mutex poisoned");
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM certificate_authorities WHERE deleted = 0 AND lower(trim(common_name)) = lower(?1)",
            params![normalized],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// True when a non-deleted certificate under the given CA already uses this
    /// common name. Cert common names are unique within their CA; the same CN
    /// may be reused under a different CA.
    pub fn cert_common_name_exists(&self, ca_id: &str, common_name: &str) -> Result<bool> {
        let normalized = common_name.trim();
        let conn = self.conn.lock().expect("db mutex poisoned");
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM certificates WHERE deleted = 0 AND ca_id = ?1 AND lower(trim(common_name)) = lower(?2)",
            params![ca_id, normalized],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Finds the id of a non-deleted certificate under a non-deleted CA whose
    /// common name matches (case- and whitespace-insensitively). Per-CA CN
    /// uniqueness guarantees at most one match.
    pub fn find_cert_id_by_cn(&self, ca_id: &str, common_name: &str) -> Result<Option<String>> {
        let normalized = common_name.trim();
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.query_row(
            r#"
            SELECT id FROM certificates
            WHERE ca_id = ?1 AND deleted = 0 AND lower(trim(common_name)) = lower(?2)
              AND (SELECT deleted FROM certificate_authorities WHERE id = ?1) = 0
            "#,
            params![ca_id, normalized],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn update_cert_with_state(
        &self,
        ca_id: &str,
        cert_id: &str,
        cert_pem: &[u8],
        pkcs12: &[u8],
        bundle_zip: &[u8],
        issue_time: i64,
        valid_days: i64,
        ca_state: (&[u8], &[u8]),
        lock_owner: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        let tx = conn.transaction()?;
        verify_lock_tx(&tx, ca_id, lock_owner)?;
        let cert_rows = tx.execute(
            r#"
            UPDATE certificates
            SET cert_pem = ?, pkcs12 = ?, bundle_zip = ?, issue_time = ?, valid_days = ?, revoked_at = NULL, revocation_reason = NULL, updated_at = ?
            WHERE id = ? AND ca_id = ?
            "#,
            params![cert_pem, pkcs12, bundle_zip, issue_time, valid_days, now, cert_id, ca_id],
        )?;
        let ca_rows = tx.execute(
            "UPDATE certificate_authorities SET index_txt = ?, serial_txt = ?, updated_at = ? WHERE id = ?",
            params![ca_state.0, ca_state.1, now, ca_id],
        )?;
        let lock_rows = tx.execute(
            "DELETE FROM ca_locks WHERE ca_id = ? AND owner_id = ?",
            params![ca_id, lock_owner],
        )?;
        tx.commit()?;
        tracing::info!(
            ca_id = %ca_id,
            cert_id = %cert_id,
            valid_days,
            cert_rows_affected = cert_rows,
            ca_rows_affected = ca_rows,
            lock_rows_affected = lock_rows,
            "updated certificate and persisted CA signing state"
        );
        Ok(())
    }

    pub fn revoke_cert_with_state(
        &self,
        ca_id: &str,
        cert_id: &str,
        reason: &str,
        revoked_at: i64,
        ca_state: (&[u8], &[u8]),
        crl_der: &[u8],
        lock_owner: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        let tx = conn.transaction()?;
        verify_lock_tx(&tx, ca_id, lock_owner)?;
        let cert_rows = tx.execute(
            r#"
            UPDATE certificates
            SET revoked_at = ?, revocation_reason = ?, updated_at = ?
            WHERE id = ? AND ca_id = ? AND deleted = 0
            "#,
            params![revoked_at, reason, now, cert_id, ca_id],
        )?;
        if cert_rows == 0 {
            bail!("certificate not found: {ca_id}/{cert_id}");
        }
        let ca_rows = tx.execute(
            "UPDATE certificate_authorities SET index_txt = ?, serial_txt = ?, crl_der = ?, crl_updated_at = ?, updated_at = ? WHERE id = ? AND deleted = 0",
            params![ca_state.0, ca_state.1, crl_der, now, now, ca_id],
        )?;
        let lock_rows = tx.execute(
            "DELETE FROM ca_locks WHERE ca_id = ? AND owner_id = ?",
            params![ca_id, lock_owner],
        )?;
        tx.commit()?;
        tracing::info!(
            ca_id = %ca_id,
            cert_id = %cert_id,
            reason,
            cert_rows_affected = cert_rows,
            ca_rows_affected = ca_rows,
            lock_rows_affected = lock_rows,
            crl_bytes = crl_der.len(),
            "revoked certificate and refreshed CRL"
        );
        Ok(())
    }

    pub fn update_ca_crl(&self, ca_id: &str, crl_der: &[u8], index_txt: &[u8]) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("db mutex poisoned");
        let rows = conn.execute(
            "UPDATE certificate_authorities SET crl_der = ?, crl_updated_at = ?, index_txt = ?, updated_at = ? WHERE id = ? AND deleted = 0",
            params![crl_der, now, index_txt, now, ca_id],
        )?;
        if rows == 0 {
            bail!("CA not found: {ca_id}");
        }
        tracing::info!(ca_id = %ca_id, rows_affected = rows, crl_bytes = crl_der.len(), "updated certificate authority CRL");
        Ok(())
    }

    pub fn get_ca_crl(&self, ca_id: &str) -> Result<Vec<u8>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.query_row(
            "SELECT crl_der FROM certificate_authorities WHERE id = ? AND deleted = 0",
            params![ca_id],
            |row| row.get(0),
        )
        .optional()?
        .with_context(|| format!("CRL not found: {ca_id}"))
    }

    pub fn list_certs(&self, ca_id: &str) -> Result<Vec<Certificate>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            r#"
            SELECT id, ca_id, common_name, country_code, state, city, organization, organization_unit,
                   subject, issue_time, valid_days, dns_list, ip_list, key_profile, digest_algorithm,
                   cert_pem, key_pem, revoked_at, revocation_reason
            FROM certificates
            WHERE ca_id = ?1 AND deleted = 0
              AND (SELECT deleted FROM certificate_authorities WHERE id = ?1) = 0
            ORDER BY created_at DESC
            "#,
        )?;
        let rows = stmt.query_map(params![ca_id], row_to_cert)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn get_cert(&self, ca_id: &str, cert_id: &str) -> Result<Certificate> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.query_row(
            r#"
            SELECT id, ca_id, common_name, country_code, state, city, organization, organization_unit,
                   subject, issue_time, valid_days, dns_list, ip_list, key_profile, digest_algorithm,
                   cert_pem, key_pem, revoked_at, revocation_reason
            FROM certificates
            WHERE ca_id = ?1 AND id = ?2 AND deleted = 0
              AND (SELECT deleted FROM certificate_authorities WHERE id = ?1) = 0
            "#,
            params![ca_id, cert_id],
            row_to_cert,
        )
        .optional()?
        .with_context(|| format!("certificate not found: {ca_id}/{cert_id}"))
    }

    pub fn get_cert_secrets(&self, ca_id: &str, cert_id: &str) -> Result<CertSecrets> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.query_row(
            r#"
            SELECT cert_pem, key_pem, csr_pem, pkcs12, password, bundle_zip
            FROM certificates
            WHERE ca_id = ?1 AND id = ?2 AND deleted = 0
              AND (SELECT deleted FROM certificate_authorities WHERE id = ?1) = 0
            "#,
            params![ca_id, cert_id],
            |row| {
                Ok(CertSecrets {
                    cert_pem: row.get(0)?,
                    key_pem: row.get(1)?,
                    csr_pem: row.get(2)?,
                    pkcs12: row.get(3)?,
                    password: row.get(4)?,
                    bundle_zip: row.get(5)?,
                })
            },
        )
        .optional()?
        .with_context(|| format!("certificate not found: {ca_id}/{cert_id}"))
    }

    pub fn delete_cert(&self, ca_id: &str, cert_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let now = Utc::now().timestamp_millis();
        let count = conn.execute(
            "UPDATE certificates SET deleted = 1, updated_at = ? WHERE ca_id = ? AND id = ? AND deleted = 0",
            params![now, ca_id, cert_id],
        )?;
        if count == 0 {
            bail!("certificate not found: {ca_id}/{cert_id}");
        }
        tracing::info!(ca_id = %ca_id, cert_id = %cert_id, rows_affected = count, "soft-deleted certificate");
        Ok(())
    }

    pub fn restore_cert(&self, ca_id: &str, cert_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let now = Utc::now().timestamp_millis();
        let count = conn.execute(
            "UPDATE certificates SET deleted = 0, updated_at = ? WHERE ca_id = ? AND id = ? AND deleted = 1",
            params![now, ca_id, cert_id],
        )?;
        if count == 0 {
            bail!("deleted certificate not found: {ca_id}/{cert_id}");
        }
        tracing::info!(ca_id = %ca_id, cert_id = %cert_id, rows_affected = count, "restored certificate");
        Ok(())
    }

    /// Lists soft-deleted certificates across all CAs for the admin console.
    pub fn list_deleted_certs(&self) -> Result<Vec<Certificate>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            r#"
            SELECT id, ca_id, common_name, country_code, state, city, organization, organization_unit,
                   subject, issue_time, valid_days, dns_list, ip_list, key_profile, digest_algorithm,
                   cert_pem, key_pem, revoked_at, revocation_reason
            FROM certificates
            WHERE deleted = 1
            ORDER BY updated_at DESC
            "#,
        )?;
        let rows = stmt.query_map([], row_to_cert)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn acquire_ca_lock(&self, ca_id: &str, owner_id: &str, ttl_ms: i64) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let expires = now + ttl_ms;
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        let tx = conn.transaction()?;
        let expired_rows = tx.execute("DELETE FROM ca_locks WHERE expires_at < ?", params![now])?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT owner_id FROM ca_locks WHERE ca_id = ?",
                params![ca_id],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_some() {
            tracing::warn!(ca_id = %ca_id, "certificate authority signing lock is busy");
            bail!("CA is busy; retry shortly");
        }
        tx.execute(
            "INSERT INTO ca_locks(ca_id, owner_id, locked_at, expires_at) VALUES (?, ?, ?, ?)",
            params![ca_id, owner_id, now, expires],
        )?;
        tx.commit()?;
        tracing::debug!(ca_id = %ca_id, owner_id = %owner_id, ttl_ms, expired_lock_rows = expired_rows, rows_affected = 1, "acquired certificate authority signing lock");
        Ok(())
    }

    pub fn release_ca_lock(&self, ca_id: &str, owner_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let removed = conn.execute(
            "DELETE FROM ca_locks WHERE ca_id = ? AND owner_id = ?",
            params![ca_id, owner_id],
        )?;
        tracing::debug!(ca_id = %ca_id, owner_id = %owner_id, rows_affected = removed, "released certificate authority signing lock");
        Ok(())
    }

    pub fn insert_user(
        &self,
        id: &str,
        username: &str,
        password_hash: &str,
        role: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let now = Utc::now().timestamp_millis();
        let rows = conn.execute(
            "INSERT INTO users(id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            params![id, username, password_hash, role, now],
        )
        .map_err(|err| {
            if err.to_string().contains("UNIQUE") {
                anyhow::anyhow!("username already exists: {username}")
            } else {
                err.into()
            }
        })?;
        tracing::info!(user_id = %id, username = %username, role = %role, rows_affected = rows, "created user");
        Ok(())
    }

    pub fn list_users(&self) -> Result<Vec<UserRecord>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, username, password_hash, role, created_at FROM users ORDER BY username",
        )?;
        let rows = stmt.query_map([], row_to_user)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn find_user(&self, username: &str) -> Result<Option<UserRecord>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.query_row(
            "SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?",
            params![username],
            row_to_user,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn delete_user(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let count = conn.execute("DELETE FROM users WHERE id = ?", params![id])?;
        if count == 0 {
            bail!("user not found: {id}");
        }
        tracing::info!(user_id = %id, rows_affected = count, "deleted user");
        Ok(())
    }
}

fn row_to_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserRecord> {
    Ok(UserRecord {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        role: row.get(3)?,
        created_at: row.get(4)?,
    })
}

fn schema_is_current(conn: &Connection) -> Result<bool> {
    let version = schema_version(conn)?;
    if let Some(version) = version {
        if version > SCHEMA_VERSION {
            bail!("database schema version {version} is newer than supported {SCHEMA_VERSION}");
        }
    }

    let required = [
        (
            "certificate_authorities",
            &[
                "id",
                "common_name",
                "country_code",
                "state",
                "city",
                "organization",
                "organization_unit",
                "subject",
                "issue_time",
                "valid_days",
                "key_profile",
                "digest_algorithm",
                "cert_pem",
                "key_pem",
                "pkcs12",
                "password",
                "index_txt",
                "serial_txt",
                "crl_der",
                "crl_updated_at",
                "deleted",
                "created_at",
                "updated_at",
            ][..],
        ),
        (
            "certificates",
            &[
                "id",
                "ca_id",
                "common_name",
                "country_code",
                "state",
                "city",
                "organization",
                "organization_unit",
                "subject",
                "issue_time",
                "valid_days",
                "dns_list",
                "ip_list",
                "key_profile",
                "digest_algorithm",
                "cert_pem",
                "key_pem",
                "csr_pem",
                "pkcs12",
                "password",
                "bundle_zip",
                "revoked_at",
                "revocation_reason",
                "deleted",
                "created_at",
                "updated_at",
            ][..],
        ),
        (
            "ca_locks",
            &["ca_id", "owner_id", "locked_at", "expires_at"][..],
        ),
        (
            "users",
            &["id", "username", "password_hash", "role", "created_at"][..],
        ),
    ];

    for (table, columns) in required {
        if !table_exists(conn, table)? {
            return Ok(false);
        }
        let existing = table_columns(conn, table)?;
        if columns
            .iter()
            .any(|column| !existing.iter().any(|name| name == column))
        {
            return Ok(false);
        }
    }

    Ok(version == Some(SCHEMA_VERSION))
}

fn schema_version(conn: &Connection) -> Result<Option<u32>> {
    if !table_exists(conn, "schema_version")? {
        return Ok(None);
    }
    conn.query_row("SELECT max(version) FROM schema_version", [], |row| {
        row.get::<_, Option<u32>>(0)
    })
    .map_err(Into::into)
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
        params![table],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get(1))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn copy_db_backup(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("db.sqlite");
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let suffix: String = rand::rng()
        .sample_iter(Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let backup = parent.join(format!("{name}.pre-migrate-{stamp}-{suffix}.bak"));
    fs::copy(path, &backup)
        .with_context(|| format!("failed to create migration backup {}", backup.display()))?;
    tracing::info!(
        db_path = %path.display(),
        backup_path = %backup.display(),
        "created pre-migration sqlite backup"
    );
    Ok(backup)
}

fn verify_lock_tx(tx: &rusqlite::Transaction<'_>, ca_id: &str, owner_id: &str) -> Result<()> {
    let ok: Option<String> = tx
        .query_row(
            "SELECT owner_id FROM ca_locks WHERE ca_id = ? AND owner_id = ?",
            params![ca_id, owner_id],
            |row| row.get(0),
        )
        .optional()?;
    if ok.is_none() {
        bail!("lost CA signing lock");
    }
    Ok(())
}

fn row_to_cert(row: &rusqlite::Row<'_>) -> rusqlite::Result<Certificate> {
    let dns: String = row.get(11)?;
    let ips: String = row.get(12)?;
    Ok(Certificate {
        id: row.get(0)?,
        ca_id: row.get(1)?,
        common_name: row.get(2)?,
        country_code: row.get(3)?,
        state: row.get(4)?,
        city: row.get(5)?,
        organization: row.get(6)?,
        organization_unit: row.get(7)?,
        subject: row.get(8)?,
        issue_time: row.get(9)?,
        valid_days: row.get(10)?,
        dns_list: split_list(&dns),
        ip_list: split_list(&ips),
        key_profile: row.get(13)?,
        digest_algorithm: row.get(14)?,
        cert_pem: blob_string(row.get(15)?),
        key_pem: blob_string(row.get(16)?),
        revoked_at: row.get(17)?,
        revocation_reason: row.get(18)?,
    })
}

fn split_list(input: &str) -> Vec<String> {
    input
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn blob_string(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> Db {
        let suffix: String = rand::rng()
            .sample_iter(Alphanumeric)
            .take(12)
            .map(char::from)
            .collect();
        let dir = std::env::temp_dir().join(format!("minica-db-test-{suffix}"));
        Db::open(&dir.join("test.sqlite")).expect("open temp db")
    }

    fn sample_ca(id: &str, common_name: &str) -> (CaMeta, CaSecrets) {
        (
            CaMeta {
                id: id.to_string(),
                common_name: common_name.to_string(),
                country_code: "SG".to_string(),
                state: "SG".to_string(),
                city: "SG".to_string(),
                organization: "Org".to_string(),
                organization_unit: "Unit".to_string(),
                subject: format!("CN={common_name}"),
                issue_time: 0,
                valid_days: 365,
                key_profile: "rsa:2048".to_string(),
                digest_algorithm: "sha256".to_string(),
            },
            CaSecrets {
                cert_pem: Vec::new(),
                key_pem: Vec::new(),
                pkcs12: Vec::new(),
                password: Vec::new(),
                index_txt: Vec::new(),
                serial_txt: Vec::new(),
                crl_der: Vec::new(),
                crl_updated_at: 0,
            },
        )
    }

    fn sample_cert(id: &str, ca_id: &str, common_name: &str) -> (CertMeta, CertSecrets) {
        (
            CertMeta {
                id: id.to_string(),
                ca_id: ca_id.to_string(),
                common_name: common_name.to_string(),
                country_code: "SG".to_string(),
                state: "SG".to_string(),
                city: "SG".to_string(),
                organization: "Org".to_string(),
                organization_unit: "Unit".to_string(),
                subject: format!("CN={common_name}"),
                issue_time: 0,
                valid_days: 365,
                dns_list: Vec::new(),
                ip_list: Vec::new(),
                key_profile: "rsa:2048".to_string(),
                digest_algorithm: "sha256".to_string(),
                revoked_at: None,
                revocation_reason: None,
            },
            CertSecrets {
                cert_pem: Vec::new(),
                key_pem: Vec::new(),
                csr_pem: Vec::new(),
                pkcs12: Vec::new(),
                password: Vec::new(),
                bundle_zip: Vec::new(),
            },
        )
    }

    fn insert_ca(db: &Db, id: &str, common_name: &str) {
        let (meta, secrets) = sample_ca(id, common_name);
        db.insert_ca(&meta, &secrets).expect("insert ca");
    }

    fn insert_cert(db: &Db, id: &str, ca_id: &str, common_name: &str) {
        let (meta, secrets) = sample_cert(id, ca_id, common_name);
        db.insert_cert_restore(&meta, &secrets)
            .expect("insert cert");
    }

    #[test]
    fn cert_common_name_is_unique_within_ca_not_across_cas() {
        let db = temp_db();
        insert_ca(&db, "ca1", "CA One");
        insert_ca(&db, "ca2", "CA Two");
        insert_cert(&db, "cert1", "ca1", "web");

        assert!(db.cert_common_name_exists("ca1", "web").unwrap());
        // Different CA: the same cert CN is allowed.
        assert!(!db.cert_common_name_exists("ca2", "web").unwrap());
        // Same CA, case- and whitespace-insensitive.
        assert!(db.cert_common_name_exists("ca1", "  WEB ").unwrap());
        assert!(!db.cert_common_name_exists("ca1", "other").unwrap());
    }

    #[test]
    fn deleted_cert_does_not_count_for_uniqueness() {
        let db = temp_db();
        insert_ca(&db, "ca1", "CA One");
        insert_cert(&db, "cert1", "ca1", "web");
        db.delete_cert("ca1", "cert1").unwrap();

        assert!(!db.cert_common_name_exists("ca1", "web").unwrap());
    }

    #[test]
    fn ca_common_name_is_unique_among_cas_only() {
        let db = temp_db();
        insert_ca(&db, "ca1", "Root CA");
        insert_cert(&db, "cert1", "ca1", "shared");

        assert!(db.ca_common_name_exists("root ca").unwrap());
        assert!(!db.ca_common_name_exists("Other CA").unwrap());
        // A cert CN must not register as a CA CN.
        assert!(!db.ca_common_name_exists("shared").unwrap());
    }

    #[test]
    fn find_cert_id_by_cn_returns_matching_id() {
        let db = temp_db();
        insert_ca(&db, "ca1", "CA One");
        insert_ca(&db, "ca2", "CA Two");
        insert_cert(&db, "cert1", "ca1", "web");

        assert_eq!(
            db.find_cert_id_by_cn("ca1", "web").unwrap().as_deref(),
            Some("cert1")
        );
        // Case- and whitespace-insensitive.
        assert_eq!(
            db.find_cert_id_by_cn("ca1", " WEB ").unwrap().as_deref(),
            Some("cert1")
        );
        // Scoped to the CA: a match under a different CA is not found here.
        assert_eq!(db.find_cert_id_by_cn("ca2", "web").unwrap(), None);
        assert_eq!(db.find_cert_id_by_cn("ca1", "nope").unwrap(), None);
    }

    #[test]
    fn find_cert_id_by_cn_skips_deleted_cert() {
        let db = temp_db();
        insert_ca(&db, "ca1", "CA One");
        insert_cert(&db, "cert1", "ca1", "web");
        db.delete_cert("ca1", "cert1").unwrap();

        assert_eq!(db.find_cert_id_by_cn("ca1", "web").unwrap(), None);
    }
}
