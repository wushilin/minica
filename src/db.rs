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

pub const SCHEMA_VERSION: u32 = 2;

/// How many `.pre-migrate-*.bak` copies of the database to keep. Each holds
/// every private key, so older ones are pruned after a new one is made.
const MAX_MIGRATION_BACKUPS: usize = 3;

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
    /// openssl `crlnumber` file contents; empty for CAs created before CRL
    /// numbering (the openssl layer then starts at 1).
    pub crlnumber_txt: Vec<u8>,
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

/// A full logical copy of the database, as exported to / restored from a
/// backup file.
#[derive(Clone, Default)]
pub struct BackupSnapshot {
    pub users: Vec<UserRecord>,
    pub cas: Vec<(BackupCaRow, Vec<BackupCertRow>)>,
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
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty() && !parent.exists())
        {
            create_private_dir_all(parent)
                .with_context(|| format!("failed to create db folder {}", parent.display()))?;
        }
        let db_existed = path.exists();
        if db_existed {
            // The database holds every private key; tighten an existing file
            // left with umask permissions, but don't refuse to start if we
            // can't (e.g. the file belongs to another user).
            restrict_permissions(path);
        } else {
            create_private_file(path)
                .with_context(|| format!("failed to create sqlite db {}", path.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open sqlite db {}", path.display()))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Another process (e.g. `minica --import-legacy` beside a running
        // server) may hold a write lock briefly; wait instead of failing.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
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
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        // One transaction: a migration that fails part-way leaves the schema
        // exactly as it was (SQLite DDL is transactional).
        let tx = conn.transaction()?;
        tx.execute_batch(
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
                crlnumber_txt BLOB NOT NULL DEFAULT X'',
                truststore BLOB NOT NULL DEFAULT X'',
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
        // Add columns to databases created before they existed. Only the
        // "duplicate column" error (column already present) is tolerated.
        for sql in [
            "ALTER TABLE certificate_authorities ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE certificates ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE certificate_authorities ADD COLUMN key_profile TEXT NOT NULL DEFAULT 'rsa:4096'",
            "ALTER TABLE certificates ADD COLUMN key_profile TEXT NOT NULL DEFAULT 'rsa:4096'",
            "ALTER TABLE certificate_authorities ADD COLUMN crl_der BLOB NOT NULL DEFAULT X''",
            "ALTER TABLE certificate_authorities ADD COLUMN crl_updated_at INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE certificate_authorities ADD COLUMN crlnumber_txt BLOB NOT NULL DEFAULT X''",
            "ALTER TABLE certificates ADD COLUMN revoked_at INTEGER",
            "ALTER TABLE certificates ADD COLUMN revocation_reason TEXT",
            "ALTER TABLE certificate_authorities ADD COLUMN truststore BLOB NOT NULL DEFAULT X''",
            // Schema 2: rows whose metadata was re-derived from the certificate
            // (see AppService::repair_stale_metadata) carry 1; 0 means unchecked.
            "ALTER TABLE certificate_authorities ADD COLUMN meta_version INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE certificates ADD COLUMN meta_version INTEGER NOT NULL DEFAULT 0",
        ] {
            add_column(&tx, sql)?;
        }
        if !schema_columns_present(&tx)? {
            bail!("database schema is still incomplete after migration");
        }
        tx.execute("DELETE FROM schema_version", [])?;
        tx.execute(
            "INSERT INTO schema_version(version) VALUES (?)",
            params![SCHEMA_VERSION],
        )?;
        tx.commit()?;
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
                cert_pem, key_pem, pkcs12, password, index_txt, serial_txt, crl_der, crl_updated_at,
                crlnumber_txt, created_at, updated_at, meta_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
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
                secrets.crlnumber_txt,
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
            LEFT JOIN certificates c ON c.ca_id = ca.id AND c.deleted = 0
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
            "UPDATE certificate_authorities SET key_profile = ?, digest_algorithm = ?, updated_at = ? WHERE id = ? AND deleted = 0",
            params![key_profile, digest_algorithm, now, id],
        )?;
        if count == 0 {
            bail!("CA not found: {id}");
        }
        tracing::info!(ca_id = %id, rows_affected = count, "updated certificate authority metadata");
        Ok(())
    }

    pub fn ca_exists(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM certificate_authorities WHERE id = ?",
            params![id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn cert_exists(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM certificates WHERE id = ?",
            params![id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Metadata and certificate of every CA (deleted ones too) not yet checked
    /// by the metadata repair.
    pub fn list_cas_for_repair(&self) -> Result<Vec<(CaMeta, Vec<u8>)>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            r#"
            SELECT id, common_name, country_code, state, city, organization, organization_unit,
                   subject, issue_time, valid_days, key_profile, digest_algorithm, cert_pem
            FROM certificate_authorities
            WHERE meta_version = 0
            ORDER BY created_at
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                CaMeta {
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
                row.get(12)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Certificate counterpart of `list_cas_for_repair`.
    pub fn list_certs_for_repair(&self) -> Result<Vec<(CertMeta, Vec<u8>)>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            r#"
            SELECT id, ca_id, common_name, country_code, state, city, organization, organization_unit,
                   subject, issue_time, valid_days, dns_list, ip_list, key_profile, digest_algorithm,
                   revoked_at, revocation_reason, cert_pem
            FROM certificates
            WHERE meta_version = 0
            ORDER BY created_at
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                CertMeta {
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
                    dns_list: split_list(&row.get::<_, String>(11)?),
                    ip_list: split_list(&row.get::<_, String>(12)?),
                    key_profile: row.get(13)?,
                    digest_algorithm: row.get(14)?,
                    revoked_at: row.get(15)?,
                    revocation_reason: row.get(16)?,
                },
                row.get(17)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Writes re-derived subject/validity metadata and marks the row checked.
    pub fn update_ca_meta_repaired(&self, meta: &CaMeta) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            r#"
            UPDATE certificate_authorities
            SET country_code = ?, state = ?, city = ?, organization = ?, organization_unit = ?,
                subject = ?, issue_time = ?, valid_days = ?, meta_version = 1
            WHERE id = ?
            "#,
            params![
                meta.country_code,
                meta.state,
                meta.city,
                meta.organization,
                meta.organization_unit,
                meta.subject,
                meta.issue_time,
                meta.valid_days,
                meta.id
            ],
        )?;
        Ok(())
    }

    pub fn update_cert_meta_repaired(&self, meta: &CertMeta) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            r#"
            UPDATE certificates
            SET country_code = ?, state = ?, city = ?, organization = ?, organization_unit = ?,
                subject = ?, meta_version = 1
            WHERE id = ?
            "#,
            params![
                meta.country_code,
                meta.state,
                meta.city,
                meta.organization,
                meta.organization_unit,
                meta.subject,
                meta.id
            ],
        )?;
        Ok(())
    }

    pub fn mark_ca_meta_checked(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "UPDATE certificate_authorities SET meta_version = 1 WHERE id = ?",
            params![id],
        )?;
        Ok(())
    }

    pub fn mark_cert_meta_checked(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "UPDATE certificates SET meta_version = 1 WHERE id = ?",
            params![id],
        )?;
        Ok(())
    }

    /// Test hook: rewrites a CA's metadata the way older versions stored an
    /// import (fabricated subject parts, "now + 3650 days") and marks the row
    /// unchecked, so the repair can be exercised.
    #[cfg(test)]
    pub fn fake_legacy_ca_meta(
        &self,
        id: &str,
        country_code: &str,
        organization: &str,
        subject: &str,
        issue_time: i64,
        valid_days: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            r#"
            UPDATE certificate_authorities
            SET country_code = ?, organization = ?, subject = ?, issue_time = ?, valid_days = ?,
                meta_version = 0
            WHERE id = ?
            "#,
            params![country_code, organization, subject, issue_time, valid_days, id],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn fake_legacy_cert_meta(
        &self,
        id: &str,
        country_code: &str,
        organization: &str,
        subject: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "UPDATE certificates SET country_code = ?, organization = ?, subject = ?, meta_version = 0 WHERE id = ?",
            params![country_code, organization, subject, id],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn meta_versions(&self) -> Result<(Vec<i64>, Vec<i64>)> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut cas = conn.prepare("SELECT meta_version FROM certificate_authorities")?;
        let cas = cas
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<i64>>>()?;
        let mut certs = conn.prepare("SELECT meta_version FROM certificates")?;
        let certs = certs
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<i64>>>()?;
        Ok((cas, certs))
    }

    pub fn get_ca_secrets(&self, id: &str) -> Result<CaSecrets> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.query_row(
            r#"
            SELECT cert_pem, key_pem, pkcs12, password, index_txt, serial_txt, crl_der, crl_updated_at,
                   crlnumber_txt
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
                    crlnumber_txt: row.get(8)?,
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

    /// Restores a soft-deleted CA, refusing if an active CA has since taken its
    /// common name (checked in the same transaction as the update).
    pub fn restore_ca(&self, id: &str) -> Result<()> {
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        let tx = conn.transaction()?;
        let now = Utc::now().timestamp_millis();
        let common_name: String = tx
            .query_row(
                "SELECT common_name FROM certificate_authorities WHERE id = ? AND deleted = 1",
                params![id],
                |row| row.get(0),
            )
            .optional()?
            .with_context(|| format!("deleted CA not found: {id}"))?;
        let clashes: i64 = tx.query_row(
            "SELECT COUNT(*) FROM certificate_authorities WHERE deleted = 0 AND lower(trim(common_name)) = lower(trim(?1))",
            params![common_name],
            |row| row.get(0),
        )?;
        if clashes > 0 {
            bail!(
                "cannot restore CA: an active CA already uses the common name {}",
                common_name.trim()
            );
        }
        let count = tx.execute(
            "UPDATE certificate_authorities SET deleted = 0, updated_at = ? WHERE id = ? AND deleted = 1",
            params![now, id],
        )?;
        tx.commit()?;
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

    /// Inserts a certificate under the CA signing lock. `ca_state` is the new
    /// (index.txt, serial.txt) pair to persist, or `None` when the operation
    /// (an import) did not touch the CA's openssl state.
    pub fn insert_cert_with_state(
        &self,
        meta: &CertMeta,
        secrets: &CertSecrets,
        ca_state: Option<(&[u8], &[u8])>,
        lock_owner: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        let tx = conn.transaction()?;
        verify_lock_tx(&tx, &meta.ca_id, lock_owner)?;
        let ca_rows = match ca_state {
            Some((index_txt, serial_txt)) => tx.execute(
                "UPDATE certificate_authorities SET index_txt = ?, serial_txt = ?, updated_at = ? WHERE id = ? AND deleted = 0",
                params![index_txt, serial_txt, now, meta.ca_id],
            )?,
            None => tx.execute(
                "UPDATE certificate_authorities SET updated_at = ? WHERE id = ? AND deleted = 0",
                params![now, meta.ca_id],
            )?,
        };
        if ca_rows == 0 {
            bail!("CA not found: {}", meta.ca_id);
        }
        let cert_rows = tx.execute(
            r#"
            INSERT INTO certificates (
                id, ca_id, common_name, country_code, state, city, organization, organization_unit,
                subject, issue_time, valid_days, dns_list, ip_list, key_profile, digest_algorithm,
                cert_pem, key_pem, csr_pem, pkcs12, password, bundle_zip, created_at, updated_at, meta_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
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

    /// Reads users, CAs and each CA's certificates as one consistent snapshot:
    /// a single lock acquisition and a single read transaction, so a
    /// concurrent issue/revoke cannot leave the backup half-updated.
    pub fn backup_snapshot(&self) -> Result<BackupSnapshot> {
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        let tx = conn.transaction()?;
        let users = query_users(&tx)?;
        let mut cas = Vec::new();
        for ca in query_backup_cas(&tx)? {
            let certs = query_backup_certs(&tx, &ca.meta.id)?;
            cas.push((ca, certs));
        }
        tx.commit()?;
        Ok(BackupSnapshot { users, cas })
    }

    /// Restores a whole backup atomically: the emptiness check and every insert
    /// run in one transaction under one lock acquisition, so a failure part-way
    /// leaves the database empty rather than half-restored.
    pub fn restore_backup(&self, snapshot: &BackupSnapshot) -> Result<()> {
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        let tx = conn.transaction()?;
        if !is_empty_conn(&tx)? {
            bail!("backup restore requires an empty database");
        }
        for user in &snapshot.users {
            insert_user_row(&tx, user)?;
        }
        for (ca, certs) in &snapshot.cas {
            insert_ca_row(&tx, ca)?;
            for cert in certs {
                if cert.meta.ca_id != ca.meta.id {
                    bail!(
                        "backup certificate {} does not belong to CA {}",
                        cert.meta.id,
                        ca.meta.id
                    );
                }
                insert_cert_row(&tx, cert)?;
            }
        }
        tx.commit()?;
        tracing::info!(
            user_count = snapshot.users.len(),
            ca_count = snapshot.cas.len(),
            cert_count = snapshot
                .cas
                .iter()
                .map(|(_, certs)| certs.len())
                .sum::<usize>(),
            "restored backup in one transaction"
        );
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
        is_empty_conn(&conn)
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
            // Never touches revocation: a revoked certificate stays revoked
            // and is not renewable (its key may be compromised).
            r#"
            UPDATE certificates
            SET cert_pem = ?, pkcs12 = ?, bundle_zip = ?, issue_time = ?, valid_days = ?, updated_at = ?
            WHERE id = ? AND ca_id = ? AND deleted = 0 AND revoked_at IS NULL
            "#,
            params![cert_pem, pkcs12, bundle_zip, issue_time, valid_days, now, cert_id, ca_id],
        )?;
        if cert_rows == 0 {
            bail!("certificate not found or revoked: {ca_id}/{cert_id}");
        }
        let ca_rows = tx.execute(
            "UPDATE certificate_authorities SET index_txt = ?, serial_txt = ?, updated_at = ? WHERE id = ? AND deleted = 0",
            params![ca_state.0, ca_state.1, now, ca_id],
        )?;
        if ca_rows == 0 {
            bail!("CA not found: {ca_id}");
        }
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
        crl: (&[u8], &[u8]),
        lock_owner: &str,
    ) -> Result<()> {
        let (crl_der, crlnumber_txt) = crl;
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
            "UPDATE certificate_authorities SET index_txt = ?, serial_txt = ?, crl_der = ?, crlnumber_txt = ?, crl_updated_at = ?, updated_at = ? WHERE id = ? AND deleted = 0",
            params![ca_state.0, ca_state.1, crl_der, crlnumber_txt, now, now, ca_id],
        )?;
        if ca_rows == 0 {
            bail!("CA not found: {ca_id}");
        }
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

    /// Every certificate stored under a CA (soft-deleted ones too, since they
    /// can be restored), with its secrets. Used to rebuild artifacts that embed
    /// the CA certificate.
    pub fn list_cert_secrets_for_ca(&self, ca_id: &str) -> Result<Vec<(String, CertSecrets)>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            r#"
            SELECT id, cert_pem, key_pem, csr_pem, pkcs12, password, bundle_zip
            FROM certificates
            WHERE ca_id = ?
            ORDER BY id
            "#,
        )?;
        let rows = stmt.query_map(params![ca_id], |row| {
            Ok((
                row.get(0)?,
                CertSecrets {
                    cert_pem: row.get(1)?,
                    key_pem: row.get(2)?,
                    csr_pem: row.get(3)?,
                    pkcs12: row.get(4)?,
                    password: row.get(5)?,
                    bundle_zip: row.get(6)?,
                },
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Persists a renewed CA certificate: the new certificate and PKCS12, its
    /// validity metadata, the refreshed CRL (when CRLs are enabled) and the
    /// rebuilt bundles of its certificates, then releases the signing lock —
    /// all in one transaction. The stored truststore holds the old
    /// certificate, so it is cleared for the service to rebuild.
    #[allow(clippy::too_many_arguments)]
    pub fn renew_ca_with_state(
        &self,
        ca_id: &str,
        cert_pem: &[u8],
        pkcs12: &[u8],
        issue_time: i64,
        valid_days: i64,
        crl: Option<(&[u8], &[u8])>,
        cert_bundles: &[(String, Vec<u8>)],
        lock_owner: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        let tx = conn.transaction()?;
        verify_lock_tx(&tx, ca_id, lock_owner)?;
        let ca_rows = tx.execute(
            r#"
            UPDATE certificate_authorities
            SET cert_pem = ?, pkcs12 = ?, truststore = X'', issue_time = ?, valid_days = ?, updated_at = ?
            WHERE id = ? AND deleted = 0
            "#,
            params![cert_pem, pkcs12, issue_time, valid_days, now, ca_id],
        )?;
        if ca_rows == 0 {
            bail!("CA not found: {ca_id}");
        }
        if let Some((crl_der, crlnumber_txt)) = crl {
            tx.execute(
                "UPDATE certificate_authorities SET crl_der = ?, crlnumber_txt = ?, crl_updated_at = ? WHERE id = ?",
                params![crl_der, crlnumber_txt, now, ca_id],
            )?;
        }
        let mut bundle_rows = 0;
        for (cert_id, bundle_zip) in cert_bundles {
            bundle_rows += tx.execute(
                "UPDATE certificates SET bundle_zip = ?, updated_at = ? WHERE id = ? AND ca_id = ?",
                params![bundle_zip, now, cert_id, ca_id],
            )?;
        }
        let lock_rows = tx.execute(
            "DELETE FROM ca_locks WHERE ca_id = ? AND owner_id = ?",
            params![ca_id, lock_owner],
        )?;
        tx.commit()?;
        tracing::info!(
            ca_id = %ca_id,
            valid_days,
            ca_rows_affected = ca_rows,
            bundle_rows_affected = bundle_rows,
            lock_rows_affected = lock_rows,
            crl_refreshed = crl.is_some(),
            "renewed certificate authority certificate"
        );
        Ok(())
    }

    /// The stored PKCS#12 truststore; empty when it has not been built yet
    /// (CAs from before truststores existed, restored backups, renewals).
    pub fn get_ca_truststore(&self, ca_id: &str) -> Result<Vec<u8>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.query_row(
            "SELECT truststore FROM certificate_authorities WHERE id = ? AND deleted = 0",
            params![ca_id],
            |row| row.get(0),
        )
        .optional()?
        .with_context(|| format!("CA not found: {ca_id}"))
    }

    /// Stores a truststore built from `cert_pem`, only while that is still the
    /// CA's certificate, so one built just before a renewal is dropped.
    pub fn set_ca_truststore(&self, ca_id: &str, cert_pem: &[u8], truststore: &[u8]) -> Result<bool> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let rows = conn.execute(
            "UPDATE certificate_authorities SET truststore = ? WHERE id = ? AND cert_pem = ? AND deleted = 0",
            params![truststore, ca_id, cert_pem],
        )?;
        Ok(rows > 0)
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

    /// Restores a soft-deleted certificate. Refused while its CA is deleted, or
    /// when an active certificate under the same CA has since taken its common
    /// name; both checks run in the same transaction as the update.
    pub fn restore_cert(&self, ca_id: &str, cert_id: &str) -> Result<()> {
        let mut conn = self.conn.lock().expect("db mutex poisoned");
        let tx = conn.transaction()?;
        let now = Utc::now().timestamp_millis();
        let common_name: String = tx
            .query_row(
                "SELECT common_name FROM certificates WHERE ca_id = ? AND id = ? AND deleted = 1",
                params![ca_id, cert_id],
                |row| row.get(0),
            )
            .optional()?
            .with_context(|| format!("deleted certificate not found: {ca_id}/{cert_id}"))?;
        let ca_deleted: Option<i64> = tx
            .query_row(
                "SELECT deleted FROM certificate_authorities WHERE id = ?",
                params![ca_id],
                |row| row.get(0),
            )
            .optional()?;
        if ca_deleted != Some(0) {
            bail!("cannot restore certificate: its CA is deleted; restore the CA first");
        }
        let clashes: i64 = tx.query_row(
            "SELECT COUNT(*) FROM certificates WHERE deleted = 0 AND ca_id = ?1 AND lower(trim(common_name)) = lower(trim(?2))",
            params![ca_id, common_name],
            |row| row.get(0),
        )?;
        if clashes > 0 {
            bail!(
                "cannot restore certificate: an active certificate in this CA already uses the common name {}",
                common_name.trim()
            );
        }
        let count = tx.execute(
            "UPDATE certificates SET deleted = 0, updated_at = ? WHERE ca_id = ? AND id = ? AND deleted = 1",
            params![now, ca_id, cert_id],
        )?;
        tx.commit()?;
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
        query_users(&conn)
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

fn query_users(conn: &Connection) -> Result<Vec<UserRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, username, password_hash, role, created_at FROM users ORDER BY username",
    )?;
    let rows = stmt.query_map([], row_to_user)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn query_backup_cas(conn: &Connection) -> Result<Vec<BackupCaRow>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, common_name, country_code, state, city, organization, organization_unit,
               subject, issue_time, valid_days, key_profile, digest_algorithm,
               cert_pem, key_pem, pkcs12, password, index_txt, serial_txt, crl_der, crl_updated_at,
               deleted, created_at, updated_at, crlnumber_txt
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
                crlnumber_txt: row.get(23)?,
            },
            deleted: row.get::<_, i64>(20)? != 0,
            created_at: row.get(21)?,
            updated_at: row.get(22)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn query_backup_certs(conn: &Connection, ca_id: &str) -> Result<Vec<BackupCertRow>> {
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

fn is_empty_conn(conn: &Connection) -> Result<bool> {
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

/// Zero timestamps (older backups) become "now" / created_at respectively.
fn restore_timestamps(created_at: i64, updated_at: i64) -> (i64, i64) {
    let created_at = if created_at == 0 {
        Utc::now().timestamp_millis()
    } else {
        created_at
    };
    let updated_at = if updated_at == 0 {
        created_at
    } else {
        updated_at
    };
    (created_at, updated_at)
}

fn insert_user_row(conn: &Connection, user: &UserRecord) -> Result<()> {
    let (created_at, _) = restore_timestamps(user.created_at, 0);
    conn.execute(
        "INSERT INTO users(id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
        params![
            user.id,
            user.username,
            user.password_hash,
            user.role,
            created_at
        ],
    )
    .with_context(|| format!("failed to restore user {}", user.username))?;
    tracing::info!(user_id = %user.id, username = %user.username, role = %user.role, "restored user from backup");
    Ok(())
}

fn insert_ca_row(conn: &Connection, ca: &BackupCaRow) -> Result<()> {
    let (created_at, updated_at) = restore_timestamps(ca.created_at, ca.updated_at);
    let (meta, secrets) = (&ca.meta, &ca.secrets);
    conn.execute(
        r#"
        INSERT INTO certificate_authorities (
            id, common_name, country_code, state, city, organization, organization_unit,
            subject, issue_time, valid_days, key_profile, digest_algorithm,
            cert_pem, key_pem, pkcs12, password, index_txt, serial_txt, crl_der, crl_updated_at,
            crlnumber_txt, deleted, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            secrets.crlnumber_txt,
            if ca.deleted { 1 } else { 0 },
            created_at,
            updated_at
        ],
    )
    .with_context(|| format!("failed to restore CA {}", meta.id))?;
    tracing::info!(ca_id = %meta.id, deleted = ca.deleted, "restored certificate authority from backup");
    Ok(())
}

fn insert_cert_row(conn: &Connection, cert: &BackupCertRow) -> Result<()> {
    let (created_at, updated_at) = restore_timestamps(cert.created_at, cert.updated_at);
    let (meta, secrets) = (&cert.meta, &cert.secrets);
    conn.execute(
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
            if cert.deleted { 1 } else { 0 },
            cert.revoked_at,
            cert.revocation_reason,
            created_at,
            updated_at
        ],
    )
    .with_context(|| format!("failed to restore certificate {}", meta.id))?;
    tracing::info!(
        ca_id = %meta.ca_id,
        cert_id = %meta.id,
        deleted = cert.deleted,
        "restored certificate from backup"
    );
    Ok(())
}

/// Runs an `ALTER TABLE ... ADD COLUMN`, tolerating only the error SQLite
/// raises when the column already exists. Anything else aborts the migration.
fn add_column(conn: &Connection, sql: &str) -> Result<()> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(err) if err.to_string().contains("duplicate column name") => Ok(()),
        Err(err) => Err(err).with_context(|| format!("migration step failed: {sql}")),
    }
}

fn schema_is_current(conn: &Connection) -> Result<bool> {
    let version = schema_version(conn)?;
    if let Some(version) = version {
        if version > SCHEMA_VERSION {
            bail!("database schema version {version} is newer than supported {SCHEMA_VERSION}");
        }
    }
    if !schema_columns_present(conn)? {
        return Ok(false);
    }
    Ok(version == Some(SCHEMA_VERSION))
}

/// True when every required table has every required column.
fn schema_columns_present(conn: &Connection) -> Result<bool> {
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
                "crlnumber_txt",
                "truststore",
                "deleted",
                "created_at",
                "updated_at",
                "meta_version",
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
                "meta_version",
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
    Ok(true)
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
    // fs::copy carries over the source mode; the copy holds the same private
    // keys, so make sure it is owner-only regardless.
    restrict_permissions(&backup);
    tracing::info!(
        db_path = %path.display(),
        backup_path = %backup.display(),
        "created pre-migration sqlite backup"
    );
    prune_migration_backups(parent, name, &backup);
    Ok(backup)
}

/// Deletes all but the newest `MAX_MIGRATION_BACKUPS` pre-migration copies.
/// The timestamp in the file name sorts chronologically. `keep` (the backup
/// just made) is never removed.
fn prune_migration_backups(parent: &Path, name: &str, keep: &Path) {
    let prefix = format!("{name}.pre-migrate-");
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    let mut backups = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|file| file.starts_with(&prefix) && file.ends_with(".bak"))
        })
        .collect::<Vec<_>>();
    backups.sort();
    let excess = backups.len().saturating_sub(MAX_MIGRATION_BACKUPS);
    for old in backups.into_iter().take(excess) {
        if old == keep {
            continue;
        }
        match fs::remove_file(&old) {
            Ok(_) => {
                tracing::info!(backup_path = %old.display(), "pruned old pre-migration sqlite backup")
            }
            Err(err) => tracing::warn!(
                backup_path = %old.display(),
                error = %err,
                "failed to prune old pre-migration sqlite backup"
            ),
        }
    }
}

/// Creates a missing database folder (and parents) owner-only.
fn create_private_dir_all(dir: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Creates an empty (valid) SQLite file with owner-only permissions before
/// SQLite opens it, so it is never created with umask permissions.
fn create_private_file(path: &Path) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map(|_| ())
}

/// Best-effort chmod 0600; logs instead of failing (e.g. not our file).
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(metadata) = fs::metadata(path) else {
            return;
        };
        if metadata.permissions().mode() & 0o077 == 0 {
            return;
        }
        if let Err(err) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "could not restrict database file permissions to 0600"
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
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
                crlnumber_txt: Vec::new(),
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

    #[test]
    fn restore_cert_refuses_duplicate_active_cn_and_deleted_ca() {
        let db = temp_db();
        insert_ca(&db, "ca1", "CA One");
        insert_cert(&db, "old", "ca1", "web");
        db.delete_cert("ca1", "old").unwrap();
        insert_cert(&db, "new", "ca1", " WEB ");
        let err = db.restore_cert("ca1", "old").unwrap_err().to_string();
        assert!(err.contains("already uses the common name"), "{err}");

        db.delete_cert("ca1", "new").unwrap();
        db.delete_ca("ca1").unwrap();
        let err = db.restore_cert("ca1", "old").unwrap_err().to_string();
        assert!(err.contains("CA is deleted"), "{err}");

        db.restore_ca("ca1").unwrap();
        db.restore_cert("ca1", "old").unwrap();
        assert_eq!(
            db.find_cert_id_by_cn("ca1", "web").unwrap().as_deref(),
            Some("old")
        );
    }

    #[test]
    fn restore_ca_refuses_duplicate_active_cn() {
        let db = temp_db();
        insert_ca(&db, "ca1", "Root CA");
        db.delete_ca("ca1").unwrap();
        insert_ca(&db, "ca2", "root ca");
        let err = db.restore_ca("ca1").unwrap_err().to_string();
        assert!(err.contains("already uses the common name"), "{err}");
        assert!(db.get_ca("ca1").is_err(), "CA must stay deleted");
    }

    #[test]
    fn list_cas_cert_count_ignores_deleted_certs() {
        let db = temp_db();
        insert_ca(&db, "ca1", "CA One");
        insert_cert(&db, "c1", "ca1", "a");
        insert_cert(&db, "c2", "ca1", "b");
        db.delete_cert("ca1", "c2").unwrap();
        assert_eq!(db.get_ca("ca1").unwrap().cert_count, 1);
    }

    #[test]
    fn locked_writes_refuse_revoked_certs_and_deleted_cas() {
        let db = temp_db();
        insert_ca(&db, "ca1", "CA One");
        let (meta, secrets) = sample_cert("c1", "ca1", "web");
        db.acquire_ca_lock("ca1", "owner", 60_000).unwrap();
        db.insert_cert_with_state(&meta, &secrets, None, "owner")
            .unwrap();

        db.acquire_ca_lock("ca1", "owner", 60_000).unwrap();
        db.revoke_cert_with_state(
            "ca1",
            "c1",
            "keyCompromise",
            1,
            (b"", b"01"),
            (b"", b"02"),
            "owner",
        )
        .unwrap();
        db.acquire_ca_lock("ca1", "owner", 60_000).unwrap();
        let err = db
            .update_cert_with_state(
                "ca1",
                "c1",
                b"pem",
                b"p12",
                b"zip",
                2,
                30,
                (b"", b"02"),
                "owner",
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("revoked"), "{err}");
        db.release_ca_lock("ca1", "owner").unwrap();
        let cert = db.get_cert("ca1", "c1").unwrap();
        assert_eq!(
            cert.revoked_at,
            Some(1),
            "renewal must not clear revocation"
        );

        db.delete_ca("ca1").unwrap();
        db.acquire_ca_lock("ca1", "owner", 60_000).unwrap();
        let (meta, secrets) = sample_cert("c2", "ca1", "other");
        assert!(
            db.insert_cert_with_state(&meta, &secrets, None, "owner")
                .is_err()
        );
        assert!(db.update_ca_metadata("ca1", "rsa:2048", "sha256").is_err());
    }

    #[test]
    fn restore_backup_is_all_or_nothing() {
        let db = temp_db();
        let (ca_meta, ca_secrets) = sample_ca("ca1", "CA One");
        let ca_row = BackupCaRow {
            meta: ca_meta,
            secrets: ca_secrets,
            deleted: false,
            created_at: 0,
            updated_at: 0,
        };
        let (cert_meta, cert_secrets) = sample_cert("c1", "ca1", "web");
        let cert_row = BackupCertRow {
            meta: cert_meta,
            secrets: cert_secrets,
            deleted: false,
            revoked_at: None,
            revocation_reason: None,
            created_at: 0,
            updated_at: 0,
        };
        let user = UserRecord {
            id: "u1".to_string(),
            username: "alice".to_string(),
            password_hash: "$2b$x".to_string(),
            role: "viewer".to_string(),
            created_at: 0,
        };
        // The duplicated certificate id fails on the last insert; everything
        // before it must be rolled back.
        let broken = BackupSnapshot {
            users: vec![user.clone()],
            cas: vec![(ca_row.clone(), vec![cert_row.clone(), cert_row.clone()])],
        };
        assert!(db.restore_backup(&broken).is_err());
        assert!(
            db.is_empty().unwrap(),
            "failed restore must leave the db empty"
        );

        let good = BackupSnapshot {
            users: vec![user],
            cas: vec![(ca_row, vec![cert_row])],
        };
        db.restore_backup(&good).unwrap();
        let snapshot = db.backup_snapshot().unwrap();
        assert_eq!(snapshot.users.len(), 1);
        assert_eq!(snapshot.cas.len(), 1);
        assert_eq!(snapshot.cas[0].1.len(), 1);
        let err = db.restore_backup(&good).unwrap_err().to_string();
        assert!(err.contains("empty database"), "{err}");
    }

    #[test]
    fn add_column_only_tolerates_duplicate_columns() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (a INTEGER)").unwrap();
        add_column(&conn, "ALTER TABLE t ADD COLUMN b INTEGER").unwrap();
        add_column(&conn, "ALTER TABLE t ADD COLUMN b INTEGER").unwrap();
        assert!(add_column(&conn, "ALTER TABLE missing ADD COLUMN b INTEGER").is_err());
    }

    #[test]
    fn migration_adds_crlnumber_column_to_older_schema() {
        let suffix: String = rand::rng()
            .sample_iter(Alphanumeric)
            .take(12)
            .map(char::from)
            .collect();
        let dir = std::env::temp_dir().join(format!("minica-db-test-{suffix}"));
        let path = dir.join("old.sqlite");
        drop(Db::open(&path).unwrap());
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("ALTER TABLE certificate_authorities DROP COLUMN crlnumber_txt")
                .unwrap();
        }
        let db = Db::open(&path).unwrap();
        insert_ca(&db, "ca1", "CA One");
        assert!(db.get_ca_secrets("ca1").unwrap().crlnumber_txt.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn db_files_are_private_and_old_migration_backups_pruned() {
        use std::os::unix::fs::PermissionsExt;
        let suffix: String = rand::rng()
            .sample_iter(Alphanumeric)
            .take(12)
            .map(char::from)
            .collect();
        let dir = std::env::temp_dir().join(format!("minica-db-test-{suffix}"));
        let path = dir.join("db.sqlite");
        drop(Db::open(&path).unwrap());
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&path), 0o600);

        for stamp in [
            "20200101T000000Z",
            "20210101T000000Z",
            "20220101T000000Z",
            "20230101T000000Z",
        ] {
            fs::write(
                dir.join(format!("db.sqlite.pre-migrate-{stamp}-x.bak")),
                b"",
            )
            .unwrap();
        }
        let newest = dir.join("db.sqlite.pre-migrate-20230101T000000Z-x.bak");
        prune_migration_backups(&dir, "db.sqlite", &newest);
        let mut left = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|name| name.contains(".pre-migrate-"))
            .collect::<Vec<_>>();
        left.sort();
        assert_eq!(left.len(), MAX_MIGRATION_BACKUPS);
        assert!(
            left[0].contains("2021"),
            "oldest backup must be pruned: {left:?}"
        );
        let _ = fs::remove_dir_all(dir);
    }
}
