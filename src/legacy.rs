//! Import of a MiniCA 1.0.x (Kotlin/Spring) data directory.
//!
//! The original minica kept everything as files under `minica.root`:
//!
//! ```text
//! <root>/CAs/<ca-uuid>/ca-cert.pem, ca-key.pem, password.txt, meta.properties,
//!                       index.txt, serial.txt, CA.complete, ...
//! <root>/CAs/<ca-uuid>/<cert-uuid>/cert.pem, cert.key, cert.csr, password.txt,
//!                                   meta.properties, CERT.complete, ...
//! ```
//!
//! That version had no export, so the directory tree *is* the backup. This
//! module walks it and feeds every completed CA and certificate through the
//! regular import paths, keeping the original ids (so bookmarked URLs and
//! scripts keep working) and the original PKCS#12 passwords. Everything else
//! — subject, validity, SANs, key and digest — is read from the certificates,
//! so `meta.properties` is not consulted. JKS keystores are not carried over
//! (this version offers PKCS#12 instead).
//!
//! The import is idempotent: ids that already exist are skipped, so a run
//! can be repeated after fixing a reported failure.

use crate::{
    models::{ImportCaRequest, ImportCertRequest},
    service::AppService,
};
use anyhow::{Context, Result, bail};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// What one import run did.
#[derive(Debug, Default)]
pub struct LegacyImportReport {
    pub cas_imported: usize,
    pub certs_imported: usize,
    /// Entities left alone because their id already exists.
    pub skipped: Vec<String>,
    /// Entities that could not be imported, with the reason.
    pub failures: Vec<String>,
}

impl LegacyImportReport {
    pub fn is_success(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Imports every CA and certificate found under `root`, which may be the
/// legacy `minica.root` (containing `CAs/`) or that `CAs` directory itself.
pub fn import_tree(service: &AppService, root: &Path) -> Result<LegacyImportReport> {
    let cas_dir = locate_cas_dir(root)?;
    let mut report = LegacyImportReport::default();
    for ca_dir in sorted_subdirs(&cas_dir)? {
        if !ca_dir.join("CA.complete").is_file() {
            tracing::debug!(dir = %ca_dir.display(), "skipping directory without CA.complete");
            continue;
        }
        import_ca_dir(service, &ca_dir, &mut report);
    }
    Ok(report)
}

fn locate_cas_dir(root: &Path) -> Result<PathBuf> {
    if !root.is_dir() {
        bail!("{} is not a directory", root.display());
    }
    let nested = root.join("CAs");
    if nested.is_dir() {
        return Ok(nested);
    }
    let has_ca = sorted_subdirs(root)?
        .iter()
        .any(|dir| dir.join("CA.complete").is_file());
    if has_ca {
        return Ok(root.to_path_buf());
    }
    bail!(
        "{} does not look like a MiniCA 1.0.x data directory: expected a CAs/ folder \
         (the minica.root of the old installation) or CA folders containing CA.complete",
        root.display()
    )
}

fn sorted_subdirs(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("failed to read {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .filter(|path| {
            !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with('.'))
        })
        .collect();
    dirs.sort();
    Ok(dirs)
}

fn dir_name(dir: &Path) -> String {
    dir.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string()
}

fn read_text(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

/// `password.txt` as written by the old version (no trailing newline, but be
/// lenient); `None` when the file is missing or empty.
fn read_password(dir: &Path) -> Option<String> {
    let text = fs::read_to_string(dir.join("password.txt")).ok()?;
    let password = text.trim_end_matches(['\r', '\n']).to_string();
    (!password.is_empty()).then_some(password)
}

fn import_ca_dir(service: &AppService, ca_dir: &Path, report: &mut LegacyImportReport) {
    let id = dir_name(ca_dir);
    let label = format!("CA {id}");
    let existed = match service.db().ca_exists(&id) {
        Ok(existed) => existed,
        Err(err) => {
            report.failures.push(format!("{label}: {err}"));
            return;
        }
    };
    if existed {
        report.skipped.push(format!("{label}: already imported"));
    } else {
        let outcome = (|| -> Result<String> {
            let cert_pem = read_text(&ca_dir.join("ca-cert.pem"))?;
            let key_pem = read_text(&ca_dir.join("ca-key.pem"))?;
            let ca = service.import_ca_with_id(
                Some(id.clone()),
                ImportCaRequest {
                    cert_pem,
                    key_pem,
                    password: read_password(ca_dir),
                },
            )?;
            Ok(ca.common_name)
        })();
        match outcome {
            Ok(common_name) => {
                tracing::info!(ca_id = %id, common_name = %common_name, "imported legacy certificate authority");
                report.cas_imported += 1;
            }
            Err(err) => {
                report.failures.push(format!("{label}: {err:#}"));
                // Its certificates cannot verify against a CA that is not there.
                return;
            }
        }
    }
    let cert_dirs = match sorted_subdirs(ca_dir) {
        Ok(dirs) => dirs,
        Err(err) => {
            report.failures.push(format!("{label}: {err}"));
            return;
        }
    };
    for cert_dir in cert_dirs {
        if !cert_dir.join("CERT.complete").is_file() {
            continue;
        }
        import_cert_dir(service, &id, &cert_dir, report);
    }
}

fn import_cert_dir(
    service: &AppService,
    ca_id: &str,
    cert_dir: &Path,
    report: &mut LegacyImportReport,
) {
    let id = dir_name(cert_dir);
    let label = format!("certificate {ca_id}/{id}");
    match service.db().cert_exists(&id) {
        Ok(true) => {
            report.skipped.push(format!("{label}: already imported"));
            return;
        }
        Ok(false) => {}
        Err(err) => {
            report.failures.push(format!("{label}: {err}"));
            return;
        }
    }
    let outcome = (|| -> Result<String> {
        let cert_pem = read_text(&cert_dir.join("cert.pem"))?;
        let key_pem = read_text(&cert_dir.join("cert.key"))?;
        let csr_pem = fs::read(cert_dir.join("cert.csr")).ok();
        let cert = service.import_cert_with(
            ca_id,
            Some(id.clone()),
            ImportCertRequest {
                cert_pem,
                key_pem,
                password: read_password(cert_dir),
            },
            csr_pem.as_deref(),
        )?;
        Ok(cert.common_name)
    })();
    match outcome {
        Ok(common_name) => {
            tracing::info!(ca_id = %ca_id, cert_id = %id, common_name = %common_name, "imported legacy certificate");
            report.certs_imported += 1;
        }
        Err(err) => report.failures.push(format!("{label}: {err:#}")),
    }
}
