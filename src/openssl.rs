use crate::{
    config::OpenSslConfig,
    db::{CaSecrets, CertSecrets},
};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use rand::{Rng, distr::Alphanumeric};
use serde_json::Value;
use std::{
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use zip::{ZipWriter, write::SimpleFileOptions};

#[derive(Clone)]
pub struct OpenSsl {
    config: OpenSslConfig,
}

pub struct CrlRefresh {
    pub crl_der: Vec<u8>,
    pub index_txt: Vec<u8>,
    pub serial_txt: Vec<u8>,
}

pub struct WorkDir {
    path: PathBuf,
    keep: bool,
}

pub struct CommandResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
    pub duration_ms: u128,
}

enum Outcome {
    Exited(i32),
    TimedOut,
}

/// Owns a spawned child process and guarantees it is killed and reaped no matter
/// how the caller returns — normal exit, `?` error propagation, or a panic.
/// `disarm` marks the child as already reaped so the destructor is a no-op.
struct ChildGuard {
    child: Child,
    armed: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    /// Stop the process gracefully (SIGTERM on Unix), wait up to `grace`, then
    /// force-kill (SIGKILL) and reap. The child is reaped on return, so the
    /// guard is disarmed.
    fn terminate(&mut self, grace: Duration) {
        #[cfg(unix)]
        {
            // Politely ask openssl to exit first.
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
            let deadline = Instant::now() + grace;
            while Instant::now() < deadline {
                match self.child.try_wait() {
                    Ok(Some(_)) => {
                        self.disarm();
                        return;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                    Err(_) => break,
                }
            }
        }
        // Forceful: SIGKILL, then reap so no zombie is left behind.
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.disarm();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Reads a child pipe to completion on its own thread so a large amount of
/// output cannot fill the OS pipe buffer and deadlock the process.
fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buffer);
        }
        buffer
    })
}

impl OpenSsl {
    pub fn new(config: OpenSslConfig) -> Self {
        Self { config }
    }

    pub fn check(&self) -> Result<()> {
        tracing::info!(openssl_path = %self.config.path.display(), "checking openssl executable");
        let result = self.run_in(
            Path::new("."),
            &["version"],
            Duration::from_secs(self.config.timeout_seconds),
        )?;
        if result.exit_code != 0 {
            bail!(
                "openssl version failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        tracing::info!(
            duration_ms = result.duration_ms,
            "openssl executable check passed"
        );
        Ok(())
    }

    pub fn reap_workdirs(&self) -> Result<()> {
        let start = Instant::now();
        fs::create_dir_all(&self.config.working_root)?;
        let cutoff = Utc::now().timestamp()
            - i64::try_from(self.config.reap_after_hours.saturating_mul(3600)).unwrap_or(i64::MAX);
        let mut scanned_dirs = 0_usize;
        let mut candidate_dirs = 0_usize;
        let mut reaped_dirs = 0_usize;
        let mut failed_dirs = 0_usize;
        for entry in fs::read_dir(&self.config.working_root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            scanned_dirs += 1;
            let name = entry.file_name().to_string_lossy().to_string();
            if !looks_like_workdir(&name) {
                continue;
            }
            candidate_dirs += 1;
            let modified = entry.metadata()?.modified()?;
            let modified: chrono::DateTime<Utc> = modified.into();
            if modified.timestamp() < cutoff {
                let path = entry.path();
                match fs::remove_dir_all(&path) {
                    Ok(_) => {
                        reaped_dirs += 1;
                        tracing::info!(workdir = %path.display(), "reaped stale openssl workdir")
                    }
                    Err(err) => {
                        failed_dirs += 1;
                        tracing::warn!(
                            workdir = %path.display(),
                            error = %err,
                            "failed to reap stale openssl workdir"
                        )
                    }
                }
            }
        }
        tracing::info!(
            working_root = %self.config.working_root.display(),
            reap_after_hours = self.config.reap_after_hours,
            scanned_dirs,
            candidate_dirs,
            reaped_dirs,
            failed_dirs,
            duration_ms = start.elapsed().as_millis(),
            "completed openssl workdir reaper"
        );
        Ok(())
    }

    pub fn workdir(&self) -> Result<WorkDir> {
        fs::create_dir_all(&self.config.working_root)?;
        let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
        let suffix: String = rand::rng()
            .sample_iter(Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let path = self.config.working_root.join(format!("{stamp}-{suffix}"));
        fs::create_dir(&path)?;
        let path = path.canonicalize()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        tracing::debug!(workdir = %path.display(), "created openssl workdir");
        Ok(WorkDir {
            path,
            keep: self.config.keep_failed_workdirs,
        })
    }

    pub fn run_in(&self, cwd: &Path, args: &[&str], timeout: Duration) -> Result<CommandResult> {
        let start = Instant::now();
        let sanitized_args = sanitize_args(args);
        tracing::debug!(
            cwd = %cwd.display(),
            openssl_path = %self.config.path.display(),
            args = ?sanitized_args,
            timeout_ms = timeout.as_millis(),
            "starting openssl command"
        );
        let child = Command::new(&self.config.path)
            .args(args)
            .current_dir(cwd)
            // No stdin: an openssl prompt should get EOF immediately rather than
            // block forever and only be reclaimed at the timeout.
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start openssl {}", sanitized_args.join(" ")))?;

        // From here on the child must never escape: the guard kills and reaps it
        // on every exit path, including early returns and panics.
        let mut guard = ChildGuard::new(child);

        // Drain stdout/stderr on dedicated threads. Reading only after the
        // process exits risks a pipe-buffer deadlock (openssl blocks writing,
        // we block waiting), which would masquerade as a timeout.
        let stdout_reader = drain(guard.child.stdout.take());
        let stderr_reader = drain(guard.child.stderr.take());

        let outcome = loop {
            match guard.child.try_wait() {
                Ok(Some(status)) => break Outcome::Exited(status.code().unwrap_or(-1)),
                Ok(None) => {}
                Err(err) => {
                    // We can't poll the child; the guard's drop will still try to
                    // kill and reap it so nothing is left running.
                    return Err(err).context("failed to poll openssl process");
                }
            }
            if start.elapsed() > timeout {
                break Outcome::TimedOut;
            }
            std::thread::sleep(Duration::from_millis(20));
        };

        if let Outcome::TimedOut = outcome {
            // Graceful first (SIGTERM), then forceful (SIGKILL); always reaped.
            guard.terminate(Duration::from_secs(2));
        } else {
            // Process already exited and was reaped by try_wait; disarm the guard.
            guard.disarm();
        }

        let stdout = stdout_reader.join().unwrap_or_default();
        let stderr = stderr_reader.join().unwrap_or_default();
        let exit_code = match outcome {
            Outcome::Exited(code) => code,
            Outcome::TimedOut => -1,
        };
        let duration_ms = start.elapsed().as_millis();
        if matches!(outcome, Outcome::TimedOut) {
            tracing::warn!(
                cwd = %cwd.display(),
                args = ?sanitized_args,
                exit_code,
                duration_ms,
                stdout_bytes = stdout.len(),
                stderr_bytes = stderr.len(),
                timed_out = true,
                "openssl command timed out and was terminated"
            );
        } else if exit_code == 0 {
            tracing::info!(
                cwd = %cwd.display(),
                args = ?sanitized_args,
                exit_code,
                duration_ms,
                stdout_bytes = stdout.len(),
                stderr_bytes = stderr.len(),
                timed_out = false,
                "openssl command completed"
            );
        } else {
            tracing::warn!(
                cwd = %cwd.display(),
                args = ?sanitized_args,
                exit_code,
                duration_ms,
                stdout_bytes = stdout.len(),
                stderr_bytes = stderr.len(),
                timed_out = false,
                "openssl command failed"
            );
        }
        Ok(CommandResult {
            stdout,
            stderr,
            exit_code,
            duration_ms,
        })
    }

    pub fn create_ca_files(
        &self,
        dir: &Path,
        subject: &str,
        valid_days: i64,
        digest: &str,
        algorithm: &str,
        options: &Value,
        password: &str,
    ) -> Result<CaSecrets> {
        tracing::info!(
            valid_days,
            digest,
            algorithm,
            "creating certificate authority files with openssl"
        );
        self.generate_key(dir, "ca-key.pem", algorithm, options)?;
        self.run_ok(
            dir,
            &[
                "req",
                "-new",
                "-x509",
                "-nodes",
                "-days",
                &valid_days.to_string(),
                "-key",
                "ca-key.pem",
                &format!("-{}", normalize_digest(digest)),
                "-out",
                "ca-cert.pem",
                "-subj",
                subject,
            ],
        )?;
        self.finish_ca_files(dir, password)
    }

    pub fn finish_ca_files(&self, dir: &Path, password: &str) -> Result<CaSecrets> {
        tracing::debug!(workdir = %dir.display(), "creating certificate authority PKCS12 and state files");
        self.run_ok(
            dir,
            &[
                "pkcs12",
                "-export",
                "-out",
                "ca.p12",
                "-in",
                "ca-cert.pem",
                "-inkey",
                "ca-key.pem",
                "-passout",
                &format!("pass:{password}"),
            ],
        )?;
        fs::write(dir.join("password.txt"), password)?;
        fs::write(dir.join("index.txt"), b"")?;
        fs::write(dir.join("serial.txt"), b"00")?;
        let secrets = CaSecrets {
            cert_pem: fs::read(dir.join("ca-cert.pem"))?,
            key_pem: fs::read(dir.join("ca-key.pem"))?,
            pkcs12: fs::read(dir.join("ca.p12"))?,
            password: password.as_bytes().to_vec(),
            index_txt: fs::read(dir.join("index.txt"))?,
            serial_txt: fs::read(dir.join("serial.txt"))?,
            crl_der: Vec::new(),
            crl_updated_at: 0,
        };
        tracing::info!(
            cert_bytes = secrets.cert_pem.len(),
            key_bytes = secrets.key_pem.len(),
            pkcs12_bytes = secrets.pkcs12.len(),
            index_bytes = secrets.index_txt.len(),
            serial_bytes = secrets.serial_txt.len(),
            "created certificate authority files"
        );
        Ok(secrets)
    }

    pub fn create_cert_files(
        &self,
        dir: &Path,
        ca: &CaSecrets,
        subject: &str,
        common_name: &str,
        valid_days: i64,
        digest: &str,
        algorithm: &str,
        options: &Value,
        dns_list: &[String],
        ip_list: &[String],
        password: &str,
        crl_url: Option<&str>,
        crl_days: i64,
    ) -> Result<(CertSecrets, Vec<u8>, Vec<u8>)> {
        tracing::info!(
            common_name,
            valid_days,
            digest,
            algorithm,
            dns_count = dns_list.len(),
            ip_count = ip_list.len(),
            "creating certificate files with openssl"
        );
        export_ca_state(dir, ca)?;
        fs::create_dir_all(dir.join("certs"))?;
        let cert_dir = dir.join("cert");
        fs::create_dir(&cert_dir)?;
        fs::write(
            dir.join("openssl-ca.conf"),
            ca_config(dir, crl_days, crl_url),
        )?;
        fs::write(
            dir.join("openssl-cert.conf"),
            cert_config(common_name, dns_list, ip_list),
        )?;
        self.generate_key(dir, "cert/cert.key", algorithm, options)?;
        self.run_ok(
            dir,
            &[
                "req",
                "-config",
                "openssl-cert.conf",
                "-new",
                "-key",
                "cert/cert.key",
                &format!("-{}", normalize_digest(digest)),
                "-nodes",
                "-out",
                "cert/cert.csr",
                "-outform",
                "PEM",
                "-subj",
                subject,
            ],
        )?;
        self.run_ok(
            dir,
            &[
                "ca",
                "-config",
                "openssl-ca.conf",
                "-days",
                &valid_days.to_string(),
                "-batch",
                "-policy",
                "signing_policy",
                "-extensions",
                "signing_req",
                "-notext",
                "-out",
                "cert/cert.pem",
                "-infiles",
                "cert/cert.csr",
            ],
        )?;
        self.run_ok(
            dir,
            &[
                "pkcs12",
                "-export",
                "-out",
                "cert/cert.p12",
                "-in",
                "cert/cert.pem",
                "-inkey",
                "cert/cert.key",
                "-passout",
                &format!("pass:{password}"),
            ],
        )?;
        fs::write(cert_dir.join("password.txt"), password)?;
        let secrets = read_cert_secrets(&cert_dir, dir)?;
        let index_txt = fs::read(dir.join("index.txt"))?;
        let serial_txt = fs::read(dir.join("serial.txt"))?;
        tracing::info!(
            common_name,
            cert_bytes = secrets.cert_pem.len(),
            key_bytes = secrets.key_pem.len(),
            csr_bytes = secrets.csr_pem.len(),
            pkcs12_bytes = secrets.pkcs12.len(),
            bundle_bytes = secrets.bundle_zip.len(),
            index_bytes = index_txt.len(),
            serial_bytes = serial_txt.len(),
            "created certificate files"
        );
        Ok((secrets, index_txt, serial_txt))
    }

    fn generate_key(
        &self,
        dir: &Path,
        output: &str,
        algorithm: &str,
        attributes: &Value,
    ) -> Result<()> {
        match algorithm.trim().to_ascii_lowercase().as_str() {
            "rsa" => {
                let bits = attributes
                    .get("bits")
                    .and_then(Value::as_i64)
                    .unwrap_or(4096)
                    .to_string();
                tracing::debug!(algorithm = "rsa", bits = %bits, output, "generating private key");
                self.run_ok(
                    dir,
                    &[
                        "genpkey",
                        "-algorithm",
                        "RSA",
                        "-pkeyopt",
                        &format!("rsa_keygen_bits:{bits}"),
                        "-out",
                        output,
                    ],
                )?;
                Ok(())
            }
            "ecdsa" | "ec" => {
                let curve = attributes
                    .get("curve")
                    .and_then(Value::as_str)
                    .unwrap_or("prime256v1");
                tracing::debug!(algorithm = "ecdsa", curve, output, "generating private key");
                self.run_ok(
                    dir,
                    &[
                        "genpkey",
                        "-algorithm",
                        "EC",
                        "-pkeyopt",
                        &format!("ec_paramgen_curve:{curve}"),
                        "-out",
                        output,
                    ],
                )?;
                Ok(())
            }
            other => bail!("unsupported key algorithm: {other}"),
        }
    }

    pub fn renew_cert_files(
        &self,
        dir: &Path,
        ca: &CaSecrets,
        cert: &CertSecrets,
        valid_days: i64,
        crl_url: Option<&str>,
        crl_days: i64,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        tracing::info!(valid_days, "renewing certificate files with openssl");
        export_ca_state(dir, ca)?;
        fs::create_dir_all(dir.join("certs"))?;
        fs::write(
            dir.join("openssl-ca.conf"),
            ca_config(dir, crl_days, crl_url),
        )?;
        let cert_dir = dir.join("cert");
        fs::create_dir(&cert_dir)?;
        fs::write(cert_dir.join("cert.key"), &cert.key_pem)?;
        fs::write(cert_dir.join("cert.csr"), &cert.csr_pem)?;
        let password = String::from_utf8_lossy(&cert.password).to_string();
        self.run_ok(
            dir,
            &[
                "ca",
                "-config",
                "openssl-ca.conf",
                "-days",
                &valid_days.to_string(),
                "-batch",
                "-policy",
                "signing_policy",
                "-extensions",
                "signing_req",
                "-notext",
                "-out",
                "cert/cert.pem",
                "-infiles",
                "cert/cert.csr",
            ],
        )?;
        self.run_ok(
            dir,
            &[
                "pkcs12",
                "-export",
                "-out",
                "cert/cert.p12",
                "-in",
                "cert/cert.pem",
                "-inkey",
                "cert/cert.key",
                "-passout",
                &format!("pass:{password}"),
            ],
        )?;
        fs::write(cert_dir.join("password.txt"), &cert.password)?;
        let cert_pem = fs::read(cert_dir.join("cert.pem"))?;
        let pkcs12 = fs::read(cert_dir.join("cert.p12"))?;
        let bundle = create_bundle(&cert_dir, dir)?;
        let index_txt = fs::read(dir.join("index.txt"))?;
        tracing::info!(
            cert_bytes = cert_pem.len(),
            pkcs12_bytes = pkcs12.len(),
            bundle_bytes = bundle.len(),
            index_bytes = index_txt.len(),
            "renewed certificate files"
        );
        Ok((cert_pem, pkcs12, bundle, index_txt))
    }

    pub fn generate_crl(&self, dir: &Path, ca: &CaSecrets, crl_days: i64) -> Result<CrlRefresh> {
        tracing::info!(
            crl_days,
            "generating certificate revocation list with openssl"
        );
        export_ca_state(dir, ca)?;
        fs::create_dir_all(dir.join("certs"))?;
        fs::write(dir.join("openssl-ca.conf"), ca_config(dir, crl_days, None))?;
        self.run_ok(
            dir,
            &[
                "ca",
                "-config",
                "openssl-ca.conf",
                "-gencrl",
                "-out",
                "ca.crl.pem",
            ],
        )?;
        self.run_ok(
            dir,
            &[
                "crl",
                "-in",
                "ca.crl.pem",
                "-out",
                "ca.crl",
                "-outform",
                "DER",
            ],
        )?;
        let refresh = CrlRefresh {
            crl_der: fs::read(dir.join("ca.crl"))?,
            index_txt: fs::read(dir.join("index.txt"))?,
            serial_txt: fs::read(dir.join("serial.txt"))?,
        };
        tracing::info!(
            crl_bytes = refresh.crl_der.len(),
            index_bytes = refresh.index_txt.len(),
            "generated certificate revocation list"
        );
        Ok(refresh)
    }

    pub fn revoke_cert_files(
        &self,
        dir: &Path,
        ca: &CaSecrets,
        cert: &CertSecrets,
        reason: &str,
        crl_days: i64,
    ) -> Result<CrlRefresh> {
        tracing::info!(reason, crl_days, "revoking certificate with openssl");
        export_ca_state(dir, ca)?;
        fs::create_dir_all(dir.join("certs"))?;
        fs::write(dir.join("openssl-ca.conf"), ca_config(dir, crl_days, None))?;
        fs::write(dir.join("revoke.pem"), &cert.cert_pem)?;
        self.run_ok(
            dir,
            &[
                "ca",
                "-config",
                "openssl-ca.conf",
                "-revoke",
                "revoke.pem",
                "-crl_reason",
                reason,
            ],
        )?;
        self.run_ok(
            dir,
            &[
                "ca",
                "-config",
                "openssl-ca.conf",
                "-gencrl",
                "-out",
                "ca.crl.pem",
            ],
        )?;
        self.run_ok(
            dir,
            &[
                "crl",
                "-in",
                "ca.crl.pem",
                "-out",
                "ca.crl",
                "-outform",
                "DER",
            ],
        )?;
        let refresh = CrlRefresh {
            crl_der: fs::read(dir.join("ca.crl"))?,
            index_txt: fs::read(dir.join("index.txt"))?,
            serial_txt: fs::read(dir.join("serial.txt"))?,
        };
        tracing::info!(
            reason,
            crl_bytes = refresh.crl_der.len(),
            index_bytes = refresh.index_txt.len(),
            "revoked certificate and generated certificate revocation list"
        );
        Ok(refresh)
    }

    pub fn import_cert_files(
        &self,
        dir: &Path,
        ca: &CaSecrets,
        cert_pem: &str,
        key_pem: &str,
        password: &str,
    ) -> Result<CertSecrets> {
        tracing::info!("importing certificate files with openssl");
        export_ca_state(dir, ca)?;
        let cert_dir = dir.join("cert");
        fs::create_dir(&cert_dir)?;
        fs::write(cert_dir.join("cert.pem"), cert_pem.as_bytes())?;
        fs::write(cert_dir.join("cert.key"), key_pem.as_bytes())?;
        self.run_ok(dir, &["verify", "-CAfile", "ca-cert.pem", "cert/cert.pem"])
            .context("imported certificate was not issued by this CA")?;
        self.run_ok(
            dir,
            &[
                "x509",
                "-x509toreq",
                "-in",
                "cert/cert.pem",
                "-signkey",
                "cert/cert.key",
                "-out",
                "cert/cert.csr",
            ],
        )
        .context("imported private key does not match the certificate")?;
        self.run_ok(
            dir,
            &[
                "pkcs12",
                "-export",
                "-out",
                "cert/cert.p12",
                "-in",
                "cert/cert.pem",
                "-inkey",
                "cert/cert.key",
                "-passout",
                &format!("pass:{password}"),
            ],
        )?;
        fs::write(cert_dir.join("password.txt"), password)?;
        let secrets = read_cert_secrets(&cert_dir, dir)?;
        tracing::info!(
            cert_bytes = secrets.cert_pem.len(),
            key_bytes = secrets.key_pem.len(),
            csr_bytes = secrets.csr_pem.len(),
            pkcs12_bytes = secrets.pkcs12.len(),
            bundle_bytes = secrets.bundle_zip.len(),
            "imported certificate files"
        );
        Ok(secrets)
    }

    pub fn inspect_cert(&self, dir: &Path, pem: &str) -> Result<Vec<(String, String)>> {
        tracing::debug!(workdir = %dir.display(), "inspecting certificate summary with openssl");
        fs::write(dir.join("inspect.pem"), pem)?;
        let out = self.run_ok(
            dir,
            &[
                "x509",
                "-in",
                "inspect.pem",
                "-noout",
                "-subject",
                "-issuer",
                "-dates",
                "-serial",
                "-fingerprint",
                "-sha256",
            ],
        )?;
        let text = String::from_utf8_lossy(&out.stdout);
        let info = text
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect::<Vec<_>>();
        tracing::debug!(field_count = info.len(), "inspected certificate summary");
        Ok(info)
    }

    pub fn inspect_cert_text(&self, dir: &Path, pem: &str) -> Result<String> {
        tracing::debug!(workdir = %dir.display(), "inspecting certificate text with openssl");
        fs::write(dir.join("inspect-text.pem"), pem)?;
        let out = self.run_ok(dir, &["x509", "-in", "inspect-text.pem", "-noout", "-text"])?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        tracing::debug!(bytes = text.len(), "inspected certificate text");
        Ok(text)
    }

    pub fn inspect_cert_purposes(&self, dir: &Path, pem: &str) -> Result<Vec<(String, String)>> {
        tracing::debug!(workdir = %dir.display(), "inspecting certificate purposes with openssl");
        fs::write(dir.join("inspect-purpose.pem"), pem)?;
        let out = self.run_ok(
            dir,
            &["x509", "-in", "inspect-purpose.pem", "-noout", "-purpose"],
        )?;
        let text = String::from_utf8_lossy(&out.stdout);
        let purposes = text
            .lines()
            .filter_map(|line| line.split_once(':'))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect::<Vec<_>>();
        tracing::debug!(
            purpose_count = purposes.len(),
            "inspected certificate purposes"
        );
        Ok(purposes)
    }

    pub fn inspect_cert_sans(&self, dir: &Path, pem: &str) -> Result<(Vec<String>, Vec<String>)> {
        tracing::debug!(workdir = %dir.display(), "inspecting certificate SANs with openssl");
        fs::write(dir.join("inspect-san.pem"), pem)?;
        let out = self.run_ok(
            dir,
            &[
                "x509",
                "-in",
                "inspect-san.pem",
                "-noout",
                "-ext",
                "subjectAltName",
            ],
        )?;
        let text = String::from_utf8_lossy(&out.stdout);
        let mut dns = Vec::new();
        let mut ips = Vec::new();
        for part in text.split([',', '\n']) {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("DNS:") {
                dns.push(value.trim().to_string());
            } else if let Some(value) = part.strip_prefix("IP Address:") {
                ips.push(value.trim().to_string());
            }
        }
        tracing::debug!(
            dns_count = dns.len(),
            ip_count = ips.len(),
            "inspected certificate SANs"
        );
        Ok((dns, ips))
    }

    fn run_ok(&self, cwd: &Path, args: &[&str]) -> Result<CommandResult> {
        let result = self.run_in(cwd, args, Duration::from_secs(self.config.timeout_seconds))?;
        if result.exit_code != 0 {
            bail!(
                "openssl {} failed: {}",
                args.first().copied().unwrap_or(""),
                String::from_utf8_lossy(&result.stderr)
            );
        }
        Ok(result)
    }
}

impl WorkDir {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        if !self.keep {
            match fs::remove_dir_all(&self.path) {
                Ok(_) => tracing::debug!(workdir = %self.path.display(), "removed openssl workdir"),
                Err(err) => tracing::warn!(
                    workdir = %self.path.display(),
                    error = %err,
                    "failed to remove openssl workdir"
                ),
            }
        } else {
            tracing::warn!(workdir = %self.path.display(), "keeping openssl workdir for debugging");
        }
    }
}

pub fn random_password() -> String {
    rand::rng()
        .sample_iter(Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

pub fn create_subject(
    common_name: &str,
    country_code: &str,
    organization: &str,
    state: &str,
    city: &str,
    organization_unit: &str,
) -> Result<String> {
    if common_name.trim().is_empty() {
        bail!("common name is required");
    }
    if country_code.trim().is_empty() {
        bail!("country code is required");
    }
    if organization.trim().is_empty() {
        bail!("organization is required");
    }
    let mut subject = format!("/C={}", escape_subject(country_code));
    if !state.trim().is_empty() {
        subject.push_str(&format!("/ST={}", escape_subject(state)));
    }
    if !city.trim().is_empty() {
        subject.push_str(&format!("/L={}", escape_subject(city)));
    }
    subject.push_str(&format!("/O={}", escape_subject(organization)));
    if !organization_unit.trim().is_empty() {
        subject.push_str(&format!("/OU={}", escape_subject(organization_unit)));
    }
    subject.push_str(&format!("/CN={}", escape_subject(common_name)));
    Ok(subject)
}

fn escape_subject(input: &str) -> String {
    input.replace('\\', "\\\\").replace('/', "\\/")
}

fn normalize_digest(input: &str) -> String {
    input.trim().trim_start_matches('-').to_lowercase()
}

fn export_ca_state(dir: &Path, ca: &CaSecrets) -> Result<()> {
    fs::write(dir.join("ca-cert.pem"), &ca.cert_pem)?;
    fs::write(dir.join("ca-key.pem"), &ca.key_pem)?;
    fs::write(dir.join("index.txt"), &ca.index_txt)?;
    fs::write(dir.join("serial.txt"), &ca.serial_txt)?;
    Ok(())
}

fn read_cert_secrets(cert_dir: &Path, ca_dir: &Path) -> Result<CertSecrets> {
    let bundle = create_bundle(cert_dir, ca_dir)?;
    Ok(CertSecrets {
        cert_pem: fs::read(cert_dir.join("cert.pem"))?,
        key_pem: fs::read(cert_dir.join("cert.key"))?,
        csr_pem: fs::read(cert_dir.join("cert.csr"))?,
        pkcs12: fs::read(cert_dir.join("cert.p12"))?,
        password: fs::read(cert_dir.join("password.txt"))?,
        bundle_zip: bundle,
    })
}

fn create_bundle(cert_dir: &Path, ca_dir: &Path) -> Result<Vec<u8>> {
    let cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default();
    for (fs_path, zip_name) in [
        (cert_dir.join("cert.csr"), "cert.csr"),
        (cert_dir.join("cert.key"), "cert.key"),
        (cert_dir.join("cert.p12"), "cert.p12"),
        (cert_dir.join("cert.pem"), "cert.pem"),
        (cert_dir.join("password.txt"), "cert-p12-password.txt"),
        (ca_dir.join("ca-cert.pem"), "ca.pem"),
    ] {
        zip.start_file(zip_name, opts)?;
        zip.write_all(&fs::read(fs_path)?)?;
    }
    Ok(zip.finish()?.into_inner())
}

fn ca_config(base: &Path, crl_days: i64, crl_url: Option<&str>) -> String {
    let base = base.display();
    let crl_extension = crl_url
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("crlDistributionPoints = URI:{value}\n"))
        .unwrap_or_default();
    format!(
        r#"[ ca ]
default_ca = CA_default
[ CA_default ]
default_days = 7300
default_crl_days = {crl_days}
default_md = sha512
preserve = no
unique_subject = no
base_dir = {base}
certificate = $base_dir/ca-cert.pem
private_key = $base_dir/ca-key.pem
new_certs_dir = $base_dir/certs
database = $base_dir/index.txt
serial = $base_dir/serial.txt
x509_extensions = ca_extensions
email_in_dn = no
copy_extensions = copy

[ req ]
default_bits = 4096
default_keyfile = {base}/ca-key.pem
distinguished_name = ca_distinguished_name
x509_extensions = ca_extensions
string_mask = utf8only

[ ca_distinguished_name ]
countryName = Country Name
stateOrProvinceName = State
localityName = Locality
organizationName = Organization
organizationalUnitName = Organizational Unit
commonName = Common Name

[ ca_extensions ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
basicConstraints = critical, CA:true
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign

[ signing_policy ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ signing_req ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, nonRepudiation
extendedKeyUsage = clientAuth, emailProtection, serverAuth
{crl_extension}
"#
    )
}

fn cert_config(common_name: &str, dns_list: &[String], ip_list: &[String]) -> String {
    let mut all_dns = vec![common_name.to_string()];
    for dns in dns_list {
        if dns != common_name {
            all_dns.push(dns.clone());
        }
    }
    let dns = all_dns
        .iter()
        .enumerate()
        .map(|(i, v)| format!("DNS.{} = {}", i + 1, v))
        .collect::<Vec<_>>()
        .join("\n");
    let ips = ip_list
        .iter()
        .enumerate()
        .map(|(i, v)| format!("IP.{} = {}", i + 1, v))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"[ req ]
default_bits = 4096
distinguished_name = server_distinguished_name
req_extensions = server_req_extensions
string_mask = utf8only

[ server_distinguished_name ]
commonName = Common Name
commonName_default = {common_name}

[ server_req_extensions ]
subjectKeyIdentifier = hash
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, keyAgreement, nonRepudiation
extendedKeyUsage = critical, serverAuth, clientAuth
subjectAltName = @alternate_names
nsComment = "OpenSSL Generated Certificate"

[ alternate_names ]
{dns}
{ips}
"#
    )
}

fn looks_like_workdir(name: &str) -> bool {
    name.len() > 18 && name.as_bytes().get(8) == Some(&b'T') && name.contains('-')
}

fn sanitize_args(args: &[&str]) -> Vec<String> {
    let mut sanitized = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            sanitized.push("*****".to_string());
            redact_next = false;
            continue;
        }
        if matches!(*arg, "-passout" | "-passin" | "-password") {
            sanitized.push((*arg).to_string());
            redact_next = true;
        } else if arg.starts_with("pass:") {
            sanitized.push("pass:*****".to_string());
        } else {
            sanitized.push((*arg).to_string());
        }
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_in_times_out_and_force_kills() {
        // Use `sleep` as a stand-in for an openssl command that never finishes.
        let runner = OpenSsl::new(OpenSslConfig {
            path: PathBuf::from("/bin/sleep"),
            timeout_seconds: 1,
            working_root: std::env::temp_dir().join("minica-openssl-test"),
            keep_failed_workdirs: false,
            reap_after_hours: 24,
        });
        let start = Instant::now();
        let result = runner
            .run_in(Path::new("."), &["30"], Duration::from_millis(300))
            .expect("run_in returns even when the child is killed");
        // Reported as a timeout, and we did not wait for the full 30s child.
        assert_eq!(result.exit_code, -1);
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed-out child must be killed promptly, not awaited"
        );
    }

    #[test]
    fn sanitize_args_masks_password_values() {
        assert_eq!(
            sanitize_args(&[
                "pkcs12",
                "-export",
                "-passout",
                "pass:secret",
                "-passin",
                "env:SECRET",
                "pass:inline",
            ]),
            vec![
                "pkcs12".to_string(),
                "-export".to_string(),
                "-passout".to_string(),
                "*****".to_string(),
                "-passin".to_string(),
                "*****".to_string(),
                "pass:*****".to_string(),
            ]
        );
    }
}
