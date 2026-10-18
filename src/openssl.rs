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
    pub crlnumber_txt: Vec<u8>,
}

pub struct WorkDir {
    path: PathBuf,
    keep: bool,
    /// Keep the directory on drop only if an openssl command failed in it
    /// (`keep_failed_workdirs`); successful workdirs are always removed.
    keep_failed: bool,
}

/// Marker dropped into a workdir by `run_ok` when an openssl command fails, so
/// `WorkDir`'s destructor can tell failed workdirs from successful ones.
const FAILED_MARKER: &str = ".openssl-failed";

/// Starting value of a CA's `crlnumber` file (hex, as openssl expects).
pub const INITIAL_CRL_NUMBER: &[u8] = b"01\n";

/// Digests accepted for CA and leaf signing. Anything else is rejected before
/// it can be turned into an openssl flag.
pub const SUPPORTED_DIGESTS: [&str; 3] = ["sha256", "sha384", "sha512"];

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
        #[cfg(not(unix))]
        let _ = grace;
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
        // Create the directory owner-only from the start rather than chmod'ing
        // it afterwards, so key material is never briefly world-readable.
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        let path = path.canonicalize()?;
        tracing::debug!(workdir = %path.display(), "created openssl workdir");
        Ok(WorkDir {
            path,
            keep: false,
            keep_failed: self.config.keep_failed_workdirs,
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
        let digest = normalize_digest(digest)?;
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
                &format!("-{digest}"),
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
        let passout = write_pass_file(dir, "ca-p12.pass", password.as_bytes())?;
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
                &passout,
            ],
        )?;
        write_secret(&dir.join("password.txt"), password.as_bytes())?;
        write_secret(&dir.join("index.txt"), b"")?;
        // RFC 5280 wants positive, unpredictable serials. A random 128-bit
        // start also keeps an imported CA from re-issuing serials it already
        // used elsewhere.
        write_secret(
            &dir.join("serial.txt"),
            format!("{}\n", random_serial_hex()).as_bytes(),
        )?;
        write_secret(&dir.join("crlnumber.txt"), INITIAL_CRL_NUMBER)?;
        let secrets = CaSecrets {
            cert_pem: fs::read(dir.join("ca-cert.pem"))?,
            key_pem: fs::read(dir.join("ca-key.pem"))?,
            pkcs12: fs::read(dir.join("ca.p12"))?,
            password: password.as_bytes().to_vec(),
            index_txt: fs::read(dir.join("index.txt"))?,
            serial_txt: fs::read(dir.join("serial.txt"))?,
            crl_der: Vec::new(),
            crl_updated_at: 0,
            crlnumber_txt: fs::read(dir.join("crlnumber.txt"))?,
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
        let digest = normalize_digest(digest)?;
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
            cert_config(dns_list, ip_list),
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
                &format!("-{digest}"),
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
                "-md",
                &digest,
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
        let passout = write_pass_file(dir, "cert-p12.pass", password.as_bytes())?;
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
                &passout,
            ],
        )?;
        write_secret(&cert_dir.join("password.txt"), password.as_bytes())?;
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

    #[allow(clippy::too_many_arguments)]
    pub fn renew_cert_files(
        &self,
        dir: &Path,
        ca: &CaSecrets,
        cert: &CertSecrets,
        valid_days: i64,
        digest: &str,
        crl_url: Option<&str>,
        crl_days: i64,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        tracing::info!(
            valid_days,
            digest,
            "renewing certificate files with openssl"
        );
        let digest = normalize_digest(digest)?;
        export_ca_state(dir, ca)?;
        fs::create_dir_all(dir.join("certs"))?;
        fs::write(
            dir.join("openssl-ca.conf"),
            ca_config(dir, crl_days, crl_url),
        )?;
        let cert_dir = dir.join("cert");
        fs::create_dir(&cert_dir)?;
        write_secret(&cert_dir.join("cert.key"), &cert.key_pem)?;
        fs::write(cert_dir.join("cert.csr"), &cert.csr_pem)?;
        self.run_ok(
            dir,
            &[
                "ca",
                "-config",
                "openssl-ca.conf",
                "-days",
                &valid_days.to_string(),
                "-md",
                &digest,
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
        let passout = write_pass_file(dir, "cert-p12.pass", &cert.password)?;
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
                &passout,
            ],
        )?;
        write_secret(&cert_dir.join("password.txt"), &cert.password)?;
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

    /// Whether the certificate's issuer DN equals its subject DN (compared by
    /// openssl's canonical name hash, as chain building does), i.e. a root CA
    /// rather than an intermediate issued by some other CA.
    pub fn is_self_issued(&self, dir: &Path, pem: &[u8]) -> Result<bool> {
        fs::write(dir.join("inspect-issuer.pem"), pem)?;
        let out = self.run_ok(
            dir,
            &[
                "x509",
                "-in",
                "inspect-issuer.pem",
                "-noout",
                "-subject_hash",
                "-issuer_hash",
            ],
        )?;
        let text = String::from_utf8_lossy(&out.stdout);
        let hashes: Vec<&str> = text.lines().map(str::trim).collect();
        Ok(hashes.len() == 2 && hashes[0] == hashes[1])
    }

    /// Re-signs a self-signed CA certificate with its own key. `x509 -signkey`
    /// keeps the subject DN and every extension (so the SKI/AKI stay the same,
    /// the key being unchanged) and only replaces the serial, the validity
    /// (from now) and the signature. Leaf certificates issued earlier keep
    /// verifying, since their issuer DN and AKI still match. Returns the new
    /// certificate PEM and the rebuilt CA PKCS12.
    pub fn renew_ca_files(
        &self,
        dir: &Path,
        ca: &CaSecrets,
        valid_days: i64,
        digest: &str,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        tracing::info!(
            valid_days,
            digest,
            "renewing certificate authority files with openssl"
        );
        let digest = normalize_digest(digest)?;
        fs::write(dir.join("ca-cert.pem"), &ca.cert_pem)?;
        write_secret(&dir.join("ca-key.pem"), &ca.key_pem)?;
        if !self.is_self_issued(dir, &ca.cert_pem)? {
            bail!(
                "only a self-signed (root) CA can be renewed here; an intermediate CA must be re-issued by its parent"
            );
        }
        // `-signkey` would silently swap in a mismatched key's public key.
        let key_pub = self
            .run_ok(dir, &["pkey", "-in", "ca-key.pem", "-pubout"])
            .context("CA private key could not be read")?;
        let cert_pub = self.run_ok(dir, &["x509", "-in", "ca-cert.pem", "-noout", "-pubkey"])?;
        if String::from_utf8_lossy(&key_pub.stdout).trim()
            != String::from_utf8_lossy(&cert_pub.stdout).trim()
        {
            bail!("CA private key does not match the CA certificate");
        }
        let old_serial = self.run_ok(dir, &["x509", "-in", "ca-cert.pem", "-noout", "-serial"])?;
        let serial = format!("0x{}", random_serial_hex());
        self.run_ok(
            dir,
            &[
                "x509",
                "-in",
                "ca-cert.pem",
                "-signkey",
                "ca-key.pem",
                "-days",
                &valid_days.to_string(),
                "-set_serial",
                &serial,
                &format!("-{digest}"),
                "-out",
                "ca-cert-renewed.pem",
            ],
        )?;
        // Older openssl ignores -set_serial with -signkey; a renewed CA must
        // never reuse the old serial. The renewed certificate must also still
        // verify as a trust anchor on its own.
        let new_serial = self.run_ok(
            dir,
            &["x509", "-in", "ca-cert-renewed.pem", "-noout", "-serial"],
        )?;
        if new_serial.stdout == old_serial.stdout {
            bail!("openssl did not assign a new serial to the renewed CA certificate");
        }
        self.run_ok(
            dir,
            &[
                "verify",
                "-CAfile",
                "ca-cert-renewed.pem",
                "ca-cert-renewed.pem",
            ],
        )
        .context("renewed CA certificate does not verify against itself")?;
        let passout = write_pass_file(dir, "ca-p12.pass", &ca.password)?;
        self.run_ok(
            dir,
            &[
                "pkcs12",
                "-export",
                "-out",
                "ca-renewed.p12",
                "-in",
                "ca-cert-renewed.pem",
                "-inkey",
                "ca-key.pem",
                "-passout",
                &passout,
            ],
        )?;
        let cert_pem = fs::read(dir.join("ca-cert-renewed.pem"))?;
        let pkcs12 = fs::read(dir.join("ca-renewed.p12"))?;
        tracing::info!(
            cert_bytes = cert_pem.len(),
            pkcs12_bytes = pkcs12.len(),
            "renewed certificate authority files"
        );
        Ok((cert_pem, pkcs12))
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
        let refresh = read_crl_refresh(dir)?;
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
        // Renewal reissues the same key under a new serial, leaving the earlier
        // serials 'V' in index.txt. Revoke those too so the old certificates
        // cannot outlive the revocation of the current one.
        let serial_out = self.run_ok(dir, &["x509", "-in", "revoke.pem", "-noout", "-serial"])?;
        let serial = String::from_utf8_lossy(&serial_out.stdout)
            .trim()
            .trim_start_matches("serial=")
            .to_string();
        let index = fs::read_to_string(dir.join("index.txt"))?;
        let (index, extra_revoked) = revoke_superseded_index_entries(&index, &serial);
        if extra_revoked > 0 {
            write_secret(&dir.join("index.txt"), index.as_bytes())?;
            tracing::warn!(
                serial = %serial,
                extra_revoked,
                "also revoked earlier serials issued for the same certificate"
            );
        }
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
        let refresh = read_crl_refresh(dir)?;
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
        write_secret(&cert_dir.join("cert.key"), key_pem.as_bytes())?;
        self.run_ok(dir, &["verify", "-CAfile", "ca-cert.pem", "cert/cert.pem"])
            .context("imported certificate was not issued by this CA")?;
        // `x509 -x509toreq -signkey` happily signs with a mismatched key, so
        // compare the public keys explicitly.
        let key_pub = self
            .run_ok(dir, &["pkey", "-in", "cert/cert.key", "-pubout"])
            .context("imported private key could not be read")?;
        let cert_pub = self.run_ok(dir, &["x509", "-in", "cert/cert.pem", "-noout", "-pubkey"])?;
        if String::from_utf8_lossy(&key_pub.stdout).trim()
            != String::from_utf8_lossy(&cert_pub.stdout).trim()
        {
            bail!("imported private key does not match the certificate");
        }
        // `-copy_extensions copyall` (OpenSSL 3) carries the SANs into the CSR
        // so renewals keep them; older openssl/LibreSSL lack the option, so
        // fall back to the plain conversion there.
        let to_req = |copy: bool| {
            let mut args = vec!["x509", "-x509toreq"];
            if copy {
                args.extend(["-copy_extensions", "copyall"]);
            }
            args.extend([
                "-in",
                "cert/cert.pem",
                "-signkey",
                "cert/cert.key",
                "-out",
                "cert/cert.csr",
            ]);
            args
        };
        let copied = self.run_in(
            dir,
            &to_req(true),
            Duration::from_secs(self.config.timeout_seconds),
        )?;
        if copied.exit_code != 0 {
            tracing::warn!(
                "openssl x509 -copy_extensions failed; imported certificate renewals will not keep SANs"
            );
            self.run_ok(dir, &to_req(false))
                .context("failed to derive a CSR from the imported certificate")?;
        }
        let passout = write_pass_file(dir, "cert-p12.pass", password.as_bytes())?;
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
                &passout,
            ],
        )?;
        write_secret(&cert_dir.join("password.txt"), password.as_bytes())?;
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

    /// A certificate-only PKCS#12 truststore holding `cert_pem` under `alias`.
    /// The Oracle trusted-key-usage attribute (`-jdktrust`) makes Java load
    /// the entry as a `trustedCertEntry`; without it Java ignores the cert.
    pub fn truststore_pkcs12(
        &self,
        dir: &Path,
        cert_pem: &[u8],
        alias: &str,
        password: &str,
    ) -> Result<Vec<u8>> {
        tracing::debug!(workdir = %dir.display(), "creating PKCS12 truststore");
        fs::write(dir.join("truststore-cert.pem"), cert_pem)?;
        let passout = write_pass_file(dir, "truststore.pass", password.as_bytes())?;
        self.run_ok(
            dir,
            &[
                "pkcs12",
                "-export",
                "-nokeys",
                "-in",
                "truststore-cert.pem",
                "-jdktrust",
                "anyExtendedKeyUsage",
                "-caname",
                alias,
                "-out",
                "truststore.p12",
                "-passout",
                &passout,
            ],
        )?;
        Ok(fs::read(dir.join("truststore.p12"))?)
    }

    pub fn inspect_cert_text(&self, dir: &Path, pem: &str) -> Result<String> {
        tracing::debug!(workdir = %dir.display(), "inspecting certificate text with openssl");
        fs::write(dir.join("inspect-text.pem"), pem)?;
        let out = self.run_ok(dir, &["x509", "-in", "inspect-text.pem", "-noout", "-text"])?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        tracing::debug!(bytes = text.len(), "inspected certificate text");
        Ok(text)
    }

    /// The certificate subject in escaped RFC 2253 syntax (kept in DER order),
    /// so values containing ',' '+' or '=' can be split unambiguously.
    pub fn inspect_cert_subject_rfc2253(&self, dir: &Path, pem: &str) -> Result<String> {
        tracing::debug!(workdir = %dir.display(), "inspecting certificate subject with openssl");
        fs::write(dir.join("inspect-subject.pem"), pem)?;
        let out = self.run_ok(
            dir,
            &[
                "x509",
                "-in",
                "inspect-subject.pem",
                "-noout",
                "-subject",
                "-nameopt",
                "RFC2253,-esc_msb,-dn_rev",
            ],
        )?;
        let text = String::from_utf8_lossy(&out.stdout);
        let text = text.trim();
        Ok(text
            .strip_prefix("subject=")
            .unwrap_or(text)
            .trim()
            .to_string())
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
        // `x509 -ext` is an OpenSSL 1.1.1 addition that LibreSSL never adopted.
        // If it fails (e.g. LibreSSL's "unknown option"), fall back to the full
        // `-text` dump, which prints SAN entries in the same DNS:/IP Address:
        // form that `parse_san_entries` scans for.
        let out = self.run_in(
            dir,
            &[
                "x509",
                "-in",
                "inspect-san.pem",
                "-noout",
                "-ext",
                "subjectAltName",
            ],
            Duration::from_secs(self.config.timeout_seconds),
        )?;
        let text = if out.exit_code == 0 {
            String::from_utf8_lossy(&out.stdout).to_string()
        } else {
            let out = self.run_ok(dir, &["x509", "-in", "inspect-san.pem", "-noout", "-text"])?;
            String::from_utf8_lossy(&out.stdout).to_string()
        };
        let (dns, ips) = parse_san_entries(&text);
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
            // Flag the workdir so `keep_failed_workdirs` retains it.
            let _ = fs::write(cwd.join(FAILED_MARKER), args.first().copied().unwrap_or(""));
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
        let failed = self.path.join(FAILED_MARKER).exists();
        if !(self.keep || (self.keep_failed && failed)) {
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
    for (label, value) in [
        ("common name", common_name),
        ("country code", country_code),
        ("organization", organization),
        ("state", state),
        ("city", city),
        ("organization unit", organization_unit),
    ] {
        if value.chars().any(char::is_control) {
            bail!("{label} must not contain control characters or newlines");
        }
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

/// Escapes a value for `openssl -subj`. Besides the `/` RDN separator, `+`
/// starts a multi-valued RDN (always enabled in OpenSSL 3) and `=` separates
/// type from value, so all of them are backslash-escaped.
fn escape_subject(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if matches!(ch, '\\' | '/' | '+' | '=') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Normalizes a digest name ("SHA-512", "-sha512", " sha512 ") and rejects
/// anything outside `SUPPORTED_DIGESTS`, since the result becomes an openssl
/// command-line flag.
pub fn normalize_digest(input: &str) -> Result<String> {
    let normalized = input
        .trim()
        .trim_start_matches('-')
        .replace('-', "")
        .to_ascii_lowercase();
    if SUPPORTED_DIGESTS.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        bail!(
            "digest algorithm must be one of {}",
            SUPPORTED_DIGESTS.join(", ")
        )
    }
}

/// A random positive 128-bit serial in hex: the first byte is kept below
/// 0x80 (positive in DER) and non-zero (no leading-zero ambiguity).
pub fn random_serial_hex() -> String {
    let mut bytes: [u8; 16] = rand::rng().random();
    bytes[0] &= 0x7f;
    if bytes[0] == 0 {
        bytes[0] = 0x01;
    }
    hex::encode_upper(bytes)
}

/// Writes a file readable only by the owner (key material, passwords, CA
/// state), instead of relying on the process umask.
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(bytes)?;
    Ok(())
}

/// Writes a password for openssl's `file:` source and returns the argument.
/// Passing `pass:<secret>` would expose it in the process list. openssl reads
/// the first line, so a trailing newline keeps an empty password valid.
fn write_pass_file(dir: &Path, name: &str, password: &[u8]) -> Result<String> {
    if password.iter().any(|b| matches!(b, b'\n' | b'\r')) {
        bail!("password must not contain newlines");
    }
    let mut content = password.to_vec();
    content.push(b'\n');
    write_secret(&dir.join(name), &content)?;
    Ok(format!("file:{name}"))
}

fn export_ca_state(dir: &Path, ca: &CaSecrets) -> Result<()> {
    fs::write(dir.join("ca-cert.pem"), &ca.cert_pem)?;
    write_secret(&dir.join("ca-key.pem"), &ca.key_pem)?;
    write_secret(&dir.join("index.txt"), &ca.index_txt)?;
    write_secret(&dir.join("serial.txt"), &ca.serial_txt)?;
    // CAs created before CRL numbering have no stored crlnumber; start at 1.
    let crlnumber: &[u8] = if ca.crlnumber_txt.iter().all(u8::is_ascii_whitespace) {
        INITIAL_CRL_NUMBER
    } else {
        &ca.crlnumber_txt
    };
    write_secret(&dir.join("crlnumber.txt"), crlnumber)?;
    Ok(())
}

fn read_crl_refresh(dir: &Path) -> Result<CrlRefresh> {
    Ok(CrlRefresh {
        crl_der: fs::read(dir.join("ca.crl"))?,
        index_txt: fs::read(dir.join("index.txt"))?,
        serial_txt: fs::read(dir.join("serial.txt"))?,
        crlnumber_txt: fs::read(dir.join("crlnumber.txt"))?,
    })
}

/// After `ca -revoke` marked `serial` as 'R', marks every other still-valid
/// index.txt entry with the same subject DN as revoked too, copying the
/// revocation date/reason. Renewals reuse the subject (and key) under a new
/// serial, and active certificate CNs are unique per CA, so the subject is
/// what ties a certificate's serial history together. Returns the new index
/// text and how many extra entries were revoked.
fn revoke_superseded_index_entries(index: &str, serial: &str) -> (String, usize) {
    fn same_serial(a: &str, b: &str) -> bool {
        a.trim_start_matches('0')
            .eq_ignore_ascii_case(b.trim_start_matches('0'))
    }
    let lines: Vec<&str> = index.lines().collect();
    let revoked = lines.iter().find_map(|line| {
        let fields: Vec<&str> = line.split('\t').collect();
        (fields.len() >= 6 && fields[0] == "R" && same_serial(fields[3], serial))
            .then(|| (fields[2].to_string(), fields[5..].join("\t")))
    });
    let Some((revocation, subject)) = revoked else {
        return (index.to_string(), 0);
    };
    let mut count = 0;
    let mut out = String::with_capacity(index.len());
    for line in lines {
        let mut fields: Vec<&str> = line.split('\t').collect();
        if fields.len() >= 6 && fields[0] == "V" && fields[5..].join("\t") == subject {
            fields[0] = "R";
            fields[2] = &revocation;
            count += 1;
            out.push_str(&fields.join("\t"));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    (out, count)
}

/// Escapes a value written into a generated openssl config file. Backslash
/// makes the next character literal, which neutralizes `$` variable expansion
/// (e.g. `${ENV::SECRET}`), `#` comments and quotes. Newlines cannot be
/// escaped and must be rejected by input validation before this point.
fn conf_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '\\' | '$' | '#' | '"' | '\'') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
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
    let cert = CertSecrets {
        cert_pem: fs::read(cert_dir.join("cert.pem"))?,
        key_pem: fs::read(cert_dir.join("cert.key"))?,
        csr_pem: fs::read(cert_dir.join("cert.csr"))?,
        pkcs12: fs::read(cert_dir.join("cert.p12"))?,
        password: fs::read(cert_dir.join("password.txt"))?,
        bundle_zip: Vec::new(),
    };
    build_bundle(&cert, &fs::read(ca_dir.join("ca-cert.pem"))?)
}

/// The certificate download bundle (ZIP), with `ca_cert_pem` as its `ca.pem`.
/// Also used to refresh existing bundles after the CA certificate is renewed.
pub fn build_bundle(cert: &CertSecrets, ca_cert_pem: &[u8]) -> Result<Vec<u8>> {
    let cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default();
    for (bytes, zip_name) in [
        (&cert.csr_pem[..], "cert.csr"),
        (&cert.key_pem[..], "cert.key"),
        (&cert.pkcs12[..], "cert.p12"),
        (&cert.cert_pem[..], "cert.pem"),
        (&cert.password[..], "cert-p12-password.txt"),
        (ca_cert_pem, "ca.pem"),
    ] {
        zip.start_file(zip_name, opts)?;
        zip.write_all(bytes)?;
    }
    Ok(zip.finish()?.into_inner())
}

fn ca_config(base: &Path, crl_days: i64, crl_url: Option<&str>) -> String {
    // Every interpolated value is escaped so the config parser never expands
    // `$` references or comments from it; callers validate against newlines.
    let base = conf_escape(&base.display().to_string());
    let crl_extension = crl_url
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("crlDistributionPoints = URI:{}\n", conf_escape(value)))
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
crlnumber = $base_dir/crlnumber.txt
crl_extensions = crl_extensions
x509_extensions = ca_extensions
email_in_dn = no
copy_extensions = copy

[ crl_extensions ]
authorityKeyIdentifier = keyid:always

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

/// Request config for a leaf CSR. `dns_list` is the complete DNS SAN list
/// (the service decides whether the CN is included). The subject always comes
/// from `-subj`, so no subject values are written here.
fn cert_config(dns_list: &[String], ip_list: &[String]) -> String {
    let dns = dns_list
        .iter()
        .enumerate()
        .map(|(i, v)| format!("DNS.{} = {}", i + 1, conf_escape(v)))
        .collect::<Vec<_>>()
        .join("\n");
    let ips = ip_list
        .iter()
        .enumerate()
        .map(|(i, v)| format!("IP.{} = {}", i + 1, conf_escape(v)))
        .collect::<Vec<_>>()
        .join("\n");
    // An empty alternate_names section is an openssl error, so omit the SAN
    // extension entirely when there is nothing to put in it.
    let san = if dns_list.is_empty() && ip_list.is_empty() {
        ""
    } else {
        "subjectAltName = @alternate_names\n"
    };
    format!(
        r#"[ req ]
default_bits = 4096
distinguished_name = server_distinguished_name
req_extensions = server_req_extensions
string_mask = utf8only

[ server_distinguished_name ]
commonName = Common Name

[ server_req_extensions ]
subjectKeyIdentifier = hash
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, keyAgreement, nonRepudiation
extendedKeyUsage = critical, serverAuth, clientAuth
{san}nsComment = "OpenSSL Generated Certificate"

[ alternate_names ]
{dns}
{ips}
"#
    )
}

/// Extract `DNS:` and `IP Address:` SAN entries from openssl output — either
/// the compact `x509 -ext subjectAltName` form or the full `-text` dump. Only
/// the value line following the "Subject Alternative Name:" header is read,
/// so `DNS:` entries of other extensions (e.g. name constraints) are ignored.
fn parse_san_entries(text: &str) -> (Vec<String>, Vec<String>) {
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    let mut lines = text.lines();
    let values = loop {
        match lines.next() {
            Some(line) if line.contains("Subject Alternative Name:") => {
                break lines.next().unwrap_or_default();
            }
            Some(_) => continue,
            None => return (dns, ips),
        }
    };
    for part in values.split(',') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("DNS:") {
            dns.push(value.trim().to_string());
        } else if let Some(value) = part.strip_prefix("IP Address:") {
            ips.push(value.trim().to_string());
        }
    }
    (dns, ips)
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
    fn parse_san_entries_reads_ext_and_text_forms() {
        // `x509 -ext subjectAltName` output
        let ext = "X509v3 Subject Alternative Name:\n    DNS:a.example.com, DNS:b.example.com, IP Address:10.0.0.5\n";
        let (dns, ips) = parse_san_entries(ext);
        assert_eq!(dns, vec!["a.example.com", "b.example.com"]);
        assert_eq!(ips, vec!["10.0.0.5"]);

        // fragment of a full `x509 -text` dump (LibreSSL fallback path)
        let text = "        X509v3 extensions:\n            X509v3 Basic Constraints:\n                CA:FALSE\n            X509v3 Subject Alternative Name:\n                DNS:a.example.com, IP Address:10.0.0.5\n    Signature Algorithm: sha512WithRSAEncryption\n";
        let (dns, ips) = parse_san_entries(text);
        assert_eq!(dns, vec!["a.example.com"]);
        assert_eq!(ips, vec!["10.0.0.5"]);

        let (dns, ips) = parse_san_entries("no san here\n");
        assert!(dns.is_empty() && ips.is_empty());
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

    fn real_openssl(keep_failed_workdirs: bool) -> OpenSsl {
        OpenSsl::new(OpenSslConfig {
            path: PathBuf::from("/usr/bin/openssl"),
            timeout_seconds: 30,
            working_root: std::env::temp_dir().join("minica-openssl-unit"),
            keep_failed_workdirs,
            reap_after_hours: 24,
        })
    }

    #[test]
    fn escape_subject_blocks_multi_valued_rdn_injection() {
        assert_eq!(escape_subject(r"a/b\c+CN=d"), r"a\/b\\c\+CN\=d");
        let subject = create_subject("foo+CN=bar", "SG", "Org", "", "", "").unwrap();
        assert_eq!(subject, r"/C=SG/O=Org/CN=foo\+CN\=bar");
        assert!(create_subject("foo\nbar", "SG", "Org", "", "", "").is_err());
        assert!(create_subject("foo", "SG", "Org\r", "", "", "").is_err());
        assert!(create_subject("foo", "SG", "Org", "", "x\u{0}", "").is_err());
    }

    #[test]
    fn normalize_digest_allows_only_sha2_family() {
        assert_eq!(normalize_digest("SHA-512").unwrap(), "sha512");
        assert_eq!(normalize_digest(" -sha256 ").unwrap(), "sha256");
        assert_eq!(normalize_digest("sha384").unwrap(), "sha384");
        for bad in ["md5", "sha1", "", "sha256 -engine x", "config"] {
            assert!(normalize_digest(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn random_serial_is_positive_128_bit_hex() {
        for _ in 0..200 {
            let serial = random_serial_hex();
            assert_eq!(serial.len(), 32);
            let first = u8::from_str_radix(&serial[..2], 16).unwrap();
            assert!(first > 0 && first < 0x80, "bad first byte in {serial}");
        }
        assert_ne!(random_serial_hex(), random_serial_hex());
    }

    #[test]
    fn conf_escape_neutralizes_variable_expansion_end_to_end() {
        assert_eq!(conf_escape(r#"a${ENV::X}#"'\"#), r#"a\${ENV::X}\#\"\'\\"#);
        // Feed an injection attempt through the generated config to openssl
        // and check the SAN comes out literally instead of expanded.
        let openssl = real_openssl(false);
        let work = openssl.workdir().unwrap();
        let dir = work.path();
        fs::write(
            dir.join("openssl-cert.conf"),
            cert_config(&["a${ENV::HOME}b".to_string()], &["10.0.0.1".to_string()]),
        )
        .unwrap();
        openssl
            .generate_key(dir, "k.pem", "ecdsa", &serde_json::json!({}))
            .unwrap();
        openssl
            .run_ok(
                dir,
                &[
                    "req",
                    "-config",
                    "openssl-cert.conf",
                    "-new",
                    "-key",
                    "k.pem",
                    "-subj",
                    "/CN=x",
                    "-out",
                    "r.csr",
                ],
            )
            .unwrap();
        let text = openssl
            .run_ok(dir, &["req", "-in", "r.csr", "-noout", "-text"])
            .unwrap();
        let text = String::from_utf8_lossy(&text.stdout);
        assert!(text.contains("DNS:a${ENV::HOME}b"), "{text}");
        assert!(text.contains("IP Address:10.0.0.1"));
        // No SAN entries at all: the extension is omitted instead of empty.
        assert!(!cert_config(&[], &[]).contains("subjectAltName"));
    }

    #[test]
    fn revoke_superseded_index_entries_revokes_same_subject_only() {
        let index = "V\t271121115248Z\t\t0A\tunknown\t/CN=leaf\n\
                     R\t261027115248Z\t261017115248Z,keyCompromise\t0B\tunknown\t/CN=leaf\n\
                     V\t261027115248Z\t\t0C\tunknown\t/CN=other\n";
        let (out, count) = revoke_superseded_index_entries(index, "0b");
        assert_eq!(count, 1);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[0],
            "R\t271121115248Z\t261017115248Z,keyCompromise\t0A\tunknown\t/CN=leaf"
        );
        assert!(lines[2].starts_with("V\t"));
        // Unknown serial: nothing changes.
        let (same, none) = revoke_superseded_index_entries(index, "FF");
        assert_eq!((same.as_str(), none), (index, 0));
    }

    #[test]
    fn parse_san_entries_ignores_name_constraints() {
        let text = "            X509v3 Name Constraints: critical\n                Permitted:\n                  DNS:corp.example\n            X509v3 Subject Alternative Name: critical\n                DNS:a.example.com, IP Address:10.0.0.5\n";
        let (dns, ips) = parse_san_entries(text);
        assert_eq!(dns, vec!["a.example.com"]);
        assert_eq!(ips, vec!["10.0.0.5"]);
    }

    #[cfg(unix)]
    #[test]
    fn workdirs_are_private_and_kept_only_on_failure() {
        use std::os::unix::fs::PermissionsExt;
        let openssl = real_openssl(true);
        let ok = openssl.workdir().unwrap();
        let ok_path = ok.path().to_path_buf();
        assert_eq!(
            fs::metadata(&ok_path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let pass = write_pass_file(&ok_path, "p.pass", b"secret").unwrap();
        assert_eq!(pass, "file:p.pass");
        assert_eq!(fs::read(ok_path.join("p.pass")).unwrap(), b"secret\n");
        assert_eq!(
            fs::metadata(ok_path.join("p.pass"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(write_pass_file(&ok_path, "q.pass", b"a\nb").is_err());
        openssl.run_ok(&ok_path, &["version"]).unwrap();
        drop(ok);
        assert!(!ok_path.exists(), "successful workdir must be removed");

        let failed = openssl.workdir().unwrap();
        let failed_path = failed.path().to_path_buf();
        assert!(
            openssl
                .run_ok(&failed_path, &["x509", "-in", "missing.pem"])
                .is_err()
        );
        drop(failed);
        assert!(failed_path.exists(), "failed workdir must be kept");
        let _ = fs::remove_dir_all(failed_path);
    }
}
