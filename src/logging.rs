use crate::config::LoggingConfig;
use anyhow::{Context, Result};
use flate2::{Compression, write::GzEncoder};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread::JoinHandle,
};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
pub struct RotatingFileMakeWriter {
    state: Arc<Mutex<RotatingState>>,
}

struct RotatingState {
    path: PathBuf,
    rotate_size_bytes: u64,
    max_backups: usize,
    compress: bool,
    file: Option<File>,
    current_size: u64,
    /// In-flight background gzip of the last rotated file.
    compression: Option<JoinHandle<()>>,
}

pub struct RotatingFileWriter {
    state: Arc<Mutex<RotatingState>>,
}

impl RotatingFileMakeWriter {
    pub fn new(config: &LoggingConfig) -> Result<Self> {
        if let Some(parent) = config.file.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create log directory {}", parent.display())
                })?;
            }
        }
        let file = open_log_file(&config.file)?;
        let current_size = file.metadata()?.len();
        // A staging file left by a crash mid-compression is the newest backup
        // (backups were already shifted), so finish compressing it into slot 1.
        let staging = staging_path(&config.file);
        let compression = (config.compress && config.max_backups > 0 && staging.exists())
            .then(|| spawn_compression(staging, backup_path(&config.file, 1, true)));
        Ok(Self {
            state: Arc::new(Mutex::new(RotatingState {
                path: config.file.clone(),
                rotate_size_bytes: config.rotate_size_bytes.max(1),
                max_backups: config.max_backups,
                compress: config.compress,
                file: Some(file),
                current_size,
                compression,
            })),
        })
    }

    /// Block until any background compression has finished (tests).
    #[cfg(test)]
    fn wait_for_compression(&self) {
        self.state
            .lock()
            .expect("log writer mutex poisoned")
            .wait_for_compression();
    }
}

impl<'a> MakeWriter<'a> for RotatingFileMakeWriter {
    type Writer = RotatingFileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RotatingFileWriter {
            state: self.state.clone(),
        }
    }
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut state = self.state.lock().expect("log writer mutex poisoned");
        state.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut state = self.state.lock().expect("log writer mutex poisoned");
        if let Some(file) = state.file.as_mut() {
            file.flush()
        } else {
            Ok(())
        }
    }
}

impl RotatingState {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.current_size > 0
            && self.current_size.saturating_add(buf.len() as u64) > self.rotate_size_bytes
        {
            self.rotate()?;
        }
        let Some(file) = self.file.as_mut() else {
            return Ok(0);
        };
        let written = file.write(buf)?;
        self.current_size = self.current_size.saturating_add(written as u64);
        Ok(written)
    }

    /// Rotate the active file. Never fails the caller's write: on error the
    /// current handle is kept (or the path reopened) and the size counter is
    /// reset, so logging continues and rotation is retried only after another
    /// `rotate_size_bytes` instead of on every line.
    fn rotate(&mut self) -> std::io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
        }
        if let Err(err) = self.rotate_files() {
            eprintln!(
                "minica: log rotation of {} failed: {err}",
                self.path.display()
            );
        }
        match open_log_file_io(&self.path) {
            Ok(file) => self.file = Some(file),
            Err(err) => {
                eprintln!(
                    "minica: reopening log file {} failed: {err}",
                    self.path.display()
                );
                if self.file.is_none() {
                    return Err(err);
                }
            }
        }
        self.current_size = 0;
        Ok(())
    }

    /// Shift backups and move the active file to backup 1. With compression,
    /// the file is renamed to a staging path and gzipped on a background
    /// thread so the log mutex is not held while compressing.
    fn rotate_files(&mut self) -> std::io::Result<()> {
        // A previous compression must finish before backups are shifted, or
        // it could still be writing `.1.gz` while that file is renamed.
        self.wait_for_compression();
        if self.max_backups == 0 {
            let _ = fs::remove_file(&self.path);
            return Ok(());
        }

        let oldest = backup_path(&self.path, self.max_backups, self.compress);
        let _ = fs::remove_file(oldest);
        for index in (1..self.max_backups).rev() {
            let from = backup_path(&self.path, index, self.compress);
            let to = backup_path(&self.path, index + 1, self.compress);
            if from.exists() {
                let _ = fs::rename(from, to);
            }
        }

        if self.path.exists() {
            let first = backup_path(&self.path, 1, self.compress);
            if self.compress {
                let staging = staging_path(&self.path);
                fs::rename(&self.path, &staging)?;
                self.compression = Some(spawn_compression(staging, first));
            } else {
                fs::rename(&self.path, first)?;
            }
        }
        Ok(())
    }

    fn wait_for_compression(&mut self) {
        if let Some(handle) = self.compression.take() {
            let _ = handle.join();
        }
    }
}

/// Where the active file is parked between rename and compression.
fn staging_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.rotating", path.display()))
}

/// Gzip `staging` into `destination` off the logging path, then delete it.
fn spawn_compression(staging: PathBuf, destination: PathBuf) -> JoinHandle<()> {
    std::thread::spawn(move || match compress_file(&staging, &destination) {
        Ok(()) => {
            let _ = fs::remove_file(&staging);
        }
        Err(err) => eprintln!(
            "minica: compressing rotated log {} failed: {err}",
            staging.display()
        ),
    })
}

fn open_log_file(path: &Path) -> Result<File> {
    open_log_file_io(path).with_context(|| format!("failed to open log file {}", path.display()))
}

fn open_log_file_io(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn backup_path(path: &Path, index: usize, compress: bool) -> PathBuf {
    let suffix = if compress {
        format!("{index}.gz")
    } else {
        index.to_string()
    };
    PathBuf::from(format!("{}.{}", path.display(), suffix))
}

fn compress_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    let mut input = File::open(source)?;
    let output = File::create(destination)?;
    let mut encoder = GzEncoder::new(output, Compression::default());
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        encoder.write_all(&buffer[..read])?;
    }
    encoder.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use uuid::Uuid;

    #[test]
    fn rotates_and_compresses_log_files() {
        let root = std::env::temp_dir().join(format!("minica-log-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create temp log folder");
        let path = root.join("minica.log");
        let writer = RotatingFileMakeWriter::new(&LoggingConfig {
            file: path.clone(),
            rotate_size_bytes: 12,
            max_backups: 2,
            compress: true,
        })
        .expect("create rotating writer");

        let mut first = writer.make_writer();
        first.write_all(b"first line\n").expect("write first line");
        first
            .write_all(b"second line\n")
            .expect("write second line");
        first.flush().expect("flush logs");
        writer.wait_for_compression();
        assert!(!staging_path(&path).exists(), "staging file removed");

        let mut rotated = String::new();
        GzDecoder::new(File::open(backup_path(&path, 1, true)).expect("open rotated log"))
            .read_to_string(&mut rotated)
            .expect("read rotated log");
        assert!(rotated.contains("first line"));
        assert!(
            fs::read_to_string(&path)
                .expect("read active log")
                .contains("second line")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn failed_rotation_keeps_logging() {
        let root = std::env::temp_dir().join(format!("minica-log-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create temp log folder");
        let path = root.join("minica.log");
        let writer = RotatingFileMakeWriter::new(&LoggingConfig {
            file: path.clone(),
            rotate_size_bytes: 12,
            max_backups: 1,
            compress: false,
        })
        .expect("create rotating writer");
        // A directory squatting on the backup slot makes the rename fail.
        fs::create_dir_all(backup_path(&path, 1, false).join("blocker")).expect("block slot");

        let mut out = writer.make_writer();
        out.write_all(b"first line\n").expect("write first line");
        out.write_all(b"second line\n")
            .expect("write after failed rotation");
        out.flush().expect("flush logs");
        let text = fs::read_to_string(&path).expect("read active log");
        assert!(
            text.contains("first line") && text.contains("second line"),
            "{text}"
        );

        let _ = fs::remove_dir_all(root);
    }
}
