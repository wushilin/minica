use crate::config::LoggingConfig;
use anyhow::{Context, Result};
use flate2::{Compression, write::GzEncoder};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
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
        Ok(Self {
            state: Arc::new(Mutex::new(RotatingState {
                path: config.file.clone(),
                rotate_size_bytes: config.rotate_size_bytes.max(1),
                max_backups: config.max_backups,
                compress: config.compress,
                file: Some(file),
                current_size,
            })),
        })
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

    fn rotate(&mut self) -> std::io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }
        if self.max_backups == 0 {
            let _ = fs::remove_file(&self.path);
            self.file = Some(open_log_file_io(&self.path)?);
            self.current_size = 0;
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
                compress_file(&self.path, &first)?;
                let _ = fs::remove_file(&self.path);
            } else {
                fs::rename(&self.path, first)?;
            }
        }

        self.file = Some(open_log_file_io(&self.path)?);
        self.current_size = 0;
        Ok(())
    }
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
}
