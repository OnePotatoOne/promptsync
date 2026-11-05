//! Tiny size-rotating logger (text lines, UTC timestamps, optional stderr).

use anyhow::{Context, Result};
use chrono::Utc;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn parse(value: &str) -> Level {
        match value.trim().to_ascii_lowercase().as_str() {
            "debug" | "trace" => Level::Debug,
            "warn" | "warning" => Level::Warn,
            "error" => Level::Error,
            _ => Level::Info,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

struct Inner {
    level: Level,
    path: PathBuf,
    file: Mutex<File>,
    size: Mutex<u64>,
    max_bytes: u64,
    keep: usize,
    stderr: bool,
}

#[derive(Clone)]
pub struct Logger {
    inner: Arc<Inner>,
}

impl Logger {
    pub fn new(
        dir: &Path,
        file_name: &str,
        level: Level,
        max_bytes: u64,
        keep: usize,
        stderr: bool,
    ) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("creating log dir {}", dir.display()))?;
        let path = dir.join(file_name);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening log file {}", path.display()))?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            inner: Arc::new(Inner {
                level,
                path,
                file: Mutex::new(file),
                size: Mutex::new(size),
                max_bytes: max_bytes.max(64 * 1024),
                keep: keep.max(1),
                stderr,
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    pub fn level(&self) -> Level {
        self.inner.level
    }

    pub fn debug(&self, message: impl AsRef<str>) {
        self.log(Level::Debug, message);
    }

    pub fn info(&self, message: impl AsRef<str>) {
        self.log(Level::Info, message);
    }

    pub fn warn(&self, message: impl AsRef<str>) {
        self.log(Level::Warn, message);
    }

    pub fn error(&self, message: impl AsRef<str>) {
        self.log(Level::Error, message);
    }

    pub fn log(&self, level: Level, message: impl AsRef<str>) {
        if level < self.inner.level && level != Level::Error {
            return;
        }
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
        let line = format!("{timestamp} {:<5} {}\n", level.label(), message.as_ref());
        if self.inner.stderr {
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
        if let Ok(mut file) = self.inner.file.lock() {
            if file.write_all(line.as_bytes()).is_err() {
                return;
            }
            let _ = file.flush();
            if let Ok(mut size) = self.inner.size.lock() {
                *size += line.len() as u64;
                if *size > self.inner.max_bytes {
                    *size = 0;
                    drop(size);
                    self.rotate_locked(&mut file);
                }
            }
        }
    }

    fn rotate_locked(&self, file: &mut File) {
        let keep = self.inner.keep;
        let path = &self.inner.path;
        // log -> log.1 -> ... -> log.keep
        for index in (1..=keep).rev() {
            let target = PathBuf::from(format!("{}.{index}", path.display()));
            // Windows refuses to rename onto an existing file.
            let _ = fs::remove_file(&target);
            let source = if index == 1 {
                path.clone()
            } else {
                PathBuf::from(format!("{}.{}", path.display(), index - 1))
            };
            if source.exists() {
                let _ = fs::rename(&source, &target);
            }
        }
        if let Ok(new_file) = OpenOptions::new().create(true).append(true).open(path) {
            *file = new_file;
        }
    }
}
