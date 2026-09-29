use anyhow::{Context, Result};
use chrono::Utc;
use flate2::{Compression, write::GzEncoder};
use meta_config::Log;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::sync::broadcast;
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, filter::LevelFilter, layer::Context as LayerContext, prelude::*};

pub fn init(config: &Log, directory: &Path, events: broadcast::Sender<String>) -> Result<()> {
    let filter = match config.log_level.as_str() {
        "debug" => LevelFilter::DEBUG,
        "warning" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        "silent" => LevelFilter::OFF,
        _ => LevelFilter::INFO,
    };
    let writer = if config.log_path.is_empty() {
        None
    } else {
        Some(RotatingFile::open(
            directory.join(&config.log_path),
            config.clone(),
        )?)
    };
    let writer = Arc::new(Mutex::new(writer));
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || LogWriter(writer.clone())),
        )
        .with(EventLayer(events))
        .try_init()
        .context("cannot initialize logging")?;
    Ok(())
}

struct LogWriter(Arc<Mutex<Option<RotatingFile>>>);
impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut writer = self
            .0
            .lock()
            .map_err(|_| io::Error::other("log writer poisoned"))?;
        if let Some(file) = writer.as_mut() {
            file.write(bytes)
        } else {
            io::stderr().lock().write(bytes)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut writer = self
            .0
            .lock()
            .map_err(|_| io::Error::other("log writer poisoned"))?;
        if let Some(file) = writer.as_mut() {
            file.flush()
        } else {
            io::stderr().lock().flush()
        }
    }
}

struct EventLayer(broadcast::Sender<String>);
#[derive(Default)]
struct EventFields(String);
impl Visit for EventFields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, "{}={value:?}", field.name());
        }
    }
}
impl<S: Subscriber> Layer<S> for EventLayer {
    fn on_event(&self, event: &Event<'_>, _: LayerContext<'_, S>) {
        let mut fields = EventFields::default();
        event.record(&mut fields);
        let level = if *event.metadata().level() == tracing::Level::WARN {
            "warning".into()
        } else {
            event.metadata().level().as_str().to_ascii_lowercase()
        };
        let _ = self
            .0
            .send(serde_json::json!({"type": level, "payload": fields.0}).to_string());
    }
}

struct RotatingFile {
    path: PathBuf,
    config: Log,
    file: Option<File>,
    size: u64,
    limit: u64,
}
impl RotatingFile {
    fn open(path: PathBuf, config: Log) -> io::Result<Self> {
        let limit = config
            .max_size
            .checked_mul(1024 * 1024)
            .filter(|size| *size > 0)
            .ok_or_else(|| io::Error::other("invalid log.max-size"))?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().append(true).create(true).open(&path)?;
        let size = file.metadata()?.len();
        let mut writer = Self {
            path,
            config,
            file: Some(file),
            size,
            limit,
        };
        writer.cleanup()?;
        Ok(writer)
    }

    fn backup_prefix(&self) -> String {
        format!(
            "{}.backup-",
            self.path.file_name().unwrap_or_default().to_string_lossy()
        )
    }

    fn rotate(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }
        let stamp = Utc::now().format("%Y%m%dT%H%M%S%.9fZ");
        let name = format!("{}{stamp}-{}", self.backup_prefix(), std::process::id());
        let backup = self.path.with_file_name(name);
        // Close the handle before renaming so rotation also works on Windows.
        let renamed = fs::rename(&self.path, &backup);
        self.file = Some(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(&self.path)?,
        );
        self.size = self.file.as_ref().unwrap().metadata()?.len();
        renamed?;
        if self.config.compress {
            let compressed = backup.with_file_name(format!(
                "{}.gz",
                backup.file_name().unwrap().to_string_lossy()
            ));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&compressed)?;
            let mut encoder = GzEncoder::new(file, Compression::default());
            let result = (|| {
                io::copy(&mut File::open(&backup)?, &mut encoder)?;
                encoder.finish()?.sync_all()
            })();
            if let Err(error) = result {
                let _ = fs::remove_file(compressed);
                return Err(error);
            }
            fs::remove_file(backup)?;
        }
        self.cleanup()
    }

    fn cleanup(&mut self) -> io::Result<()> {
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let prefix = self.backup_prefix();
        let mut backups = Vec::new();
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(suffix) = name.strip_prefix(&prefix) else {
                continue;
            };
            let suffix = suffix.strip_suffix(".gz").unwrap_or(suffix);
            let Some((stamp, pid)) = suffix.rsplit_once('-') else {
                continue;
            };
            if chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%dT%H%M%S%.9fZ").is_err()
                || pid.parse::<u32>().is_err()
                || !entry.file_type()?.is_file()
            {
                continue;
            }
            backups.push((entry.metadata()?.modified()?, entry.path()));
        }
        backups.sort_by(|a, b| b.cmp(a));
        let age = Duration::from_secs(self.config.max_age.saturating_mul(86400));
        for (index, (modified, path)) in backups.into_iter().enumerate() {
            let expired = self.config.max_age > 0
                && SystemTime::now()
                    .duration_since(modified)
                    .is_ok_and(|elapsed| elapsed > age);
            if expired || (self.config.max_backups > 0 && index >= self.config.max_backups) {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }
}
impl Write for RotatingFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.size > 0 && self.size.saturating_add(bytes.len() as u64) > self.limit {
            self.rotate()?;
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("log file unavailable"))?;
        let written = file.write(bytes)?;
        self.size += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("log file unavailable"))?
            .flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn rotation_compresses_and_limits_only_owned_backups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta.log");
        let config = Log {
            max_backups: 1,
            ..Log::default()
        };
        let mut writer = RotatingFile::open(path.clone(), config).unwrap();
        writer.limit = 8;
        fs::write(dir.path().join("meta.log.backup-not-a-backup"), b"keep").unwrap();
        writer.write_all(b"first123").unwrap();
        writer.write_all(b"second12").unwrap();
        writer.write_all(b"third").unwrap();
        writer.flush().unwrap();
        assert_eq!(fs::read(path).unwrap(), b"third");
        let files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "gz"))
            .collect();
        assert_eq!(files.len(), 1);
        let mut content = String::new();
        flate2::read::GzDecoder::new(File::open(&files[0]).unwrap())
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "second12");
        assert!(dir.path().join("meta.log.backup-not-a-backup").exists());
    }

    #[test]
    fn log_events_reach_controller_subscribers() {
        let (sender, mut receiver) = broadcast::channel(4);
        let subscriber = tracing_subscriber::registry().with(EventLayer(sender));
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!("test log");
        });
        let event: serde_json::Value = serde_json::from_str(&receiver.try_recv().unwrap()).unwrap();
        assert_eq!(event["type"], "warning");
        assert_eq!(event["payload"], "test log");
    }
}
