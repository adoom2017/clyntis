use anyhow::{Context, Result};
use chrono::Utc;
use clyntis_config::Log;
use flate2::{Compression, write::GzEncoder};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    time::{Duration, Instant, SystemTime},
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
    let (queue, lines) = Queue::new(QUEUE_LINES);
    let installed = queue.clone();
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || queue.clone()),
        )
        .with(EventLayer(events))
        .try_init()
        .context("cannot initialize logging")?;
    let output: Box<dyn Write + Send> = match writer {
        Some(file) => Box::new(file),
        None => Box::new(io::stderr()),
    };
    std::thread::Builder::new()
        .name("clyntis-log".into())
        .spawn(move || lines.run(output))
        .context("cannot start the log writer")?;
    let _ = QUEUE.set(installed);
    Ok(())
}

/// Waits up to two seconds for queued log lines to be written, so the last
/// lines before the process exits are not lost.
pub fn flush() {
    if let Some(queue) = QUEUE.get() {
        queue.flush(Duration::from_secs(2));
    }
}

/// Lines waiting for the writer thread before new ones are dropped.
const QUEUE_LINES: usize = 8192;
static QUEUE: OnceLock<Queue> = OnceLock::new();

enum Message {
    Line(Vec<u8>),
    Flushed(mpsc::Sender<()>),
}

/// Log output for every thread of the core. Writing went straight to stderr
/// or the log file under one lock: desktop runners log to a pipe that the
/// app or service reads line by line, and when that reader lagged (antivirus
/// scanning its file writes, an app throttled in the background) the full
/// pipe blocked every thread that logged, the TUN packet loop included, and
/// rotating a compressed file stalled them too. Lines now go to a bounded
/// queue that a dedicated thread writes out; when it is full they are counted
/// and dropped, never waited for.
#[derive(Clone)]
struct Queue {
    sender: SyncSender<Message>,
    dropped: Arc<AtomicU64>,
}
struct Lines {
    receiver: Receiver<Message>,
    dropped: Arc<AtomicU64>,
}
impl Queue {
    fn new(capacity: usize) -> (Self, Lines) {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let queue = Self {
            sender,
            dropped: dropped.clone(),
        };
        (queue, Lines { receiver, dropped })
    }
    fn flush(&self, timeout: Duration) {
        let (done, flushed) = mpsc::channel();
        let deadline = Instant::now() + timeout;
        let mut message = Message::Flushed(done);
        loop {
            match self.sender.try_send(message) {
                Ok(()) => break,
                Err(TrySendError::Full(again)) if Instant::now() < deadline => {
                    message = again;
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
        let _ = flushed.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    }
}
impl Write for Queue {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // The formatter writes each event in one call.
        if let Err(TrySendError::Full(_)) = self.sender.try_send(Message::Line(bytes.to_vec())) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Lines {
    fn run(self, mut output: Box<dyn Write + Send>) {
        while let Ok(message) = self.receiver.recv() {
            let dropped = self.dropped.swap(0, Ordering::Relaxed);
            if dropped > 0 {
                let _ = writeln!(
                    output,
                    "{} WARN {dropped} log lines dropped: the log output could not keep up",
                    Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ")
                );
            }
            match message {
                Message::Line(line) => {
                    let _ = output.write_all(&line);
                }
                Message::Flushed(done) => {
                    let _ = output.flush();
                    let _ = done.send(());
                }
            }
        }
        let _ = output.flush();
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
    use std::{io::Read, sync::Mutex};

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_stalled_log_output_drops_lines_instead_of_blocking_the_core() {
        // Nobody reads yet, as when the pipe reader lags: logging returns at once.
        let (mut queue, lines) = Queue::new(2);
        for index in 0..5 {
            // As the formatter does: one write per event.
            queue
                .write_all(format!("line {index}\n").as_bytes())
                .unwrap();
        }
        assert_eq!(queue.dropped.load(Ordering::Relaxed), 3);
        let output = Shared::default();
        let written = output.clone();
        let writer = std::thread::spawn(move || lines.run(Box::new(written)));
        queue.flush(Duration::from_secs(2));
        let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("3 log lines dropped"), "{text}");
        assert!(text.ends_with("line 0\nline 1\n"), "{text}");
        drop(queue);
        writer.join().unwrap();
    }

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
