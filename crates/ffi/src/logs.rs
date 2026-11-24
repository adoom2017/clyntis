//! Bounded in-process log buffer. Embedded hosts (iOS) have no controller log
//! stream, so core `tracing` events are kept here until the host drains them.
use std::{
    collections::VecDeque,
    sync::{Mutex, Once},
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, filter::LevelFilter, layer::Context, prelude::*};

/// Lines kept when the host does not drain; the oldest are dropped first.
const CAPACITY: usize = 2000;
static BUFFER: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
static INIT: Once = Once::new();
/// Where panics are also written at once, for a host whose process may not
/// live to drain the buffer (`<host directory>/panic.log`).
static PANIC_FILE: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

pub(crate) fn set_panic_file(path: std::path::PathBuf) {
    *PANIC_FILE.lock().unwrap_or_else(|e| e.into_inner()) = Some(path);
}

/// Installs the process-wide subscriber once, at the first core's log level.
pub(crate) fn init(level: &str) {
    let filter = match level {
        "debug" => LevelFilter::DEBUG,
        "warning" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        "silent" => LevelFilter::OFF,
        _ => LevelFilter::INFO,
    };
    INIT.call_once(|| {
        // Another subscriber (e.g. a test harness) may already be installed.
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(BufferLayer)
            .try_init();
        // Panics in tasks and threads are otherwise silent on hosts without
        // stderr: record them in the buffer and, synchronously, in a file.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            record_panic(info);
            previous(info);
        }));
    });
}

#[derive(serde::Serialize)]
struct LogEntry<'a> {
    time: f64,
    #[serde(rename = "type")]
    kind: &'a str,
    payload: &'a str,
}

/// Drains buffered lines into a pre-sized newline-separated byte buffer.
pub(crate) fn drain_bytes() -> Vec<u8> {
    let mut buffer = BUFFER.lock().unwrap();
    let total: usize = buffer.iter().map(|line| line.len() + 1).sum();
    let mut joined = Vec::with_capacity(total);
    for line in buffer.drain(..) {
        joined.extend_from_slice(line.as_bytes());
        joined.push(b'\n');
    }
    joined
}

fn record_panic(info: &std::panic::PanicHookInfo<'_>) {
    let thread = std::thread::current();
    let message = format!(
        "panic in thread {}: {info}\n{}",
        thread.name().unwrap_or("unnamed"),
        std::backtrace::Backtrace::force_capture()
    );
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64());
    // try_lock: the panic may have happened while a lock was held.
    if let Ok(mut buffer) = BUFFER.try_lock() {
        if buffer.len() == CAPACITY {
            buffer.pop_front();
        }
        if let Ok(line) = serde_json::to_string(&LogEntry {
            time,
            kind: "error",
            payload: &message,
        }) {
            buffer.push_back(line);
        }
    }
    if let Ok(path) = PANIC_FILE.try_lock()
        && let Some(path) = path.as_ref()
        && let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        use std::io::Write;
        let _ = writeln!(file, "{time:.3} {message}");
    }
}

fn push(line: String) {
    let mut buffer = BUFFER.lock().unwrap();
    if buffer.len() == CAPACITY {
        buffer.pop_front();
    }
    buffer.push_back(line);
}

struct BufferLayer;
#[derive(Default)]
struct Fields(String);
impl Visit for Fields {
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
impl<S: Subscriber> Layer<S> for BufferLayer {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let kind = match *event.metadata().level() {
            tracing::Level::TRACE => "trace",
            tracing::Level::DEBUG => "debug",
            tracing::Level::INFO => "info",
            tracing::Level::WARN => "warning",
            tracing::Level::ERROR => "error",
        };
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        if let Ok(line) = serde_json::to_string(&LogEntry {
            time,
            kind,
            payload: &fields.0,
        }) {
            push(line);
        }
    }
}

#[cfg(test)]
pub(crate) fn record_for_test(line: &str) {
    push(line.to_owned());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_entry_serializes_expected_json_shape() {
        let json = serde_json::to_string(&LogEntry {
            time: 123.5,
            kind: "warning",
            payload: "hello \"world\"",
        })
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["time"], 123.5);
        assert_eq!(parsed["type"], "warning");
        assert_eq!(parsed["payload"], "hello \"world\"");
    }
}
