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
    });
}

/// Calls `take` with the buffered lines (newline-separated JSON objects with
/// `time`, `type` and `payload`); they are removed only when `take` reports
/// that it consumed them, so a too-small caller buffer loses nothing.
pub(crate) fn drain(take: impl FnOnce(&[u8]) -> anyhow::Result<bool>) -> anyhow::Result<()> {
    let mut buffer = BUFFER.lock().unwrap();
    let mut joined = Vec::new();
    for line in buffer.iter() {
        joined.extend_from_slice(line.as_bytes());
        joined.push(b'\n');
    }
    if take(&joined)? {
        buffer.clear();
    }
    Ok(())
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
        let level = match *event.metadata().level() {
            tracing::Level::WARN => "warning".to_owned(),
            level => level.as_str().to_ascii_lowercase(),
        };
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        push(serde_json::json!({"time": time, "type": level, "payload": fields.0}).to_string());
    }
}

#[cfg(test)]
pub(crate) fn record_for_test(line: &str) {
    push(line.to_owned());
}
