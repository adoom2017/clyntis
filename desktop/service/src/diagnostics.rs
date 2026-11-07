//! Bounded, redacted stderr capture for privileged runners. Paths are selected
//! by the service, never supplied by the client.
use clyntis_desktop_model::tr;
use std::{
    collections::VecDeque,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

/// Rotation size of `clyntis-runner.log`.
const LOG_LIMIT: u64 = 1024 * 1024;

#[derive(Clone, Default)]
pub struct Diagnostics(Arc<Mutex<Inner>>);
#[derive(Default)]
struct Inner {
    lines: VecDeque<String>,
    log: Option<LogFile>,
}
/// Kept open between lines. Reopening the file for every line of a busy
/// runner (each one also scanned by antivirus software on Windows) let the
/// reader fall behind, and a full stderr pipe stalls the runner.
struct LogFile {
    path: PathBuf,
    file: std::fs::File,
    size: u64,
}
impl LogFile {
    fn open(path: PathBuf) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let size = file.metadata()?.len();
        Ok(Self { path, file, size })
    }
}
impl Diagnostics {
    pub fn tail(&self) -> String {
        self.0
            .lock()
            .unwrap()
            .lines
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    }
    pub fn record(&self, directory: &std::path::Path, message: &str) {
        let message = clyntis_desktop_model::redact(message);
        let mut inner = self.0.lock().unwrap();
        if inner.lines.len() == 8 {
            inner.lines.pop_front();
        }
        inner.lines.push_back(message.clone());
        let path = directory.join("clyntis-runner.log");
        let line = format!("{} {message}\n", clyntis_desktop_model::now());
        // Diagnostics must not interrupt network cleanup if the disk is full.
        let written = (|| -> std::io::Result<()> {
            if inner.log.as_ref().is_none_or(|log| log.path != path) {
                inner.log = Some(LogFile::open(path.clone())?);
            }
            if inner.log.as_ref().is_some_and(|log| log.size >= LOG_LIMIT) {
                // Closed before the rename, which Windows refuses otherwise.
                inner.log = None;
                std::fs::rename(&path, directory.join("clyntis-runner.previous.log"))?;
                inner.log = Some(LogFile::open(path.clone())?);
            }
            let log = inner.log.as_mut().unwrap();
            log.file.write_all(line.as_bytes())?;
            log.size += line.len() as u64;
            Ok(())
        })();
        if written.is_err() {
            // Reopened on the next line, e.g. after the file was removed.
            inner.log = None;
        }
    }
    pub async fn capture(&self, stderr: impl AsyncRead + Unpin, directory: PathBuf) {
        let mut reader = BufReader::new(stderr);
        loop {
            let mut line = vec![];
            match (&mut reader).take(8192).read_until(b'\n', &mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    // Do not log fragments: splitting credential fields could
                    // otherwise defeat redaction. Drain oversized lines.
                    if line.last() != Some(&b'\n') {
                        while line.last() != Some(&b'\n') {
                            line.clear();
                            match (&mut reader).take(8192).read_until(b'\n', &mut line).await {
                                Ok(0) | Err(_) => return,
                                _ => {}
                            }
                        }
                        self.record(
                            &directory,
                            &tr!("[过长日志已省略]", "[overlong log omitted]"),
                        );
                    } else {
                        self.record(&directory, String::from_utf8_lossy(&line).trim());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn captures_redacted_tail_and_discards_oversized_lines() {
        let directory =
            std::env::temp_dir().join(format!("clyntis-diagnostics-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let diagnostics = Diagnostics::default();
        let input = format!("password=private\n{}\nfinal failure\n", "x".repeat(9000));
        diagnostics
            .capture(input.as_bytes(), directory.clone())
            .await;
        let output = std::fs::read_to_string(directory.join("clyntis-runner.log")).unwrap();
        assert!(!output.contains("private"));
        assert!(output.contains("[过长日志已省略]"));
        assert!(diagnostics.tail().contains("final failure"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn the_runner_log_rotates_while_kept_open() {
        let directory =
            std::env::temp_dir().join(format!("clyntis-diagnostics-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let diagnostics = Diagnostics::default();
        let line = "x".repeat(1000);
        for _ in 0..1100 {
            diagnostics.record(&directory, &line);
        }
        diagnostics.record(&directory, "after rotation");
        let current = std::fs::read_to_string(directory.join("clyntis-runner.log")).unwrap();
        let previous = std::fs::metadata(directory.join("clyntis-runner.previous.log")).unwrap();
        assert!(previous.len() >= LOG_LIMIT);
        assert!(current.ends_with("after rotation\n"));
        assert!((current.len() as u64) < LOG_LIMIT);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
