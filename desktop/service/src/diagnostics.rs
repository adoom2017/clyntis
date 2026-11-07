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
const LOG_LIMIT: u64 = 8 * 1024 * 1024;
/// Rotated files kept, `clyntis-runner.1.log` (newest) and up. A busy core
/// logs a few MiB an hour; 1 MiB plus one previous file held under an hour.
const LOG_GENERATIONS: usize = 5;
const LOG_NAME: &str = "clyntis-runner";

/// The runner log files in `directory`, oldest first.
// Used by the app through the library; the service binary compiles this
// module on its own.
#[allow(dead_code)]
pub fn log_files(directory: &std::path::Path) -> Vec<PathBuf> {
    (1..=LOG_GENERATIONS)
        .rev()
        .map(|n| generation(directory, n))
        .chain([directory.join(format!("{LOG_NAME}.log"))])
        .filter(|path| path.is_file())
        .collect()
}
fn generation(directory: &std::path::Path, n: usize) -> PathBuf {
    directory.join(format!("{LOG_NAME}.{n}.log"))
}
/// Drops the oldest file and shifts the others up by one.
fn rotate(directory: &std::path::Path, current: &std::path::Path) -> std::io::Result<()> {
    let _ = std::fs::remove_file(generation(directory, LOG_GENERATIONS));
    for n in (1..LOG_GENERATIONS).rev() {
        let from = generation(directory, n);
        if from.exists() {
            std::fs::rename(from, generation(directory, n + 1))?;
        }
    }
    // Written by earlier versions, which kept only this one.
    let _ = std::fs::remove_file(directory.join(format!("{LOG_NAME}.previous.log")));
    std::fs::rename(current, generation(directory, 1))
}

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
        let path = directory.join(format!("{LOG_NAME}.log"));
        let line = format!("{} {message}\n", clyntis_desktop_model::now());
        // Diagnostics must not interrupt network cleanup if the disk is full.
        let written = (|| -> std::io::Result<()> {
            if inner.log.as_ref().is_none_or(|log| log.path != path) {
                inner.log = Some(LogFile::open(path.clone())?);
            }
            if inner.log.as_ref().is_some_and(|log| log.size >= LOG_LIMIT) {
                // Closed before the rename, which Windows refuses otherwise.
                inner.log = None;
                rotate(directory, &path)?;
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
        std::fs::write(directory.join("clyntis-runner.previous.log"), "legacy").unwrap();
        let diagnostics = Diagnostics::default();
        let line = "x".repeat(64 * 1024);
        // Seven files' worth: the two oldest are dropped.
        for _ in 0..(7 * LOG_LIMIT as usize / line.len() + 1) {
            diagnostics.record(&directory, &line);
        }
        diagnostics.record(&directory, "after rotation");
        let files = log_files(&directory);
        assert_eq!(files.len(), LOG_GENERATIONS + 1);
        assert_eq!(files[0], directory.join("clyntis-runner.5.log"));
        assert_eq!(files[5], directory.join("clyntis-runner.log"));
        for rotated in &files[..5] {
            assert!(std::fs::metadata(rotated).unwrap().len() >= LOG_LIMIT);
        }
        let current = std::fs::read_to_string(&files[5]).unwrap();
        assert!(current.ends_with("after rotation\n"));
        assert!(!directory.join("clyntis-runner.previous.log").exists());
        assert!(!directory.join("clyntis-runner.6.log").exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
