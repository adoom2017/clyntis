//! Bounded, redacted stderr capture for privileged runners. Paths are selected
//! by the service, never supplied by the client.
use std::{
    collections::VecDeque,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

#[derive(Clone, Default)]
pub struct Diagnostics(Arc<Mutex<VecDeque<String>>>);
impl Diagnostics {
    pub fn tail(&self) -> String {
        self.0
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    }
    pub fn record(&self, directory: &std::path::Path, message: &str) {
        let message = clyntis_desktop_model::redact(message);
        let mut lines = self.0.lock().unwrap();
        if lines.len() == 8 {
            lines.pop_front();
        }
        lines.push_back(message.clone());
        let path = directory.join("clyntis-runner.log");
        // Diagnostics must not interrupt network cleanup if the disk is full.
        let _ = (|| -> std::io::Result<()> {
            if std::fs::metadata(&path).is_ok_and(|m| m.len() >= 1024 * 1024) {
                std::fs::rename(&path, directory.join("clyntis-runner.previous.log"))?;
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            writeln!(file, "{} {message}", clyntis_desktop_model::now())
        })();
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
                        self.record(&directory, "[过长日志已省略]");
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
}
