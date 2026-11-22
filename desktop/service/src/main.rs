use anyhow::{Context, Result, ensure};
use clyntis_desktop_model::protocol::FrameReader;
use clyntis_desktop_model::tr;
use clyntis_desktop_model::{
    private_dir,
    profiles::{safe_relative, validate},
    protocol::{self, Request, Response, VERSION},
};
use clyntis_desktop_service::{system_proxy::ProxyGuard, transport};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
mod diagnostics;

#[cfg(windows)]
mod windows;

fn main() {
    #[cfg(windows)]
    {
        windows::entry();
    }
    #[cfg(not(windows))]
    {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(async {
            let stop = CancellationToken::new();
            let token = stop.clone();
            tokio::spawn(async move {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .unwrap();
                term.recv().await;
                token.cancel();
            });
            serve(stop).await
        });
        if let Err(error) = result {
            eprintln!("clyntis-service: {error:#}");
            std::process::exit(1);
        }
    }
}

fn data_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        Ok(
            clyntis_desktop_service::windows_security::local_path(&std::env::current_exe()?)?
                .parent()
                .context("missing install directory")?
                .join("service-data"),
        )
    }
    #[cfg(not(windows))]
    {
        Ok(PathBuf::from(
            "/Library/Application Support/org.clyntis.desktop.service",
        ))
    }
}

async fn serve(
    stop: CancellationToken,
    #[cfg(windows)] ready: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let root = data_dir()?;
    private_dir(&root)?;
    #[cfg(windows)]
    windows::protect_data(&root)?;
    #[cfg(target_os = "macos")]
    clyntis_desktop_service::trusted::prepare(&root)?;
    // Service data lives in an administrator-owned directory, never in the client's home.
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if Uuid::parse_str(&name).is_ok() {
            clyntis_runtime::recover(&entry.path())?;
        } else if name.starts_with(STAGING_PREFIX) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
    let _ = ProxyGuard::recover(root.join("system-proxy.json"))?;
    let listener = transport::Listener::bind()?;
    #[cfg(windows)]
    ready()?;
    loop {
        let stream = tokio::select! { _ = stop.cancelled() => break, result = listener.accept() => match result { Ok(s) => s, Err(e) => { eprintln!("client rejected: {e}"); continue; } } };
        // Only one authenticated desktop session can own network changes at a time.
        if let Err(error) = session(stream, &root, stop.clone()).await {
            eprintln!(
                "session: {}",
                clyntis_desktop_model::redact(&format!("{error:#}"))
            );
        }
    }
    Ok(())
}

struct Runner {
    child: Child,
    input: ChildStdin,
    output: FrameReader<ChildStdout>,
    directory: PathBuf,
    diagnostics: diagnostics::Diagnostics,
    stderr_task: tokio::task::JoinHandle<()>,
    exit_error: Option<String>,
}
impl Runner {
    async fn check(&mut self) -> Result<()> {
        if let Some(error) = &self.exit_error {
            anyhow::bail!("{error}");
        }
        if let Some(status) = self.child.try_wait()? {
            let _ = tokio::time::timeout(Duration::from_secs(1), &mut self.stderr_task).await;
            let message = tokio::time::timeout(
                Duration::from_secs(1),
                protocol::read_frame(&mut self.output),
            )
            .await;
            let detail = match message {
                Ok(Ok(Some(line))) => match serde_json::from_str::<Response>(&line) {
                    Ok(Response::Error { message, .. }) => message,
                    _ => self.diagnostics.tail(),
                },
                _ => self.diagnostics.tail(),
            };
            self.diagnostics.record(
                &self.directory,
                &tr!(
                    "内核退出（{status}）：{detail}",
                    "Core exited ({status}): {detail}"
                ),
            );
            let error = tr!(
                "内核进程已退出（{status}）：{detail}",
                "The core process exited ({status}): {detail}"
            );
            self.exit_error = Some(error.clone());
            anyhow::bail!("{error}");
        }
        Ok(())
    }
    async fn stop(&mut self) -> Result<()> {
        let _ = protocol::write_frame(&mut self.input, &Request::Stop { version: VERSION }).await;
        match tokio::time::timeout(Duration::from_secs(20), self.child.wait()).await {
            Ok(status) => {
                status?;
            }
            Err(_) => {
                self.child.kill().await?;
                self.child.wait().await?;
            }
        }
        let exit = if self
            .child
            .try_wait()?
            .is_some_and(|status| !status.success())
        {
            self.check().await
        } else {
            Ok(())
        };
        let recovery = clyntis_runtime::recover(&self.directory);
        exit.and(recovery)
    }
}

const MAX_RESOURCE_CHUNK: usize = 2 * 1024 * 1024;
const MAX_RESOURCE_TOTAL: usize = 128 * 1024 * 1024;
const MAX_RESOURCE_FILES: usize = 512;
const STAGING_PREFIX: &str = "staging-";

struct PendingResources {
    root: PathBuf,
    staging_dir: Option<PathBuf>,
    files: std::collections::BTreeMap<String, PathBuf>,
    active: Option<(String, std::fs::File)>,
    total_size: usize,
}

impl PendingResources {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            staging_dir: None,
            files: std::collections::BTreeMap::new(),
            active: None,
            total_size: 0,
        }
    }

    fn close_active(&mut self) -> Result<()> {
        if let Some((_, file)) = self.active.take() {
            file.sync_all()?;
        }
        Ok(())
    }

    fn open_staged(&mut self, name: &str) -> Result<&mut std::fs::File> {
        let same = self
            .active
            .as_ref()
            .is_some_and(|(active_name, _)| active_name == name);
        if !same {
            self.close_active()?;
            let file = if let Some(path) = self.files.get(name) {
                std::fs::OpenOptions::new().append(true).open(path)?
            } else {
                ensure!(
                    self.files.len() < MAX_RESOURCE_FILES,
                    "invalid resource chunk"
                );
                let dir = match &self.staging_dir {
                    Some(dir) => dir.clone(),
                    None => {
                        let dir = self
                            .root
                            .join(format!("{STAGING_PREFIX}{}", Uuid::new_v4()));
                        private_dir(&dir)?;
                        self.staging_dir = Some(dir.clone());
                        dir
                    }
                };
                let staged = dir.join(format!("resource-{:04}", self.files.len()));
                let mut options = std::fs::OpenOptions::new();
                options.create_new(true).write(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let file = options.open(&staged)?;
                self.files.insert(name.to_owned(), staged);
                file
            };
            self.active = Some((name.to_owned(), file));
        }
        Ok(&mut self.active.as_mut().unwrap().1)
    }

    fn append(&mut self, name: String, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        safe_relative(&name)?;
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_RESOURCE_CHUNK,
            "invalid resource chunk"
        );
        if !self.files.contains_key(&name) {
            ensure!(
                self.files.len() < MAX_RESOURCE_FILES,
                "invalid resource chunk"
            );
        }
        let next_total = self
            .total_size
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_RESOURCE_TOTAL)
            .context("routing resources exceed 128 MiB")?;
        let file = self.open_staged(&name)?;
        file.write_all(bytes)?;
        self.total_size = next_total;
        Ok(())
    }

    fn commit_into(&mut self, directory: &std::path::Path, allowed: &[String]) -> Result<()> {
        self.close_active()?;
        for name in self.files.keys() {
            ensure!(allowed.contains(name), "unreferenced routing resource");
            safe_relative(name)?;
        }
        let files = std::mem::take(&mut self.files);
        self.total_size = 0;
        let result: Result<()> = (|| {
            for (name, staged) in files {
                let destination = directory.join(safe_relative(&name)?);
                if let Some(parent) = destination.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                #[cfg(windows)]
                if destination.exists() {
                    std::fs::remove_file(&destination)?;
                }
                std::fs::rename(&staged, &destination)?;
            }
            Ok(())
        })();
        self.clear();
        result
    }

    fn clear(&mut self) {
        self.active = None;
        self.files.clear();
        self.total_size = 0;
        if let Some(dir) = self.staging_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl Drop for PendingResources {
    fn drop(&mut self) {
        self.clear();
    }
}

async fn session(
    stream: transport::Stream,
    root: &std::path::Path,
    stop: CancellationToken,
) -> Result<()> {
    let mut stream = FrameReader::new(stream);
    let mut runner: Option<Runner> = None;
    let mut proxy = ProxyGuard::recover(root.join("system-proxy.json"))?;
    let mut refresh = tokio::time::interval(Duration::from_secs(5));
    let mut deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut pending_resources = PendingResources::new(root.to_path_buf());
    let result: Result<()> = async { loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = tokio::time::sleep_until(deadline) => anyhow::bail!("desktop heartbeat expired"),
            _ = refresh.tick() => {
                proxy.refresh()?;
                if let Some(child) = &mut runner { child.check().await?; }
            },
            line = protocol::read_frame(&mut stream) => {
                let Some(line) = line? else { break; };
                let request: Request = serde_json::from_str(&line).context("invalid desktop request JSON")?;
                ensure!(request.version() == VERSION, "IPC version mismatch");
                deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                let response = match request {
                    Request::Ping { .. } => {
                        if let Some(child) = &mut runner { child.check().await?; }
                        Response::Ok { version: VERSION }
                    },
                    Request::Status { .. } => Response::Status { version: VERSION, running: runner.is_some(), build: Some(protocol::SERVICE_BUILD.into()) },
                    Request::Proxy { port, .. } => {
                        #[cfg(windows)] { let _ = port; anyhow::bail!("system proxy must run in the user session"); }
                        #[cfg(not(windows))] { proxy.enable(port)?; Response::Ok { version: VERSION } }
                    },
                    Request::Resource { name, data, .. } => {
                        use base64::Engine;
                        ensure!(runner.is_none(), "cannot replace running resources");
                        let bytes = base64::engine::general_purpose::STANDARD.decode(data)?;
                        pending_resources.append(name, &bytes)?;
                        Response::Ok { version: VERSION }
                    },
                    Request::Start { version, yaml, profile_id, system_proxy_port, language } => {
                        clyntis_desktop_model::i18n::set(language.as_deref().unwrap_or("zh"));
                        ensure!(runner.is_none(), "already running");
                        ensure!(system_proxy_port.is_none(), "service cannot set a user's proxy");
                        let config = validate(&yaml)?;
                        ensure!(config.tun.enable, "service only starts TUN cores");
                        ensure!(config.log.log_path.is_empty() && config.external_ui.is_empty(), "unsafe paths");
                        ensure!(config.external_controller.as_deref() == Some("127.0.0.1:0") && config.secret.len() >= 32, "unsafe controller");
                        let directory = root.join(Uuid::parse_str(&profile_id)?.to_string());
                        private_dir(&directory)?;
                        clyntis_runtime::recover(&directory)?;
                        let names = clyntis_desktop_model::profiles::resource_names(&config);
                        pending_resources.commit_into(&directory, &names)?;
                        let mut command = tokio::process::Command::new(clyntis_desktop_service::sibling("clyntis-runner")?);
                        command.arg("--directory").arg(&directory).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
                        #[cfg(windows)] command.creation_flags(0x08000000);
                        let mut child = command.spawn()?;
                        let input = child.stdin.take().context("missing runner stdin")?;
                        let output = FrameReader::new(child.stdout.take().context("missing runner stdout")?);
                        let stderr = child.stderr.take().context("missing runner stderr")?;
                        let diagnostics = diagnostics::Diagnostics::default();
                        let capture = diagnostics.clone();
                        let log_directory = directory.clone();
                        let stderr_task = tokio::spawn(async move { capture.capture(stderr, log_directory).await; });
                        runner = Some(Runner { child, input, output, directory, diagnostics, stderr_task, exit_error: None });
                        let child = runner.as_mut().unwrap();
                        protocol::write_frame(&mut child.input, &Request::Start { version, yaml, profile_id, system_proxy_port: None, language }).await?;
                        let line = tokio::select! {
                            _ = stop.cancelled() => anyhow::bail!("service stopping"),
                            result = tokio::time::timeout(Duration::from_secs(100), protocol::read_frame(&mut child.output)) => result??.context("runner exited before ready")?,
                        };
                        deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                        let response: Response = serde_json::from_str(&line).context("invalid core start response JSON")?;
                        if let Response::Error { message, .. } = response { anyhow::bail!("{message}"); }
                        response
                    },
                    Request::Stop { .. } => {
                        pending_resources.clear();
                        if let Some(child) = &mut runner { child.stop().await?; } runner = None;
                        proxy.restore()?;
                        protocol::write_frame(stream.get_mut(), &Response::Stopped { version: VERSION }).await?;
                        break;
                    }
                };
                protocol::write_frame(stream.get_mut(), &response).await?;
            }
        }
    } Ok(()) }.await;
    // Always attempt both cleanups, including errors during startup or IPC writes.
    let runner_cleanup = if let Some(mut child) = runner {
        child.stop().await
    } else {
        Ok(())
    };
    let proxy_cleanup = proxy.restore();
    if let Err(error) = &result {
        let _ = protocol::write_frame(
            stream.get_mut(),
            &Response::Error {
                version: VERSION,
                message: clyntis_desktop_model::redact(&format!("{error:#}")),
            },
        )
        .await;
    }
    result.and(runner_cleanup).and(proxy_cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_exit_reports_status_and_structured_error() {
        let directory = std::env::temp_dir().join(format!("clyntis-exit-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let mut child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "printf '%s\\n' '{\"event\":\"error\",\"version\":1,\"message\":\"cannot update TUN routing: File exists\"}'; exit 7"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let output = FrameReader::new(child.stdout.take().unwrap());
        child.wait().await.unwrap();
        let mut runner = Runner {
            child,
            input,
            output,
            directory: directory.clone(),
            diagnostics: diagnostics::Diagnostics::default(),
            stderr_task: tokio::spawn(async {}),
            exit_error: None,
        };
        let error = runner.check().await.unwrap_err().to_string();
        assert_eq!(runner.check().await.unwrap_err().to_string(), error);
        assert!(error.contains("7"));
        assert!(error.contains("cannot update TUN routing: File exists"));
        assert!(
            std::fs::read_to_string(directory.join("clyntis-runner.log"))
                .unwrap()
                .contains("File exists")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pending_resources_stream_to_disk_commit_and_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join(Uuid::new_v4().to_string());
        std::fs::create_dir(&dest).unwrap();

        let mut pending = PendingResources::new(root.path().to_path_buf());
        pending.append("geoip.dat".into(), b"hello ").unwrap();
        pending
            .append("rule_provider/list.yaml".into(), b"payload:\n")
            .unwrap();
        pending.append("geoip.dat".into(), b"world").unwrap();

        let staging_dir = pending.staging_dir.clone().unwrap();
        assert!(staging_dir.exists());

        // Unreferenced resource is rejected without touching destination.
        assert!(
            pending
                .commit_into(&dest, &["geoip.dat".into()])
                .unwrap_err()
                .to_string()
                .contains("unreferenced")
        );
        assert!(!dest.join("geoip.dat").exists());

        pending
            .commit_into(
                &dest,
                &["geoip.dat".into(), "rule_provider/list.yaml".into()],
            )
            .unwrap();
        assert!(!staging_dir.exists());
        assert_eq!(
            std::fs::read(dest.join("geoip.dat")).unwrap(),
            b"hello world"
        );
        assert_eq!(
            std::fs::read(dest.join("rule_provider/list.yaml")).unwrap(),
            b"payload:\n"
        );
    }

    #[test]
    fn pending_resources_drop_removes_staging_directory_and_enforces_limits() {
        let root = tempfile::tempdir().unwrap();
        let staging_dir = {
            let mut pending = PendingResources::new(root.path().to_path_buf());
            assert!(pending.append("geoip.dat".into(), b"").is_err());
            assert!(
                pending
                    .append("geoip.dat".into(), &vec![1u8; MAX_RESOURCE_CHUNK + 1])
                    .is_err()
            );
            pending.append("geoip.dat".into(), b"chunk").unwrap();
            let dir = pending.staging_dir.clone().unwrap();
            assert!(dir.exists());
            dir
        };
        assert!(!staging_dir.exists());
    }
}
