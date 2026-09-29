use anyhow::{Context, Result, ensure};
use clyntis_desktop_model::protocol::FrameReader;
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
        Ok(std::env::current_exe()?
            .parent()
            .context("missing install directory")?
            .join("service-data"))
    }
    #[cfg(not(windows))]
    {
        Ok(PathBuf::from(
            "/Library/Application Support/org.clyntis.desktop.service",
        ))
    }
}

async fn serve(stop: CancellationToken) -> Result<()> {
    let root = data_dir()?;
    private_dir(&root)?;
    #[cfg(windows)]
    windows::protect_data(&root)?;
    #[cfg(target_os = "macos")]
    clyntis_desktop_service::trusted::prepare(&root)?;
    // Service data lives in an administrator-owned directory, never in the client's home.
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if Uuid::parse_str(&entry.file_name().to_string_lossy()).is_ok() {
            meta_runtime::recover(&entry.path())?;
        }
    }
    let _ = ProxyGuard::recover(root.join("system-proxy.json"))?;
    let listener = transport::Listener::bind()?;
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
            self.diagnostics
                .record(&self.directory, &format!("内核退出（{status}）：{detail}"));
            let error = format!("内核进程已退出（{status}）：{detail}");
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
        let recovery = meta_runtime::recover(&self.directory);
        exit.and(recovery)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

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
    let mut pending_resources = std::collections::BTreeMap::<String, Vec<u8>>::new();
    let mut resource_size = 0usize;
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
                let request: Request = serde_json::from_str(&line).context("桌面请求不是有效的 JSON")?;
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
                        safe_relative(&name)?;
                        let bytes = base64::engine::general_purpose::STANDARD.decode(data)?;
                        ensure!(!bytes.is_empty() && bytes.len() <= 2 * 1024 * 1024 && pending_resources.len() < 512, "invalid resource chunk");
                        resource_size += bytes.len();
                        ensure!(resource_size <= 128 * 1024 * 1024, "routing resources exceed 128 MiB");
                        pending_resources.entry(name).or_default().extend(bytes);
                        Response::Ok { version: VERSION }
                    },
                    Request::Start { version, yaml, profile_id, system_proxy_port } => {
                        ensure!(runner.is_none(), "already running");
                        ensure!(system_proxy_port.is_none(), "service cannot set a user's proxy");
                        let config = validate(&yaml)?;
                        ensure!(config.tun.enable, "service only starts TUN cores");
                        ensure!(config.log.log_path.is_empty() && config.external_ui.is_empty(), "unsafe paths");
                        ensure!(config.external_controller.as_deref() == Some("127.0.0.1:0") && config.secret.len() >= 32, "unsafe controller");
                        let directory = root.join(Uuid::parse_str(&profile_id)?.to_string());
                        private_dir(&directory)?;
                        meta_runtime::recover(&directory)?;
                        let names = clyntis_desktop_model::profiles::resource_names(&config);
                        for (name, bytes) in std::mem::take(&mut pending_resources) {
                            ensure!(names.contains(&name), "unreferenced routing resource");
                            clyntis_desktop_model::atomic_write(&directory.join(safe_relative(&name)?), &bytes)?;
                        }
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
                        protocol::write_frame(&mut child.input, &Request::Start { version, yaml, profile_id, system_proxy_port: None }).await?;
                        let line = tokio::select! {
                            _ = stop.cancelled() => anyhow::bail!("service stopping"),
                            result = tokio::time::timeout(Duration::from_secs(100), protocol::read_frame(&mut child.output)) => result??.context("runner exited before ready")?,
                        };
                        deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                        let response: Response = serde_json::from_str(&line).context("内核启动响应不是有效的 JSON")?;
                        if let Response::Error { message, .. } = response { anyhow::bail!("{message}"); }
                        response
                    },
                    Request::Stop { .. } => {
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
