use anyhow::{Context, Result, ensure};
use clyntis_desktop_model::{
    private_dir,
    profiles::{safe_relative, validate},
    protocol::{self, Request, Response, VERSION},
};
use clyntis_desktop_service::{system_proxy::ProxyGuard, transport};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::BufReader,
    process::{Child, ChildStdin, ChildStdout},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

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
    output: BufReader<ChildStdout>,
    directory: PathBuf,
}
impl Runner {
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
        meta_runtime::recover(&self.directory)?;
        Ok(())
    }
}

async fn session(
    stream: transport::Stream,
    root: &std::path::Path,
    stop: CancellationToken,
) -> Result<()> {
    let mut stream = BufReader::new(stream);
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
                if let Some(child) = &mut runner { ensure!(child.child.try_wait()?.is_none(), "core exited unexpectedly"); }
            },
            line = protocol::read_frame(&mut stream) => {
                let Some(line) = line? else { break; };
                let request: Request = serde_json::from_str(&line)?;
                ensure!(request.version() == VERSION, "IPC version mismatch");
                deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                let response = match request {
                    Request::Ping { .. } => Response::Ok { version: VERSION },
                    Request::Status { .. } => Response::Status { version: VERSION, running: runner.is_some() },
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
                        command.arg("--directory").arg(&directory).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
                        #[cfg(windows)] command.creation_flags(0x08000000);
                        let mut child = command.spawn()?;
                        let input = child.stdin.take().context("missing runner stdin")?;
                        let output = BufReader::new(child.stdout.take().context("missing runner stdout")?);
                        runner = Some(Runner { child, input, output, directory });
                        let child = runner.as_mut().unwrap();
                        protocol::write_frame(&mut child.input, &Request::Start { version, yaml, profile_id, system_proxy_port: None }).await?;
                        let line = tokio::select! {
                            _ = stop.cancelled() => anyhow::bail!("service stopping"),
                            result = tokio::time::timeout(Duration::from_secs(100), protocol::read_frame(&mut child.output)) => result??.context("runner exited before ready")?,
                        };
                        deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                        let response: Response = serde_json::from_str(&line)?;
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
