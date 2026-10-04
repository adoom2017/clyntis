use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use clyntis_desktop_model::{
    profiles::{Profile, Store, resource_names, runtime_yaml, safe_relative, validate},
    protocol::{self, Request, Response, VERSION},
    settings::{Capture, Settings},
};
use clyntis_desktop_service::client::Client;
use futures_util::StreamExt;
use std::{
    collections::VecDeque,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tauri::Emitter;
use tokio::{
    io::BufReader,
    process::{Child, ChildStdin, ChildStdout},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub type Logs = Arc<Mutex<VecDeque<serde_json::Value>>>;
pub fn log(app: &tauri::AppHandle, logs: &Logs, level: &str, message: &str) {
    let message = clyntis_desktop_model::redact(message);
    let entry =
        serde_json::json!({"type":level,"payload":message,"time":clyntis_desktop_model::now()});
    let mut buffer = logs.lock().unwrap();
    if buffer.len() >= 2000 {
        buffer.pop_front();
    }
    buffer.push_back(entry.clone());
    let _ = app.emit("log", entry);
}

struct Process {
    child: Child,
    input: ChildStdin,
    output: protocol::FrameReader<ChildStdout>,
}
#[derive(Clone)]
pub struct Controller {
    address: std::net::SocketAddr,
    secret: String,
    client: reqwest::Client,
}
impl Controller {
    pub async fn request(
        &self,
        method: reqwest::Method,
        path: &[&str],
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let mut url = reqwest::Url::parse(&format!("http://{}/", self.address))?;
        url.path_segments_mut().unwrap().clear().extend(path);
        let mut request = self.client.request(method, url).bearer_auth(&self.secret);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.context("内核控制接口无法连接")?;
        let status = response.status();
        let value: serde_json::Value = response.json().await?;
        ensure!(
            status.is_success(),
            "{}",
            value["message"].as_str().unwrap_or("内核请求失败")
        );
        Ok(value)
    }
}
/// Download missing routing resources into the profile's runtime directory as
/// the desktop user, over the ordinary network. TUN sessions upload these files
/// to the service, so the core never has to fetch them while TUN routing is
/// being brought up.
pub async fn prefetch(store: &Store, profile: &Profile, settings: &Settings) -> Result<()> {
    let yaml = runtime_yaml(profile, settings, &"x".repeat(64))?;
    let mut config = validate(&yaml)?;
    let directory = store.runtime_dir(profile.id);
    clyntis_desktop_model::private_dir(&directory)?;
    config.directory = directory;
    meta_runtime::prefetch_resources(config).await
}

/// Background variant used after importing a subscription; failures are only logged.
pub fn spawn_prefetch(app: tauri::AppHandle, logs: Logs, store: Store, profile: Profile) {
    tokio::spawn(async move {
        let result = match store.settings() {
            Ok(settings) => prefetch(&store, &profile, &settings).await,
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            log(
                &app,
                &logs,
                "warning",
                &clyntis_desktop_model::redact(&format!(
                    "路由资源预下载失败，将在连接时重试：{error:#}"
                )),
            );
        }
    });
}

pub struct Engine {
    process: Option<Process>,
    service: Option<Arc<tokio::sync::Mutex<Client>>>,
    proxy_service: Option<Arc<tokio::sync::Mutex<Client>>>,
    address: std::net::SocketAddr,
    secret: String,
    streams: CancellationToken,
    client: reqwest::Client,
    heartbeat_error: Arc<Mutex<Option<String>>>,
}

impl Engine {
    pub async fn launch(
        app: &tauri::AppHandle,
        logs: Logs,
        store: &Store,
        profile: &Profile,
        settings: &Settings,
    ) -> Result<Self> {
        let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let yaml = runtime_yaml(profile, settings, &secret)?;
        let request = Request::Start {
            version: VERSION,
            yaml: yaml.clone(),
            profile_id: profile.id.to_string(),
            system_proxy_port: (cfg!(windows) && settings.capture == Capture::System)
                .then_some(settings.mixed_port),
        };
        let mut process = None;
        let mut service = None;
        let controller = if settings.capture == Capture::Tun {
            let mut connection = Client::connect_current().await?;
            let config = validate(&yaml)?;
            let mut total = 0;
            for name in resource_names(&config) {
                let path = store.runtime_dir(profile.id).join(safe_relative(&name)?);
                if !path.exists() {
                    continue;
                }
                let bytes = clyntis_desktop_model::read_limited(&path, 128 * 1024 * 1024)?;
                total += bytes.len();
                ensure!(total <= 128 * 1024 * 1024, "路由资源总量超过 128 MiB");
                for chunk in bytes.chunks(2 * 1024 * 1024) {
                    connection
                        .request(&Request::Resource {
                            version: VERSION,
                            name: name.clone(),
                            data: base64::engine::general_purpose::STANDARD.encode(chunk),
                        })
                        .await?;
                }
            }
            let response = connection.request(&request).await?;
            let address = ready(response)?;
            service = Some(Arc::new(tokio::sync::Mutex::new(connection)));
            address
        } else {
            let mut command =
                tokio::process::Command::new(clyntis_desktop_service::sibling("clyntis-runner")?);
            command
                .arg("--directory")
                .arg(store.runtime_dir(profile.id))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            #[cfg(windows)]
            command.creation_flags(0x08000000);
            let mut child = command
                .spawn()
                .context("无法启动内核，请重新构建或安装完整桌面应用")?;
            let mut input = child.stdin.take().context("runner stdin missing")?;
            let mut output =
                protocol::FrameReader::new(child.stdout.take().context("runner stdout missing")?);
            if let Some(stderr) = child.stderr.take() {
                let app = app.clone();
                let logs = logs.clone();
                let directory = store.runtime_dir(profile.id);
                let diagnostics = clyntis_desktop_service::diagnostics::Diagnostics::default();
                tokio::spawn(async move {
                    use tokio::io::AsyncBufReadExt;
                    let mut reader = BufReader::new(stderr);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line).await {
                            Ok(0) | Err(_) => break,
                            _ => {}
                        }
                        if line.len() < 65536 {
                            diagnostics.record(&directory, line.trim());
                            log(&app, &logs, "info", line.trim());
                        }
                    }
                });
            }
            protocol::write_frame(&mut input, &request).await?;
            let first =
                tokio::time::timeout(Duration::from_secs(110), protocol::read_frame(&mut output))
                    .await
                    .context("内核启动超时，请检查订阅资源和网络")??
                    .context("内核在启动完成前退出，请查看日志")?;
            let address =
                ready(serde_json::from_str(&first).context("内核启动响应不是有效的 JSON")?)?;
            process = Some(Process {
                child,
                input,
                output,
            });
            address
        };
        #[allow(unused_mut)] // macOS additionally attaches the system-proxy service.
        let mut engine = Self {
            process,
            service,
            proxy_service: None,
            address: controller,
            secret,
            streams: CancellationToken::new(),
            heartbeat_error: Arc::new(Mutex::new(None)),
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(35))
                .build()?,
        };
        #[cfg(target_os = "macos")]
        if settings.capture == Capture::System {
            let result = async {
                let mut service = Client::connect_current().await?;
                service
                    .request(&Request::Proxy {
                        version: VERSION,
                        port: settings.mixed_port,
                    })
                    .await?;
                engine.proxy_service = Some(Arc::new(tokio::sync::Mutex::new(service)));
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if let Err(error) = result {
                let _ = engine.stop().await;
                return Err(error);
            }
        }
        // Heartbeats must not wait behind UI actions (e.g. batches of node probes).
        for connection in [engine.service.clone(), engine.proxy_service.clone()]
            .into_iter()
            .flatten()
        {
            let token = engine.streams.clone();
            let failure = engine.heartbeat_error.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! { _ = token.cancelled() => break, _ = tokio::time::sleep(Duration::from_secs(5)) => {} }
                    // Complete an in-flight request before Stop uses this channel;
                    // otherwise an unread Pong could be mistaken for a stop acknowledgement.
                    let result = connection.lock().await.ping().await;
                    if let Err(error) = result {
                        *failure.lock().unwrap() = Some(error.to_string());
                        break;
                    }
                }
            });
        }
        engine.stream(app.clone(), logs.clone(), "traffic");
        engine.stream(app.clone(), logs, "logs");
        Ok(engine)
    }
    /// A detached handle to the controller API, usable without holding the operation lock.
    pub fn controller(&self) -> Controller {
        Controller {
            address: self.address,
            secret: self.secret.clone(),
            client: self.client.clone(),
        }
    }
    pub async fn request(
        &self,
        method: reqwest::Method,
        path: &[&str],
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        self.controller().request(method, path, body).await
    }
    pub async fn health(&mut self) -> Result<()> {
        if let Some(process) = &mut self.process {
            ensure!(
                process.child.try_wait()?.is_none(),
                "内核进程异常退出，请查看日志"
            );
        }
        if let Some(error) = self.heartbeat_error.lock().unwrap().clone() {
            anyhow::bail!("{error}");
        }
        if let Err(error) = self.request(reqwest::Method::GET, &["version"], None).await {
            // The local HTTP listener may close before the next heartbeat.
            // Ask the supervisor for the runner's exit status and actual error.
            if let Some(service) = &self.service {
                service.lock().await.ping().await?;
            }
            return Err(error);
        }
        Ok(())
    }
    pub async fn stop(&mut self) -> Result<()> {
        self.streams.cancel();
        let mut errors = Vec::new();
        // Restore system proxy before closing listeners.
        if let Some(service) = self.proxy_service.take()
            && let Err(e) = service.lock().await.stop().await
        {
            errors.push(e.to_string());
        }
        if let Some(mut process) = self.process.take() {
            let _ = protocol::write_frame(&mut process.input, &Request::Stop { version: VERSION })
                .await;
            match tokio::time::timeout(Duration::from_secs(25), process.child.wait()).await {
                Ok(Ok(status)) if status.success() => {}
                Ok(Ok(_)) => {
                    let message = protocol::read_frame(&mut process.output)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|s| serde_json::from_str::<Response>(&s).ok());
                    errors.push(match message {
                        Some(Response::Error { message, .. }) => message,
                        _ => "内核退出失败，请检查网络恢复状态".into(),
                    });
                }
                _ => {
                    let _ = process.child.kill().await;
                    errors.push("内核停止超时，已终止进程；下次启动会尝试恢复系统代理".into());
                }
            }
        }
        if let Some(service) = self.service.take()
            && let Err(e) = service.lock().await.stop().await
        {
            errors.push(e.to_string());
        }
        ensure!(errors.is_empty(), "{}", errors.join("；"));
        Ok(())
    }
    fn stream(&self, app: tauri::AppHandle, logs: Logs, channel: &'static str) {
        let address = self.address;
        let secret = self.secret.clone();
        let stop = self.streams.clone();
        tokio::spawn(async move {
            use tokio_tungstenite::tungstenite::client::IntoClientRequest;
            while !stop.is_cancelled() {
                let mut request = format!("ws://{address}/{channel}")
                    .into_client_request()
                    .unwrap();
                request
                    .headers_mut()
                    .insert("authorization", format!("Bearer {secret}").parse().unwrap());
                let connect = tokio::select! { _ = stop.cancelled() => break, result = tokio_tungstenite::connect_async(request) => result };
                if let Ok((mut socket, _)) = connect {
                    loop {
                        let message = tokio::select! { _ = stop.cancelled() => return, message = socket.next() => message };
                        match message {
                            Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text)
                                {
                                    if channel == "logs" {
                                        log(
                                            &app,
                                            &logs,
                                            value["type"].as_str().unwrap_or("info"),
                                            value["payload"].as_str().unwrap_or(""),
                                        );
                                    } else {
                                        let _ = app.emit("traffic", value);
                                    }
                                }
                            }
                            Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))
                            | Some(Err(_))
                            | None => break,
                            _ => {}
                        }
                    }
                }
                tokio::select! { _ = stop.cancelled() => break, _ = tokio::time::sleep(Duration::from_secs(2)) => {} }
            }
        });
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        self.streams.cancel();
    }
}
fn ready(response: Response) -> Result<std::net::SocketAddr> {
    match response {
        Response::Ready {
            version,
            controller,
        } => {
            ensure!(
                version == VERSION && controller.ip().is_loopback(),
                "无效内核握手"
            );
            Ok(controller)
        }
        Response::Error { message, .. } => anyhow::bail!("{message}"),
        _ => anyhow::bail!("内核未完成启动"),
    }
}
