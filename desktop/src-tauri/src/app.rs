use crate::{
    engine::{self, Engine, Logs},
    platform,
};
use anyhow::{Context, Result, ensure};
use clyntis_desktop_model::{
    profiles::{self, Profile, ProfileSummary, Store},
    settings::{Capture, Settings},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tauri::{Emitter, Manager, State};
use uuid::Uuid;

type Reply<T> = std::result::Result<T, String>;
fn error(error: anyhow::Error) -> String {
    clyntis_desktop_model::redact(&format!("{error:#}"))
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    status: String,
    error: Option<String>,
    selected: Option<Uuid>,
    mode: String,
    settings: Settings,
    profiles: Vec<ProfileSummary>,
    service_status: String,
    logs: Vec<Value>,
}
struct Operation {
    engine: Option<Engine>,
    active: Option<(Profile, Settings)>,
}
pub struct Desktop {
    app: tauri::AppHandle,
    store: Store,
    operation: tokio::sync::Mutex<Operation>,
    view: Mutex<Snapshot>,
    pub logs: Logs,
    pub exiting: AtomicBool,
    subscription_lock: tokio::sync::Mutex<()>,
}
impl Desktop {
    pub fn new(app: tauri::AppHandle, root: PathBuf) -> Result<Self> {
        let store = Store::new(root)?;
        let selected = store.selected()?;
        let settings = store.settings()?;
        let mode = selected
            .and_then(|id| store.get(id).ok())
            .map(|p| p.mode)
            .unwrap_or_else(|| "rule".into());
        let profiles = store.list()?;
        Ok(Self {
            app,
            store,
            operation: tokio::sync::Mutex::new(Operation {
                engine: None,
                active: None,
            }),
            view: Mutex::new(Snapshot {
                status: "stopped".into(),
                error: None,
                selected,
                mode,
                settings,
                profiles,
                service_status: "checking".into(),
                logs: vec![],
            }),
            logs: Arc::new(Mutex::new(VecDeque::new())),
            exiting: AtomicBool::new(false),
            subscription_lock: tokio::sync::Mutex::new(()),
        })
    }
    fn snapshot(&self) -> Result<Snapshot> {
        let mut view = self.view.lock().unwrap().clone();
        view.profiles = self.store.list()?;
        view.settings = self.store.settings()?;
        view.selected = self.store.selected()?;
        if let Some(id) = view.selected {
            view.mode = self.store.get(id)?.mode;
        }
        view.logs = self.logs.lock().unwrap().iter().cloned().collect();
        Ok(view)
    }
    fn notify(&self) {
        if let Ok(mut snapshot) = self.snapshot() {
            snapshot.logs.clear();
            let _ = self.app.emit("state", snapshot);
        }
    }
    fn status(&self, value: &str, message: Option<String>) {
        {
            let mut view = self.view.lock().unwrap();
            view.status = value.into();
            view.error = message;
        }
        self.notify();
    }
    pub fn report(&self, error: &anyhow::Error) {
        let message = clyntis_desktop_model::redact(&format!("{error:#}"));
        self.view.lock().unwrap().error = Some(message.clone());
        clyntis_desktop_service::diagnostics::Diagnostics::default()
            .record(&self.store.root, &message);
        engine::log(&self.app, &self.logs, "error", &message);
        self.notify();
    }
    // Call only while holding operation: never restart a service used by an active engine.
    async fn ensure_service(&self) -> Result<()> {
        if platform::service_is_current().await {
            self.view.lock().unwrap().service_status = "current".into();
            self.notify();
            return Ok(());
        }
        self.view.lock().unwrap().service_status = "updating".into();
        self.notify();
        engine::log(
            &self.app,
            &self.logs,
            "info",
            "正在安装或更新网络辅助服务。系统可能请求管理员或后台运行授权，用于配置 TUN、路由、DNS 和系统代理，并在停止时恢复网络设置。",
        );
        match platform::update_service().await {
            Ok(_) => {
                self.view.lock().unwrap().service_status = "current".into();
                self.notify();
                Ok(())
            }
            Err(error) => {
                self.view.lock().unwrap().service_status = "update_failed".into();
                self.notify();
                self.report(&error);
                Err(error)
            }
        }
    }
    async fn replace(
        &self,
        operation: &mut Operation,
        profile: Profile,
        settings: Settings,
    ) -> Result<()> {
        profiles::runtime_yaml(&profile, &settings, &"x".repeat(64))?;
        // Fetch before stopping the current engine: the network still works
        // normally, and the TUN session can then start from local files.
        if settings.capture == Capture::Tun {
            self.status("starting", None);
            if let Err(error) = engine::prefetch(&self.store, &profile, &settings).await {
                engine::log(
                    &self.app,
                    &self.logs,
                    "warning",
                    &clyntis_desktop_model::redact(&format!(
                        "路由资源预下载失败，将由内核重试：{error:#}"
                    )),
                );
            }
        }
        let previous = operation.active.clone();
        if let Some(mut engine) = operation.engine.take() {
            self.status("stopping", None);
            if let Err(error) = engine.stop().await {
                operation.active = None;
                self.status("failed", Some(error.to_string()));
                return Err(error);
            }
        }
        self.status("starting", None);
        if (settings.capture == Capture::Tun
            || (cfg!(target_os = "macos") && settings.capture == Capture::System))
            && let Err(error) = self.ensure_service().await
        {
            operation.active = None;
            self.status("failed", Some(format!("{error:#}")));
            return Err(error);
        }
        match Engine::launch(
            &self.app,
            self.logs.clone(),
            &self.store,
            &profile,
            &settings,
        )
        .await
        {
            Ok(engine) => {
                operation.engine = Some(engine);
                operation.active = Some((profile, settings));
                self.status("running", None);
                Ok(())
            }
            Err(error) => {
                operation.active = None;
                if let Some((old_profile, old_settings)) = previous {
                    self.status("recovering", Some(error.to_string()));
                    match Engine::launch(
                        &self.app,
                        self.logs.clone(),
                        &self.store,
                        &old_profile,
                        &old_settings,
                    )
                    .await
                    {
                        Ok(engine) => {
                            operation.engine = Some(engine);
                            operation.active = Some((old_profile, old_settings));
                            self.status(
                                "running",
                                Some(format!("新配置启动失败，已恢复旧配置：{error}")),
                            );
                        }
                        Err(recovery) => {
                            self.status(
                                "failed",
                                Some(format!("启动失败：{error}；恢复失败：{recovery}")),
                            );
                        }
                    }
                } else {
                    self.status("failed", Some(error.to_string()));
                }
                Err(error)
            }
        }
    }
    async fn start(&self) -> Result<()> {
        let mut op = self.operation.lock().await;
        ensure!(op.engine.is_none(), "内核已经运行");
        let id = self.store.selected()?.context("请先导入并选择配置")?;
        self.replace(&mut op, self.store.get(id)?, self.store.settings()?)
            .await
    }
    async fn stop(&self) -> Result<()> {
        let mut op = self.operation.lock().await;
        self.stop_locked(&mut op).await
    }
    async fn stop_locked(&self, op: &mut Operation) -> Result<()> {
        if let Some(mut engine) = op.engine.take() {
            self.status("stopping", None);
            let result = engine.stop().await;
            op.active = None;
            if let Err(error) = result {
                self.status("failed", Some(error.to_string()));
                return Err(error);
            }
        }
        self.status("stopped", None);
        Ok(())
    }
    pub async fn toggle(&self) -> Result<()> {
        let running = self.operation.lock().await.engine.is_some();
        if running {
            self.stop().await
        } else {
            self.start().await
        }
    }
    pub async fn mode(&self, mode: &str) -> Result<()> {
        ensure!(["rule", "global", "direct"].contains(&mode), "无效代理模式");
        let mut op = self.operation.lock().await;
        let id = self.store.selected()?.context("请先选择配置")?;
        let mut profile = self.store.get(id)?;
        let previous = profile.mode.clone();
        if let Some(engine) = &op.engine {
            engine
                .request(
                    reqwest::Method::PATCH,
                    &["configs"],
                    Some(json!({"mode":mode})),
                )
                .await?;
        }
        profile.mode = mode.into();
        if let Err(error) = self.store.save(&profile) {
            if let Some(engine) = &op.engine {
                let _ = engine
                    .request(
                        reqwest::Method::PATCH,
                        &["configs"],
                        Some(json!({"mode":previous})),
                    )
                    .await;
            }
            return Err(error);
        }
        if let Some((active, _)) = &mut op.active {
            active.mode = mode.into();
        }
        self.notify();
        Ok(())
    }
    async fn settings(&self, settings: Settings) -> Result<()> {
        settings.validate()?;
        let mut op = self.operation.lock().await;
        let previous = self.store.settings()?;
        let runtime_changed = settings.capture != previous.capture
            || settings.mixed_port != previous.mixed_port
            || settings.allow_lan != previous.allow_lan
            || settings.auto_dns != previous.auto_dns
            || settings.tun_interface != previous.tun_interface;
        if settings.launch_at_login != previous.launch_at_login {
            platform::autostart(&self.app, settings.launch_at_login)?;
        }
        let result = async {
            self.store.save_settings(&settings)?;
            if runtime_changed && let Some((profile, _)) = op.active.clone() {
                self.replace(&mut op, profile, settings.clone()).await?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if result.is_err() {
            self.store.save_settings(&previous)?;
            let _ = platform::autostart(&self.app, previous.launch_at_login);
        }
        self.notify();
        result
    }
    async fn update(&self, id: Uuid) -> Result<()> {
        let _guard = self.subscription_lock.lock().await;
        let profile = self.store.get(id)?;
        let url = profile.url.as_deref().context("该配置不是订阅")?;
        let before = (profile.yaml.clone(), profile.pending.clone());
        let downloaded = profiles::download(url, profile.password.as_deref()).await;
        // Re-read under the operation lock, so a concurrent edit/delete is never overwritten.
        let _op = self.operation.lock().await;
        let mut profile = self.store.get(id)?;
        ensure!(
            (profile.yaml.clone(), profile.pending.clone()) == before,
            "下载期间配置已被编辑，未覆盖本地修改，请重新检查更新"
        );
        profile.last_checked = clyntis_desktop_model::now();
        match downloaded {
            Ok(yaml) => {
                profile.pending = (yaml != profile.yaml).then_some(yaml);
                profile.last_error = None;
                self.store.save(&profile)?;
                self.notify();
                Ok(())
            }
            Err(error) => {
                profile.last_error = Some(clyntis_desktop_model::redact(&format!("{error:#}")));
                self.store.save(&profile)?;
                self.notify();
                Err(error)
            }
        }
    }
    async fn apply(&self, id: Uuid, rollback: bool) -> Result<()> {
        let mut op = self.operation.lock().await;
        let mut profile = self.store.get(id)?;
        let original = profile.clone();
        let yaml = if rollback {
            profile.previous.clone().context("没有可回滚版本")?
        } else {
            profile.pending.clone().context("没有待应用更新")?
        };
        profiles::validate(&yaml)?;
        let old = profile.yaml.clone();
        profile.yaml = yaml;
        profile.previous = Some(old);
        profile.pending = None;
        self.store.save(&profile)?;
        if op
            .active
            .as_ref()
            .is_some_and(|(active, _)| active.id == id)
            && let Err(error) = self
                .replace(&mut op, profile.clone(), self.store.settings()?)
                .await
        {
            self.store.save(&original)?;
            self.notify();
            return Err(error);
        }
        self.notify();
        Ok(())
    }
    pub async fn exit(&self) {
        if let Err(error) = self.stop().await {
            self.report(&error);
        }
        self.exiting.store(true, Ordering::SeqCst);
        self.app.exit(0);
    }
}

#[tauri::command]
pub fn snapshot(state: State<'_, Desktop>) -> Reply<Snapshot> {
    state.snapshot().map_err(error)
}
#[tauri::command]
pub async fn start(state: State<'_, Desktop>) -> Reply<()> {
    state.start().await.map_err(error)
}
#[tauri::command]
pub async fn stop(state: State<'_, Desktop>) -> Reply<()> {
    state.stop().await.map_err(error)
}
#[tauri::command]
pub async fn set_capture(state: State<'_, Desktop>, capture: Capture) -> Reply<()> {
    let mut settings = state.store.settings().map_err(error)?;
    settings.capture = capture;
    state.settings(settings).await.map_err(error)
}
#[tauri::command]
pub async fn set_mode(state: State<'_, Desktop>, mode: String) -> Reply<()> {
    state.mode(&mode).await.map_err(error)
}
#[tauri::command]
pub async fn save_settings(state: State<'_, Desktop>, settings: Settings) -> Reply<()> {
    state.settings(settings).await.map_err(error)
}
#[tauri::command]
pub fn inspect_profile_file(path: String) -> Reply<Value> {
    let source = clyntis_desktop_model::read_limited(
        std::path::Path::new(&path),
        clyntis_desktop_model::CONFIG_LIMIT,
    )
    .map_err(error)?;
    let encrypted = std::str::from_utf8(&source).is_ok_and(profiles::looks_encrypted);
    Ok(json!({ "encrypted": encrypted }))
}
#[tauri::command]
pub async fn import_profile(
    state: State<'_, Desktop>,
    path: String,
    password: Option<String>,
) -> Reply<profiles::ImportResult> {
    let _guard = state.operation.lock().await;
    let result = state
        .store
        .import_file(std::path::Path::new(&path), password.as_deref())
        .map_err(error)?;
    if state.store.selected().map_err(error)?.is_none() {
        state.store.select(Some(result.profile.id)).map_err(error)?;
    }
    state.notify();
    Ok(result)
}
#[tauri::command]
pub async fn add_subscription(
    state: State<'_, Desktop>,
    name: String,
    url: String,
    password: Option<String>,
) -> Reply<profiles::ImportResult> {
    let password = password.filter(|p| !p.is_empty());
    let source = profiles::download_source(&url).await.map_err(error)?;
    let _guard = state.operation.lock().await;
    let result = state
        .store
        .import_subscription(name, &source, url, password)
        .map_err(error)?;
    if let Ok(profile) = state.store.get(result.profile.id) {
        engine::spawn_prefetch(
            state.app.clone(),
            state.logs.clone(),
            state.store.clone(),
            profile,
        );
    }
    if state.store.selected().map_err(error)?.is_none() {
        state.store.select(Some(result.profile.id)).map_err(error)?;
    }
    state.notify();
    Ok(result)
}
#[tauri::command]
pub fn read_profile(state: State<'_, Desktop>, id: Uuid) -> Reply<Profile> {
    let mut profile = state.store.get(id).map_err(error)?;
    // The stored subscription password never needs to reach the webview.
    profile.password = None;
    Ok(profile)
}
#[tauri::command]
pub fn export_encrypted(
    state: State<'_, Desktop>,
    id: Uuid,
    password: String,
    path: String,
) -> Reply<()> {
    let profile = state.store.get(id).map_err(error)?;
    let encrypted = profiles::encrypt_yaml(&profile.yaml, &password).map_err(error)?;
    std::fs::write(&path, encrypted)
        .context("无法写入导出文件")
        .map_err(error)
}
#[tauri::command]
pub async fn save_profile(state: State<'_, Desktop>, id: Uuid, yaml: String) -> Reply<()> {
    profiles::validate(&yaml).map_err(error)?;
    let _guard = state.operation.lock().await;
    let mut profile = state.store.get(id).map_err(error)?;
    profile.pending = Some(yaml);
    state.store.save(&profile).map_err(error)?;
    state.notify();
    Ok(())
}
#[tauri::command]
pub async fn select_profile(state: State<'_, Desktop>, id: Uuid) -> Reply<()> {
    let mut op = state.operation.lock().await;
    let previous = state.store.selected().map_err(error)?;
    let profile = state.store.get(id).map_err(error)?;
    state.store.select(Some(id)).map_err(error)?;
    if op.engine.is_some()
        && let Err(failure) = state
            .replace(&mut op, profile, state.store.settings().map_err(error)?)
            .await
    {
        state.store.select(previous).map_err(error)?;
        state.notify();
        return Err(error(failure));
    }
    state.notify();
    Ok(())
}
#[tauri::command]
pub async fn delete_profile(state: State<'_, Desktop>, id: Uuid) -> Reply<()> {
    let op = state.operation.lock().await;
    if op
        .active
        .as_ref()
        .is_some_and(|(profile, _)| profile.id == id)
    {
        return Err("请先停止内核或切换配置".into());
    }
    state.store.delete(id).map_err(error)?;
    if state.view.lock().unwrap().selected == Some(id)
        || state.store.selected().map_err(error)?.is_none()
    {
        state.store.select(None).map_err(error)?;
    }
    state.notify();
    Ok(())
}
#[tauri::command]
pub async fn update_subscription(state: State<'_, Desktop>, id: Uuid) -> Reply<()> {
    state.update(id).await.map_err(error)
}
#[tauri::command]
pub async fn apply_pending(state: State<'_, Desktop>, id: Uuid) -> Reply<()> {
    state.apply(id, false).await.map_err(error)
}
#[tauri::command]
pub async fn rollback_profile(state: State<'_, Desktop>, id: Uuid) -> Reply<()> {
    state.apply(id, true).await.map_err(error)
}

// Read-only queries and delay probes release the operation lock before the
// HTTP round trip, so a slow probe cannot block stop/restart or other commands.
async fn controller(state: &Desktop) -> Reply<engine::Controller> {
    let op = state.operation.lock().await;
    op.engine
        .as_ref()
        .map(Engine::controller)
        .context("内核未运行")
        .map_err(error)
}
#[tauri::command]
pub async fn proxies(state: State<'_, Desktop>) -> Reply<Value> {
    controller(&state)
        .await?
        .request(reqwest::Method::GET, &["proxies"], None)
        .await
        .map_err(error)
}
#[tauri::command]
pub async fn select_proxy(state: State<'_, Desktop>, group: String, name: String) -> Reply<()> {
    let op = state.operation.lock().await;
    op.engine
        .as_ref()
        .context("内核未运行")
        .map_err(error)?
        .request(
            reqwest::Method::PUT,
            &["proxies", &group],
            Some(json!({"name":name})),
        )
        .await
        .map_err(error)?;
    Ok(())
}
#[tauri::command]
pub async fn probe_proxy(state: State<'_, Desktop>, name: String) -> Reply<Value> {
    controller(&state)
        .await?
        .request(reqwest::Method::GET, &["proxies", &name, "delay"], None)
        .await
        .map_err(error)
}
#[tauri::command]
pub async fn connections(state: State<'_, Desktop>) -> Reply<Value> {
    controller(&state)
        .await?
        .request(reqwest::Method::GET, &["connections"], None)
        .await
        .map_err(error)
}
#[tauri::command]
pub async fn close_connection(state: State<'_, Desktop>, id: Option<String>) -> Reply<()> {
    let op = state.operation.lock().await;
    let mut path = vec!["connections"];
    if let Some(id) = &id {
        path.push(id);
    }
    op.engine
        .as_ref()
        .context("内核未运行")
        .map_err(error)?
        .request(reqwest::Method::DELETE, &path, None)
        .await
        .map_err(error)?;
    Ok(())
}
#[tauri::command]
pub fn export_logs(state: State<'_, Desktop>, path: String) -> Reply<()> {
    let lines: Vec<_> = state
        .logs
        .lock()
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();
    clyntis_desktop_model::atomic_write(std::path::Path::new(&path), lines.join("\n").as_bytes())
        .map_err(error)
}
#[tauri::command]
pub async fn install_service(state: State<'_, Desktop>) -> Reply<String> {
    let mut op = state.operation.lock().await;
    state.stop_locked(&mut op).await.map_err(error)?;
    state.ensure_service().await.map_err(error)?;
    Ok("current".into())
}
#[tauri::command]
pub async fn uninstall_service(state: State<'_, Desktop>) -> Reply<String> {
    let mut op = state.operation.lock().await;
    state.stop_locked(&mut op).await.map_err(error)?;
    let result = platform::service("uninstall").await.map_err(error)?;
    state.view.lock().unwrap().service_status = result.clone();
    state.notify();
    Ok(result)
}
#[tauri::command]
pub async fn quit(state: State<'_, Desktop>) -> Reply<()> {
    state.exit().await;
    Ok(())
}

pub async fn background(app: tauri::AppHandle) {
    let state = app.state::<Desktop>();
    let status = platform::service("status")
        .await
        .unwrap_or_else(|_| "not_installed".into());
    state.view.lock().unwrap().service_status = status.clone();
    state.notify();
    // Do not install unused privileged features merely because the app opened.
    let update_ok = if ["enabled", "installed"].contains(&status.as_str()) {
        let op = state.operation.lock().await;
        if op.engine.is_none() {
            state.ensure_service().await.is_ok()
        } else {
            true
        }
    } else {
        true
    };
    if update_ok
        && state.store.settings().is_ok_and(|s| s.auto_connect)
        && let Err(e) = state.start().await
    {
        state.report(&e);
    }
    let update_app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let state = update_app.state::<Desktop>();
            let hours = state
                .store
                .settings()
                .map(|s| s.subscription_interval_hours)
                .unwrap_or(0);
            if hours > 0
                && let Ok(profiles) = state.store.list()
            {
                for summary in profiles {
                    if summary.pending {
                        continue;
                    }
                    if let Ok(profile) = state.store.get(summary.id)
                        && profile.url.is_some()
                        && clyntis_desktop_model::now().saturating_sub(profile.last_checked)
                            >= u64::from(hours) * 3600
                        && let Err(error) = state.update(profile.id).await
                    {
                        state.report(&error);
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        if let Ok(mut op) = state.operation.try_lock()
            && let Some(engine) = &mut op.engine
            && let Err(error) = engine.health().await
        {
            let error = match state.stop_locked(&mut op).await {
                Ok(()) => error,
                Err(cleanup) => anyhow::anyhow!("{error:#}；停止及恢复详情：{cleanup:#}"),
            };
            state.status("failed", Some(error.to_string()));
            state.report(&error);
        }
    }
}
