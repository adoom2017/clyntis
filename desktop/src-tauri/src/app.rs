use crate::{
    engine::{self, Engine, Logs},
    platform,
};
use anyhow::{Context, Result, ensure};
use clyntis_desktop_model::{
    profiles::{self, Profile, ProfileSummary, PublishTarget, Store},
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
    update_cleanup_failed: AtomicBool,
    #[cfg(windows)]
    autostart_error: Mutex<Option<String>>,
    subscription_lock: tokio::sync::Mutex<()>,
}
impl Desktop {
    /// The saved interface language: `zh`, `en` or `system`.
    pub fn language(&self) -> String {
        self.store
            .settings()
            .map(|settings| settings.language)
            .unwrap_or_default()
    }
    #[cfg(windows)]
    pub fn reconcile_autostart(&self) -> Result<()> {
        let result = crate::windows_autostart::reconcile(self.store.settings()?.launch_at_login);
        if let Err(failure) = &result {
            *self.autostart_error.lock().unwrap() =
                Some(clyntis_desktop_model::redact(&format!("{failure:#}")));
        }
        result
    }
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
            update_cleanup_failed: AtomicBool::new(false),
            #[cfg(windows)]
            autostart_error: Mutex::new(None),
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
            &tr!(
                "正在安装或更新网络辅助服务。系统可能请求管理员或后台运行授权，用于配置 TUN、路由、DNS 和系统代理，并在停止时恢复网络设置。",
                "Installing or updating the network helper service. The system may ask for administrator or background permission; the service configures TUN, routes, DNS and the system proxy, and restores network settings when stopped."
            ),
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
        ensure!(
            !self.exiting.load(Ordering::SeqCst),
            "Application is exiting"
        );
        profiles::runtime_yaml(
            &profile,
            &settings,
            &"x".repeat(64),
            &self.store.custom_rules()?,
        )?;
        // Fetch before stopping the current engine: the network still works
        // normally, and the TUN session can then start from local files.
        if settings.capture == Capture::Tun {
            self.status("starting", None);
            if let Err(error) = engine::prefetch(&self.store, &profile, &settings).await {
                engine::log(
                    &self.app,
                    &self.logs,
                    "warning",
                    &clyntis_desktop_model::redact(&tr!(
                        "路由资源预下载失败，将由内核重试：{error:#}",
                        "Prefetching routing resources failed; the core will retry: {error:#}"
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
                                Some(tr!("新配置启动失败，已恢复旧配置：{error}", "The new profile failed to start; restored the previous one: {error}")),
                            );
                        }
                        Err(recovery) => {
                            self.status(
                                "failed",
                                Some(tr!(
                                    "启动失败：{error}；恢复失败：{recovery}",
                                    "Start failed: {error}; recovery failed: {recovery}"
                                )),
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
        ensure!(
            op.engine.is_none(),
            "{}",
            tr!("内核已经运行", "The core is already running")
        );
        let id = self
            .store
            .selected()?
            .with_context(|| tr!("请先导入并选择配置", "Import and select a profile first"))?;
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
        ensure!(
            ["rule", "global", "direct"].contains(&mode),
            "{}",
            tr!("无效代理模式", "Invalid proxy mode")
        );
        let mut op = self.operation.lock().await;
        let id = self
            .store
            .selected()?
            .with_context(|| tr!("请先选择配置", "Select a profile first"))?;
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
    async fn settings(&self, mut settings: Settings) -> Result<()> {
        settings.validate()?;
        // The CA lives in its own files.
        if let Some(mitm) = settings.overrides.mitm.as_mut() {
            mitm.ca_cert.clear();
            mitm.ca_key.clear();
        }
        let mut op = self.operation.lock().await;
        let previous = self.store.settings()?;
        // An allowlist edit applies to the running core; everything else in
        // the overrides needs a new runtime configuration.
        let without_allow = |s: &Settings| {
            let mut overrides = s.overrides.clone();
            if let Some(adblock) = overrides.adblock.as_mut() {
                adblock.allow.clear();
            }
            // Decryption settings apply to the running core too.
            overrides.mitm = None;
            overrides
        };
        let mitm_changed = settings.overrides.mitm != previous.overrides.mitm;
        let allow = |s: &Settings| s.overrides.adblock.as_ref().map(|a| a.allow.clone());
        let allow_changed = allow(&settings) != allow(&previous);
        let runtime_changed = settings.capture != previous.capture
            || settings.mixed_port != previous.mixed_port
            || settings.allow_lan != previous.allow_lan
            || settings.auto_dns != previous.auto_dns
            || settings.tun_interface != previous.tun_interface
            || without_allow(&settings) != without_allow(&previous);
        // Saving an already-enabled setting must also repair a missing Windows entry.
        if cfg!(windows) || settings.launch_at_login != previous.launch_at_login {
            platform::autostart(&self.app, settings.launch_at_login)?;
        }
        let result = async {
            self.store.save_settings(&settings)?;
            if runtime_changed && let Some((profile, _)) = op.active.clone() {
                self.replace(&mut op, profile, settings.clone()).await?;
            } else if let Some(engine) = op.engine.as_ref() {
                if allow_changed {
                    let allow = allow(&settings).unwrap_or_default();
                    engine
                        .request(
                            reqwest::Method::PATCH,
                            &["configs"],
                            Some(serde_json::json!({ "adblock-allow": allow })),
                        )
                        .await?;
                }
                if mitm_changed {
                    engine
                        .request(
                            reqwest::Method::PATCH,
                            &["configs"],
                            Some(self.mitm_patch(&settings)?),
                        )
                        .await?;
                }
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if result.is_err() {
            self.store.save_settings(&previous)?;
            let _ = platform::autostart(&self.app, previous.launch_at_login);
        }
        #[cfg(windows)]
        if result.is_ok()
            && let Some(failure) = self.autostart_error.lock().unwrap().take()
        {
            let mut view = self.view.lock().unwrap();
            if view.error.as_ref() == Some(&failure) {
                view.error = None;
            }
        }
        self.notify();
        result
    }
    /// The running core's decryption settings, with the CA.
    fn mitm_patch(&self, settings: &Settings) -> Result<Value> {
        let settings = self.store.with_mitm_authority(settings.clone())?;
        let mitm = settings.overrides.mitm.unwrap_or_default().to_config();
        Ok(json!({"mitm": {
            "enable": mitm.enable,
            "hostname": mitm.hostname,
            "ca-cert": mitm.ca_cert,
            "ca-key": mitm.ca_key,
        }}))
    }
    /// Makes a new CA; a running core decrypting with the old one switches.
    async fn generate_mitm_ca(&self) -> Result<()> {
        let (cert, key) = clyntis_core::generate_authority()?;
        let op = self.operation.lock().await;
        self.store.save_mitm_authority(&cert, &key)?;
        let settings = self.store.settings()?;
        if settings.overrides.mitm.is_some()
            && let Some(engine) = op.engine.as_ref()
        {
            engine
                .request(
                    reqwest::Method::PATCH,
                    &["configs"],
                    Some(self.mitm_patch(&settings)?),
                )
                .await?;
        }
        Ok(())
    }
    /// Saved rules plus, for the selected profile, its targets and the rules
    /// it cannot use.
    fn custom_rules_view(&self) -> Result<CustomRules> {
        let rules = self.store.custom_rules()?;
        let profile = match self.store.selected()? {
            Some(id) => Some(self.store.get(id)?),
            None => None,
        };
        let (targets, skipped) = match &profile {
            Some(profile) => (
                clyntis_config::custom::targets(&profile.yaml)?,
                clyntis_config::custom::apply(&profile.yaml, &rules)?.skipped,
            ),
            None => (vec!["DIRECT".into(), "REJECT".into()], vec![]),
        };
        Ok(CustomRules {
            rules,
            targets,
            skipped,
            profile: profile.map(|p| p.name),
        })
    }
    /// Saves the rules and restarts a running engine so they apply at once. A
    /// start failure restores the previous rules and engine.
    async fn save_custom_rules(&self, rules: Vec<String>) -> Result<CustomRules> {
        let mut op = self.operation.lock().await;
        let previous = self.store.custom_rules()?;
        self.store.save_custom_rules(&rules)?;
        if let Some((profile, settings)) = op.active.clone()
            && let Err(error) = self
                .replace(&mut op, profile.clone(), settings.clone())
                .await
        {
            self.store.save_custom_rules(&previous)?;
            if op.engine.is_none() {
                let _ = self.replace(&mut op, profile, settings).await;
            }
            self.notify();
            return Err(error.context(tr!(
                "新规则无法启动，已恢复原来的规则",
                "The new rules failed to start; restored the previous rules"
            )));
        }
        drop(op);
        self.notify();
        self.custom_rules_view()
    }
    async fn update(&self, id: Uuid) -> Result<()> {
        let _guard = self.subscription_lock.lock().await;
        let profile = self.store.get(id)?;
        let url = profile
            .url
            .as_deref()
            .with_context(|| tr!("该配置不是订阅", "This profile is not a subscription"))?;
        let before = (profile.yaml.clone(), profile.pending.clone());
        let downloaded = profiles::download(url, profile.password.as_deref()).await;
        // Re-read under the operation lock, so a concurrent edit/delete is never overwritten.
        let _op = self.operation.lock().await;
        let mut profile = self.store.get(id)?;
        ensure!(
            (profile.yaml.clone(), profile.pending.clone()) == before,
            "{}",
            tr!(
                "下载期间配置已被编辑，未覆盖本地修改，请重新检查更新",
                "The profile was edited during the download; kept your changes. Check for updates again"
            )
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
            profile
                .previous
                .clone()
                .with_context(|| tr!("没有可回滚版本", "No earlier version to roll back to"))?
        } else {
            profile
                .pending
                .clone()
                .with_context(|| tr!("没有待应用更新", "No pending update"))?
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

    pub fn auto_check_updates(&self) -> bool {
        self.store.settings().is_ok_and(|s| s.auto_check_updates)
    }

    pub async fn install_update(
        &self,
        update: tauri_plugin_updater::Update,
        bytes: Vec<u8>,
    ) -> Result<()> {
        // Keep starts, profile switches and shutdown serialized until replacement finishes.
        let mut op = self.operation.lock().await;
        ensure!(
            !self.exiting.load(Ordering::SeqCst),
            "Application is exiting"
        );
        ensure!(
            !self.update_cleanup_failed.load(Ordering::SeqCst),
            "Restart Clyntis and check network recovery before retrying the update"
        );
        if let Err(error) = self.stop_locked(&mut op).await {
            self.update_cleanup_failed.store(true, Ordering::SeqCst);
            return Err(error.context("Update cancelled: could not restore network settings; restart Clyntis before retrying"));
        }
        self.exiting.store(true, Ordering::SeqCst);
        let result = tokio::task::spawn_blocking(move || update.install(bytes)).await;
        match result {
            Ok(Ok(())) => self.app.restart(),
            result => {
                self.exiting.store(false, Ordering::SeqCst);
                match result {
                    Ok(Err(error)) => Err(error.into()),
                    Err(error) => Err(error.into()),
                    Ok(Ok(())) => unreachable!(),
                }
            }
        }
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
#[derive(Serialize)]
pub struct CustomRules {
    rules: Vec<String>,
    targets: Vec<String>,
    skipped: Vec<clyntis_config::custom::Skipped>,
    profile: Option<String>,
}
/// The first YAML syntax error, for marking it while the profile is edited.
#[tauri::command]
pub fn check_yaml(yaml: String) -> Option<clyntis_config::syntax::SyntaxError> {
    clyntis_config::syntax::check(&yaml)
}
#[tauri::command]
pub fn custom_rules(state: State<'_, Desktop>) -> Reply<CustomRules> {
    state.custom_rules_view().map_err(error)
}
#[tauri::command]
pub async fn save_custom_rules(
    state: State<'_, Desktop>,
    rules: Vec<String>,
) -> Reply<CustomRules> {
    state.save_custom_rules(rules).await.map_err(error)
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
        .with_context(|| tr!("无法写入导出文件", "Cannot write the export file"))
        .map_err(error)
}
/// The saved COS SecretId, or None without saved keys. The SecretKey never
/// leaves the keychain.
#[tauri::command]
pub async fn cos_credentials() -> Reply<Option<String>> {
    tokio::task::spawn_blocking(crate::keychain::load)
        .await
        .map_err(|e| error(e.into()))?
        .map(|keys| keys.map(|keys| keys.secret_id))
        .map_err(error)
}
/// Saves COS keys; an empty `secret_key` keeps the saved one.
#[tauri::command]
pub async fn save_cos_credentials(secret_id: String, secret_key: String) -> Reply<()> {
    tokio::task::spawn_blocking(move || {
        let secret_id = secret_id.trim().to_owned();
        ensure!(
            !secret_id.is_empty(),
            "{}",
            tr!("SecretId 不能为空", "SecretId cannot be empty")
        );
        let secret_key = match secret_key.trim() {
            "" => {
                crate::keychain::load()?
                    .with_context(|| tr!("请填写 SecretKey", "Enter the SecretKey"))?
                    .secret_key
            }
            key => key.to_owned(),
        };
        crate::keychain::store(&clyntis_core::cos::CosCredentials {
            secret_id,
            secret_key,
        })
    })
    .await
    .map_err(|e| error(e.into()))?
    .map_err(error)
}
#[tauri::command]
pub async fn delete_cos_credentials() -> Reply<()> {
    tokio::task::spawn_blocking(crate::keychain::delete)
        .await
        .map_err(|e| error(e.into()))?
        .map_err(error)
}
/// Where to publish `id`: where it was published last, else its subscription
/// URL when that is a COS object (publishing then replaces the subscription).
#[tauri::command]
pub fn publish_target(state: State<'_, Desktop>, id: Uuid) -> Reply<Option<PublishTarget>> {
    let profile = state.store.get(id).map_err(error)?;
    Ok(profile.publish.or_else(|| {
        let target = clyntis_core::cos::CosTarget::from_url(profile.url.as_deref()?)?;
        Some(PublishTarget {
            bucket: target.bucket,
            region: target.region,
            key: target.key,
        })
    }))
}
/// Encrypts `id` like `export_encrypted` and uploads it to Tencent COS;
/// returns the object's URL and remembers the target for the profile.
#[tauri::command]
pub async fn publish_encrypted(
    state: State<'_, Desktop>,
    id: Uuid,
    password: String,
    target: PublishTarget,
) -> Reply<String> {
    let cos = clyntis_core::cos::CosTarget {
        bucket: target.bucket.trim().to_owned(),
        region: target.region.trim().to_owned(),
        key: target.key.trim().trim_start_matches('/').to_owned(),
    };
    cos.validate().map_err(error)?;
    let profile = state.store.get(id).map_err(error)?;
    let encrypted = profiles::encrypt_yaml(&profile.yaml, &password).map_err(error)?;
    let credentials = tokio::task::spawn_blocking(crate::keychain::load)
        .await
        .map_err(|e| error(e.into()))?
        .map_err(error)?
        .ok_or_else(|| {
            tr!("请先在「设置 → 远程发布」中填写腾讯云 COS 的 SecretId 和 SecretKey", "Enter the Tencent Cloud COS SecretId and SecretKey in Settings → Remote publishing first")
        })?;
    clyntis_core::cos::put_object(
        &cos,
        &credentials,
        encrypted.into_bytes(),
        "text/plain; charset=utf-8",
    )
    .await
    .map_err(error)?;
    {
        let _guard = state.operation.lock().await;
        let mut profile = state.store.get(id).map_err(error)?;
        profile.publish = Some(PublishTarget {
            bucket: cos.bucket.clone(),
            region: cos.region.clone(),
            key: cos.key.clone(),
        });
        state.store.save(&profile).map_err(error)?;
    }
    Ok(cos.url())
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
        return Err(tr!(
            "请先停止内核或切换配置",
            "Stop the core or switch profiles first"
        ));
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
        .with_context(|| tr!("内核未运行", "The core is not running"))
        .map_err(error)
}
#[tauri::command]
pub async fn adblock_status(state: State<'_, Desktop>) -> Reply<Value> {
    controller(&state)
        .await?
        .request(reqwest::Method::GET, &["adblock"], None)
        .await
        .map_err(error)
}
#[tauri::command]
pub async fn rewrite_status(state: State<'_, Desktop>) -> Reply<Value> {
    controller(&state)
        .await?
        .request(reqwest::Method::GET, &["rewrite"], None)
        .await
        .map_err(error)
}
#[tauri::command]
pub async fn network_status(state: State<'_, Desktop>) -> Reply<Value> {
    controller(&state)
        .await?
        .request(reqwest::Method::GET, &["network"], None)
        .await
        .map_err(error)
}
#[tauri::command]
pub async fn test_route(
    state: State<'_, Desktop>,
    target: String,
    network: String,
) -> Reply<Value> {
    controller(&state)
        .await?
        .request(
            reqwest::Method::POST,
            &["rules", "test"],
            Some(json!({"target":target,"network":network})),
        )
        .await
        .map_err(error)
}
#[tauri::command]
pub async fn dns_leak_audit(state: State<'_, Desktop>) -> Reply<Value> {
    controller(&state)
        .await?
        .request(reqwest::Method::GET, &["dns", "leak"], None)
        .await
        .map_err(error)
}
#[tauri::command]
pub async fn dns_leak_test(state: State<'_, Desktop>) -> Reply<Value> {
    controller(&state)
        .await?
        .request(reqwest::Method::POST, &["dns", "leak", "test"], None)
        .await
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
        .with_context(|| tr!("内核未运行", "The core is not running"))
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
        .with_context(|| tr!("内核未运行", "The core is not running"))
        .map_err(error)?
        .request(reqwest::Method::DELETE, &path, None)
        .await
        .map_err(error)?;
    Ok(())
}
/// Recorded requests newer than `after` (see the core's `/requests`).
#[tauri::command]
pub async fn requests(state: State<'_, Desktop>, after: u64) -> Reply<Value> {
    controller(&state)
        .await?
        .request_query(
            reqwest::Method::GET,
            &["requests"],
            &[("after", after.to_string())],
            None,
        )
        .await
        .map_err(error)
}
#[tauri::command]
pub async fn request_detail(state: State<'_, Desktop>, id: u64) -> Reply<Value> {
    controller(&state)
        .await?
        .request(reqwest::Method::GET, &["requests", &id.to_string()], None)
        .await
        .map_err(error)
}
/// Saves the request log to `path`: CSV (every entry) for a `.csv` path,
/// HAR (HTTP requests with headers and bodies) otherwise.
#[tauri::command]
pub async fn export_requests(state: State<'_, Desktop>, path: String) -> Reply<()> {
    let csv = std::path::Path::new(&path)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("csv"));
    let format = if csv { "csv" } else { "har" };
    let bytes = controller(&state)
        .await?
        .download(&["requests", "export"], &[("format", format.into())])
        .await
        .map_err(error)?;
    std::fs::write(&path, bytes).map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn clear_requests(state: State<'_, Desktop>) -> Reply<()> {
    controller(&state)
        .await?
        .request(reqwest::Method::DELETE, &["requests"], None)
        .await
        .map_err(error)?;
    Ok(())
}
/// The CA (name, fingerprints), whether the system trusts it, and the
/// running core's decryption status.
#[tauri::command]
pub async fn mitm_info(state: State<'_, Desktop>) -> Reply<Value> {
    let ca = state
        .store
        .mitm_authority()
        .map_err(error)?
        .and_then(|(cert, _)| clyntis_core::describe_authority(&cert));
    let trusted = match &ca {
        Some(ca) => {
            platform::ca_trusted(
                &state.store.root.join("mitm-ca.pem"),
                ca["thumbprint"].as_str().unwrap_or_default(),
            )
            .await
        }
        None => false,
    };
    let core = match controller(&state).await {
        Ok(controller) => controller
            .request(reqwest::Method::GET, &["mitm"], None)
            .await
            .ok(),
        Err(_) => None,
    };
    Ok(json!({"ca": ca, "trusted": trusted, "core": core}))
}
#[tauri::command]
pub async fn generate_mitm_ca(state: State<'_, Desktop>) -> Reply<()> {
    state.generate_mitm_ca().await.map_err(error)
}
#[tauri::command]
pub async fn trust_mitm_ca(state: State<'_, Desktop>) -> Reply<()> {
    let path = state.store.root.join("mitm-ca.pem");
    if !path.exists() {
        return Err(tr!("请先生成证书", "Create the certificate first"));
    }
    platform::trust_ca(&path).await.map_err(error)
}
/// Saves the CA certificate (not its key), for other devices or browsers.
#[tauri::command]
pub fn export_mitm_ca(state: State<'_, Desktop>, path: String) -> Reply<()> {
    let (cert, _) = state
        .store
        .mitm_authority()
        .map_err(error)?
        .ok_or_else(|| tr!("请先生成证书", "Create the certificate first"))?;
    std::fs::write(path, cert).map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn clear_mitm_bypass(state: State<'_, Desktop>) -> Reply<()> {
    controller(&state)
        .await?
        .request(reqwest::Method::DELETE, &["mitm", "bypass"], None)
        .await
        .map_err(error)?;
    Ok(())
}
/// The core's own log (every rotated `clyntis-runner` file of each profile
/// run by this app, oldest first) followed by the app's recent log lines,
/// which hold only the last 2000 and are lost on exit. A core run by the
/// network service (TUN) logs in the service's directory instead.
#[tauri::command]
pub fn export_logs(state: State<'_, Desktop>, path: String) -> Reply<()> {
    use clyntis_desktop_service::diagnostics::log_files;
    let mut output = Vec::new();
    let mut directories = vec![state.store.root.clone()];
    if let Ok(profiles) = state.store.list() {
        directories.extend(profiles.iter().map(|p| state.store.runtime_dir(p.id)));
    }
    for directory in directories {
        for file in log_files(&directory) {
            if let Ok(bytes) = std::fs::read(&file) {
                output.extend_from_slice(format!("==> {} <==\n", file.display()).as_bytes());
                output.extend_from_slice(&bytes);
                if !bytes.ends_with(b"\n") {
                    output.push(b'\n');
                }
            }
        }
    }
    let lines: Vec<_> = state
        .logs
        .lock()
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();
    if !output.is_empty() {
        output.extend_from_slice(b"==> app <==\n");
    }
    output.extend_from_slice(lines.join("\n").as_bytes());
    clyntis_desktop_model::atomic_write(std::path::Path::new(&path), &output).map_err(error)
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
                Err(cleanup) => anyhow::anyhow!(tr!(
                    "{error:#}；停止及恢复详情：{cleanup:#}",
                    "{error:#}; stop and recovery details: {cleanup:#}"
                )),
            };
            state.status("failed", Some(error.to_string()));
            state.report(&error);
        }
    }
}
