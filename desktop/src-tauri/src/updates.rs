use crate::app::Desktop;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
use tauri::{Emitter, Manager, State};
use tauri_plugin_updater::{Update, UpdaterExt};

const PUBLIC_KEY: &str = match option_env!("CLYNTIS_UPDATER_PUBLIC_KEY") {
    Some(key) => key,
    None => "",
};
const ENDPOINT: &str = match option_env!("CLYNTIS_UPDATER_ENDPOINT") {
    Some(url) => url,
    None => "https://github.com/adoom2017/clyntis/releases/latest/download/latest.json",
};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateState {
    phase: &'static str,
    version: Option<String>,
    notes: Option<String>,
    error: Option<String>,
    downloaded: u64,
    total: Option<u64>,
    checked_at: Option<u64>,
}
impl Default for UpdateState {
    fn default() -> Self {
        Self {
            phase: if PUBLIC_KEY.trim().is_empty() {
                "disabled"
            } else {
                "idle"
            },
            version: None,
            notes: None,
            error: None,
            downloaded: 0,
            total: None,
            checked_at: None,
        }
    }
}

#[derive(Default)]
struct Pending {
    update: Option<Update>,
    bytes: Option<Vec<u8>>,
}
#[derive(Default)]
pub struct Updates {
    view: Mutex<UpdateState>,
    operation: tokio::sync::Mutex<Pending>,
}
impl Updates {
    fn publish(&self, app: &tauri::AppHandle, edit: impl FnOnce(&mut UpdateState)) -> UpdateState {
        let mut view = self.view.lock().unwrap();
        edit(&mut view);
        let _ = app.emit("app-update", &*view);
        view.clone()
    }

    async fn check(&self, app: &tauri::AppHandle) -> Result<UpdateState> {
        let mut pending = self
            .operation
            .try_lock()
            .context("An update operation is already in progress")?;
        ensure!(
            !PUBLIC_KEY.trim().is_empty(),
            "This build has no update signing public key"
        );
        // A periodic check must not discard an already downloaded, verified package.
        if pending.bytes.is_some() {
            return Ok(self.view.lock().unwrap().clone());
        }
        self.publish(app, |s| {
            s.phase = "checking";
            s.error = None;
        });
        let result = async {
            let endpoint: reqwest::Url = ENDPOINT.parse()?;
            ensure!(
                endpoint.scheme() == "https",
                "Update endpoint must use HTTPS"
            );
            let updater = app
                .updater_builder()
                .pubkey(PUBLIC_KEY.trim())
                .endpoints(vec![endpoint])?
                .timeout(Duration::from_secs(30))
                .configure_client(|client| {
                    client
                        .https_only(true)
                        .connect_timeout(Duration::from_secs(15))
                })
                // Keep the UI usable if Windows cannot launch the installer.
                // The plugin exits the process after a successful handoff.
                .on_before_exit(|| {})
                .build()?;
            let update = updater.check().await?;
            if let Some(update) = &update {
                ensure!(
                    update.download_url.scheme() == "https",
                    "Update download must use HTTPS"
                );
            }
            Ok::<_, anyhow::Error>(update)
        }
        .await;
        match result {
            Ok(update) => {
                let view = self.publish(app, |s| {
                    s.phase = if update.is_some() {
                        "available"
                    } else {
                        "current"
                    };
                    s.version = update.as_ref().map(|u| u.version.clone());
                    s.notes = update.as_ref().and_then(|u| u.body.clone());
                    s.checked_at = Some(clyntis_desktop_model::now());
                    s.downloaded = 0;
                    s.total = None;
                });
                pending.update = update;
                Ok(view)
            }
            Err(error) => {
                // Retain a previously discovered release so an offline re-check is retryable.
                self.fail(app, &error);
                Err(error)
            }
        }
    }

    fn fail(&self, app: &tauri::AppHandle, error: &anyhow::Error) {
        self.publish(app, |s| {
            s.phase = "error";
            s.error = Some(clyntis_desktop_model::redact(&format!("{error:#}")));
        });
    }

    async fn download(&self, app: &tauri::AppHandle) -> Result<()> {
        let mut pending = self
            .operation
            .try_lock()
            .context("An update operation is already in progress")?;
        if pending.bytes.is_some() {
            return Ok(());
        }
        let mut update = pending
            .update
            .clone()
            .context("Check for an update first")?;
        update.timeout = Some(Duration::from_secs(15 * 60));
        self.publish(app, |s| {
            s.phase = "downloading";
            s.error = None;
            s.downloaded = 0;
            s.total = None;
        });
        let mut downloaded = 0u64;
        let mut last = Instant::now();
        let result = update
            .download(
                |chunk, total| {
                    downloaded = downloaded.saturating_add(chunk as u64);
                    if last.elapsed() >= Duration::from_millis(150) {
                        self.publish(app, |s| {
                            s.downloaded = downloaded;
                            s.total = total;
                        });
                        last = Instant::now();
                    }
                },
                || {},
            )
            .await;
        match result {
            Ok(bytes) => {
                // download() returns only after verifying the artifact and its signed version.
                self.publish(app, |s| {
                    s.phase = "ready";
                    s.downloaded = bytes.len() as u64;
                    s.total = Some(bytes.len() as u64);
                });
                pending.bytes = Some(bytes);
                Ok(())
            }
            Err(error) => {
                let error = error.into();
                self.fail(app, &error);
                Err(error)
            }
        }
    }

    async fn install(&self, app: &tauri::AppHandle) -> Result<()> {
        let mut pending = self
            .operation
            .try_lock()
            .context("An update operation is already in progress")?;
        let update = pending
            .update
            .clone()
            .context("Check for an update first")?;
        let bytes = pending
            .bytes
            .take()
            .context("Download and verify the update first")?;
        self.publish(app, |s| {
            s.phase = "installing";
            s.error = None;
        });
        match app.state::<Desktop>().install_update(update, bytes).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.fail(app, &error);
                Err(error)
            }
        }
    }
}

fn reply<T>(result: Result<T>) -> Result<T, String> {
    result.map_err(|e| clyntis_desktop_model::redact(&format!("{e:#}")))
}
#[tauri::command]
pub fn app_update_state(state: State<'_, Updates>) -> UpdateState {
    state.view.lock().unwrap().clone()
}
#[tauri::command]
pub async fn check_app_update(
    app: tauri::AppHandle,
    state: State<'_, Updates>,
) -> Result<UpdateState, String> {
    reply(state.check(&app).await)
}
#[tauri::command]
pub async fn download_app_update(
    app: tauri::AppHandle,
    state: State<'_, Updates>,
) -> Result<(), String> {
    reply(state.download(&app).await)
}
#[tauri::command]
pub async fn install_app_update(
    app: tauri::AppHandle,
    state: State<'_, Updates>,
) -> Result<(), String> {
    reply(state.install(&app).await)
}

pub async fn background(app: tauri::AppHandle) {
    if PUBLIC_KEY.trim().is_empty() {
        return;
    }
    tokio::time::sleep(Duration::from_secs(20)).await;
    // The next check is set forward from now: an Instant is measured from
    // boot on macOS and Windows, so subtracting hours from one shortly after
    // a login start underflowed and panicked, ending the checks.
    let mut next_check = Instant::now();
    loop {
        if app.state::<Desktop>().auto_check_updates() && Instant::now() >= next_check {
            let result = app.state::<Updates>().check(&app).await;
            // Retry offline failures after 15 minutes, rather than waiting six hours.
            next_check = Instant::now()
                + if result.is_ok() {
                    Duration::from_secs(6 * 3600)
                } else {
                    Duration::from_secs(15 * 60)
                };
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}
