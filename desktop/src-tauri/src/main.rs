#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod engine;
mod platform;
#[cfg(target_os = "macos")]
mod tray;

use app::Desktop;
use tauri::{
    Manager,
    menu::{Menu, MenuItem},
    tray::{TrayIconBuilder, TrayIconEvent},
};

#[cfg(target_os = "macos")]
const TRAY_ICON: &[u8] = include_bytes!("../icons/clyntis-v3/tray-template.png");
#[cfg(not(target_os = "macos"))]
const TRAY_ICON: &[u8] = include_bytes!("../icons/clyntis-v3/64x64.png");

fn main() {
    let autostart = tauri_plugin_autostart::Builder::new();
    #[cfg(target_os = "macos")]
    let autostart = autostart.macos_launcher(tauri_plugin_autostart::MacosLauncher::LaunchAgent);

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| show(app)))
        .plugin(tauri_plugin_dialog::init())
        .plugin(autostart.build())
        .invoke_handler(tauri::generate_handler![
            app::snapshot,
            app::start,
            app::stop,
            app::set_capture,
            app::set_mode,
            app::inspect_profile_file,
            app::import_profile,
            app::export_encrypted,
            app::add_subscription,
            app::read_profile,
            app::save_profile,
            app::select_profile,
            app::delete_profile,
            app::update_subscription,
            app::apply_pending,
            app::rollback_profile,
            app::save_settings,
            app::proxies,
            app::select_proxy,
            app::probe_proxy,
            app::connections,
            app::close_connection,
            app::export_logs,
            app::install_service,
            app::uninstall_service,
            app::quit
        ])
        .setup(|app| {
            let desktop = Desktop::new(app.handle().clone(), app.path().app_data_dir()?)?;
            app.manage(desktop);
            let menu = Menu::with_items(
                app,
                &[
                    &MenuItem::with_id(app, "show", "显示 Clyntis", true, None::<&str>)?,
                    &MenuItem::with_id(app, "toggle", "启动 / 停止", true, None::<&str>)?,
                    &MenuItem::with_id(app, "rule", "规则模式", true, None::<&str>)?,
                    &MenuItem::with_id(app, "global", "全局模式", true, None::<&str>)?,
                    &MenuItem::with_id(app, "direct", "直连模式", true, None::<&str>)?,
                    &MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?,
                ],
            )?;
            let tray_icon = tauri::image::Image::from_bytes(TRAY_ICON)?;
            #[allow(unused_variables)] // Only the macOS icon is animated.
            let tray = TrayIconBuilder::new()
                .icon(tray_icon.clone())
                .icon_as_template(cfg!(target_os = "macos"))
                .tooltip("Clyntis")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_tray_icon_event(|tray, event| {
                    if matches!(event, TrayIconEvent::Click { .. }) {
                        show(tray.app_handle());
                    }
                })
                .on_menu_event(|app, event| {
                    let app = app.clone();
                    let id = event.id().as_ref().to_owned();
                    if id == "show" {
                        show(&app);
                        return;
                    }
                    tauri::async_runtime::spawn(async move {
                        let state = app.state::<Desktop>();
                        let result = match id.as_str() {
                            "toggle" => state.toggle().await,
                            "rule" | "global" | "direct" => state.mode(&id).await,
                            "quit" => {
                                state.exit().await;
                                return;
                            }
                            _ => Ok(()),
                        };
                        if let Err(error) = result {
                            state.report(&error);
                        }
                    });
                })
                .build(app)?;
            #[cfg(target_os = "macos")]
            tray::animate(tray, tray_icon, app.state::<Desktop>().running());
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                app::background(handle).await;
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("cannot initialize Clyntis desktop")
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                let state = app.state::<Desktop>();
                if !state.exiting.load(std::sync::atomic::Ordering::SeqCst) {
                    api.prevent_exit();
                    let app = app.clone();
                    tauri::async_runtime::spawn(async move {
                        app.state::<Desktop>().exit().await;
                    });
                }
            }
        });
}

fn show(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}
