#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod engine;
mod platform;
#[cfg(target_os = "macos")]
mod tray;
#[cfg(windows)]
mod windows_diagnostics;

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
    #[cfg(windows)]
    if let Some(code) = windows_diagnostics::run_if_requested() {
        std::process::exit(code);
    }
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
            app::check_yaml,
            app::select_profile,
            app::delete_profile,
            app::update_subscription,
            app::apply_pending,
            app::rollback_profile,
            app::save_settings,
            app::custom_rules,
            app::save_custom_rules,
            app::test_route,
            app::dns_leak_audit,
            app::dns_leak_test,
            app::proxies,
            app::adblock_status,
            app::network_status,
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
                    if tray_click_shows_window(&event) {
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

#[cfg(windows)]
fn tray_click_shows_window(event: &TrayIconEvent) -> bool {
    matches!(
        event,
        TrayIconEvent::Click {
            button: tauri::tray::MouseButton::Left,
            button_state: tauri::tray::MouseButtonState::Up,
            ..
        }
    )
}

#[cfg(not(windows))]
fn tray_click_shows_window(event: &TrayIconEvent) -> bool {
    matches!(event, TrayIconEvent::Click { .. })
}

fn show(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(all(test, windows))]
mod windows_tray_tests {
    use super::*;
    use tauri::tray::{MouseButton, MouseButtonState};

    fn click(button: MouseButton, button_state: MouseButtonState) -> TrayIconEvent {
        TrayIconEvent::Click {
            id: "test-tray".into(),
            position: tauri::PhysicalPosition::new(0.0, 0.0),
            rect: tauri::Rect {
                position: tauri::PhysicalPosition::new(0, 0).into(),
                size: tauri::PhysicalSize::new(16, 16).into(),
            },
            button,
            button_state,
        }
    }

    #[test]
    fn right_click_never_focuses_window_or_dismisses_native_menu() {
        for state in [MouseButtonState::Down, MouseButtonState::Up] {
            assert!(!tray_click_shows_window(&click(MouseButton::Right, state)));
        }
        assert!(!tray_click_shows_window(&click(
            MouseButton::Left,
            MouseButtonState::Down
        )));
        assert!(tray_click_shows_window(&click(
            MouseButton::Left,
            MouseButtonState::Up
        )));
    }
}
