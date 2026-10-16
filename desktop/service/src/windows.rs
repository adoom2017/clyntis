use super::*;
use std::ffi::OsString;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

const NAME: &str = clyntis_desktop_service::SERVICE_NAME;
define_windows_service!(ffi_main, service_main);

pub fn entry() {
    let result = match std::env::args().nth(1).as_deref() {
        Some("--install") => install(false),
        Some("--update") => install(true),
        Some("--uninstall") => uninstall(),
        None => service_dispatcher::start(NAME, ffi_main).map_err(Into::into),
        _ => Err(anyhow::anyhow!("invalid service command")),
    };
    if let Err(error) = result {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
fn trusted_install_path() -> Result<PathBuf> {
    let path = clyntis_desktop_service::windows_security::local_path(&std::env::current_exe()?)?;
    // Keep a DOS path in SCM. canonicalize() adds \\?\, which PowerShell 5 cannot
    // consistently handle. The policy checks junctions on the original path.
    clyntis_desktop_service::windows_security::verify_installation(&path)?;
    Ok(path)
}
pub fn protect_data(directory: &std::path::Path) -> Result<()> {
    clyntis_desktop_service::windows_security::protect_data(directory)
}
fn install(restart: bool) -> Result<()> {
    let path = trusted_install_path()?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let access = ServiceAccess::START
        | ServiceAccess::QUERY_STATUS
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "Clyntis Network Service".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let service = match manager.open_service(NAME, access) {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
            manager.create_service(&info, access)?
        }
        Err(error) => return Err(error.into()),
    };
    if restart && service.query_status()?.current_state != ServiceState::Stopped {
        if service.query_status()?.current_state != ServiceState::StopPending {
            service.stop()?;
        }
        for _ in 0..180 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        ensure!(
            service.query_status()?.current_state == ServiceState::Stopped,
            "辅助服务仍在恢复网络设置，更新已停止，请稍后重试"
        );
    }
    service.change_config(&info)?;
    if service.query_status()?.current_state != ServiceState::Running {
        service.start::<&str>(&[])?;
    }
    // SCM registration/start success is not readiness. Report immediate startup
    // failures instead of letting the desktop poll an already stopped service.
    let deadline = std::time::Instant::now() + Duration::from_secs(75);
    loop {
        let status = service.query_status()?;
        match status.current_state {
            ServiceState::Running => break,
            ServiceState::Stopped => {
                return Err(clyntis_desktop_service::windows_security::stopped_error(
                    status.exit_code,
                ));
            }
            _ => {}
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "Windows 辅助服务启动超时，请检查安装目录中的 clyntis-service.log"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = match manager.open_service(
        NAME,
        ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
    ) {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    // A failed first installation has no service to clean up, regardless of its directory.
    trusted_install_path()?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        for _ in 0..120 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        ensure!(
            service.query_status()?.current_state == ServiceState::Stopped,
            "service cleanup timed out; uninstall cancelled"
        );
    }
    let root = data_dir()?;
    if root.exists() {
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            if Uuid::parse_str(&entry.file_name().to_string_lossy()).is_ok() {
                clyntis_runtime::recover(&entry.path())?;
            }
        }
    }
    service.delete()?;
    Ok(())
}

fn service_main(_: Vec<OsString>) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let stop = CancellationToken::new();
    let control_stop = stop.clone();
    let handle = match service_control_handler::register(NAME, move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            control_stop.cancel();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) {
        Ok(handle) => handle,
        Err(_) => return,
    };
    let status = |current_state, exit_code| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted: if current_state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code,
        checkpoint: 0,
        wait_hint: if current_state == ServiceState::StartPending {
            Duration::from_secs(75)
        } else {
            Duration::default()
        },
        process_id: None,
    };
    if let Ok(path) = clyntis_desktop_service::windows_security::startup_log() {
        let _ = std::fs::remove_file(path);
    }
    let _ = handle.set_service_status(status(
        ServiceState::StartPending,
        ServiceExitCode::Win32(0),
    ));
    let result = runtime.block_on(serve(stop, || {
        handle.set_service_status(status(ServiceState::Running, ServiceExitCode::Win32(0)))?;
        Ok(())
    }));
    if let Err(error) = &result {
        let message = clyntis_desktop_model::redact(&format!("{error:#}"));
        if let Ok(path) = clyntis_desktop_service::windows_security::startup_log() {
            let _ = std::fs::write(path, message);
        }
    }
    let _ = handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceExitCode::Win32(if result.is_ok() { 0 } else { 1 }),
    ));
}
