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
        Some("--install") => install(),
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
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath},
    };
    let path = std::env::current_exe()?.canonicalize()?;
    // Elevated processes may inherit user-controlled environment variables.
    let mut pointer = std::ptr::null_mut();
    let program_files = unsafe {
        ensure!(
            SHGetKnownFolderPath(
                &FOLDERID_ProgramFiles,
                0,
                std::ptr::null_mut(),
                &mut pointer
            ) >= 0,
            "cannot resolve Program Files"
        );
        let mut length = 0;
        while *pointer.add(length) != 0 {
            length += 1;
        }
        let directory = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(
            pointer, length,
        )));
        CoTaskMemFree(pointer.cast());
        directory.canonicalize()?
    };
    ensure!(
        path.starts_with(program_files),
        "辅助服务必须从 Program Files 下的已安装应用注册"
    );
    Ok(path)
}
pub fn protect_data(directory: &std::path::Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    trusted_install_path()?;
    let status = std::process::Command::new("icacls.exe")
        .arg(directory)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "/T",
            "/Q",
        ])
        .creation_flags(0x08000000)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    ensure!(status.success(), "cannot protect service data directory");
    Ok(())
}
fn install() -> Result<()> {
    let path = trusted_install_path()?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let access = ServiceAccess::START | ServiceAccess::QUERY_STATUS;
    let service = match manager.open_service(NAME, access) {
        Ok(service) => service,
        Err(_) => manager.create_service(
            &ServiceInfo {
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
            },
            access,
        )?,
    };
    if service.query_status()?.current_state != ServiceState::Running {
        service.start::<&str>(&[])?;
    }
    Ok(())
}
fn uninstall() -> Result<()> {
    trusted_install_path()?;
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
                meta_runtime::recover(&entry.path())?;
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
        wait_hint: Duration::default(),
        process_id: None,
    };
    let _ = handle.set_service_status(status(ServiceState::Running, ServiceExitCode::Win32(0)));
    let result = runtime.block_on(serve(stop));
    let _ = handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceExitCode::Win32(if result.is_ok() { 0 } else { 1 }),
    ));
}
