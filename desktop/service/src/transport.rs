use anyhow::{Result, ensure};
use tokio::io::{AsyncRead, AsyncWrite};
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
pub type Stream = Box<dyn Duplex>;

#[cfg(unix)]
pub async fn connect() -> Result<Stream> {
    use std::os::fd::AsRawFd;
    let stream = tokio::net::UnixStream::connect(crate::SOCKET_PATH).await?;
    let mut uid = 0;
    let mut gid = 0;
    ensure!(
        unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0 && uid == 0,
        "untrusted service process"
    );
    Ok(Box::new(stream))
}
#[cfg(windows)]
pub async fn connect() -> Result<Stream> {
    use tokio::net::windows::named_pipe::ClientOptions;
    for _ in 0..20 {
        match ClientOptions::new().open(crate::PIPE_NAME) {
            Ok(pipe) => {
                use std::os::windows::io::AsRawHandle;
                verify_windows_peer(pipe.as_raw_handle(), true)?;
                return Ok(Box::new(pipe));
            }
            Err(e) if e.raw_os_error() == Some(231) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await
            }
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("辅助服务忙，请稍后重试")
}

#[cfg(unix)]
pub struct Listener(tokio::net::UnixListener);
#[cfg(unix)]
impl Listener {
    pub fn bind() -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::remove_file(crate::SOCKET_PATH) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = tokio::net::UnixListener::bind(crate::SOCKET_PATH)?;
        // Every connection is authenticated by its live process code signature before parsing commands.
        std::fs::set_permissions(crate::SOCKET_PATH, std::fs::Permissions::from_mode(0o666))?;
        Ok(Self(listener))
    }
    pub async fn accept(&self) -> Result<Stream> {
        let (stream, _) = self.0.accept().await?;
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::MetadataExt;
            let mut pid: libc::pid_t = 0;
            let mut length = std::mem::size_of_val(&pid) as libc::socklen_t;
            let mut uid = 0;
            let mut gid = 0;
            unsafe {
                ensure!(
                    libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) == 0,
                    "cannot identify peer"
                );
                ensure!(
                    libc::getsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_LOCAL,
                        libc::LOCAL_PEERPID,
                        (&mut pid as *mut libc::pid_t).cast(),
                        &mut length
                    ) == 0,
                    "cannot identify peer process"
                );
            }
            ensure!(
                uid != 0 && uid == std::fs::metadata("/dev/console")?.uid(),
                "only the active desktop user can control the service"
            );
            let status = tokio::process::Command::new(crate::sibling("clyntis-service-manager")?)
                .args(["verify-peer", &pid.to_string()])
                .status()
                .await?;
            ensure!(status.success(), "untrusted desktop client");
        }
        #[cfg(not(target_os = "macos"))]
        anyhow::bail!("unsupported service platform");
        Ok(Box::new(stream))
    }
}

#[cfg(windows)]
pub struct Listener;
#[cfg(windows)]
impl Listener {
    pub fn bind() -> Result<Self> {
        Ok(Self)
    }
    pub async fn accept(&self) -> Result<Stream> {
        use std::os::windows::io::AsRawHandle;
        use tokio::net::windows::named_pipe::ServerOptions;
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::{
                Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SECURITY_ATTRIBUTES,
            },
        };
        let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)\0"
            .encode_utf16()
            .collect();
        let mut descriptor = std::ptr::null_mut();
        let pipe = unsafe {
            ensure!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    std::ptr::null_mut()
                ) != 0,
                "invalid pipe ACL"
            );
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let result = ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    crate::PIPE_NAME,
                    (&attributes as *const SECURITY_ATTRIBUTES)
                        .cast_mut()
                        .cast(),
                );
            LocalFree(descriptor);
            result?
        };
        pipe.connect().await?;
        verify_windows_peer(pipe.as_raw_handle(), false)?;
        Ok(Box::new(pipe))
    }
}

#[cfg(windows)]
fn verify_windows_peer(handle: std::os::windows::io::RawHandle, server: bool) -> Result<()> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::{
            Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId},
            Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
            },
        },
    };
    let mut pid = 0;
    unsafe {
        ensure!(
            (if server {
                GetNamedPipeServerProcessId(handle, &mut pid)
            } else {
                GetNamedPipeClientProcessId(handle, &mut pid)
            }) != 0,
            "cannot identify IPC peer"
        );
        if server {
            // An ordinary desktop user may not open the SYSTEM process, even
            // with PROCESS_QUERY_LIMITED_INFORMATION. SCM is the authoritative
            // source for the registered service PID and administrator-owned path.
            return verify_registered_service(pid);
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        ensure!(
            !process.is_null(),
            "cannot open IPC client process: {}",
            std::io::Error::last_os_error()
        );
        let mut path = vec![0u16; 32768];
        let mut length = path.len() as u32;
        let result = QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut length);
        CloseHandle(process);
        ensure!(result != 0, "cannot identify client executable");
        let actual = std::path::PathBuf::from(String::from_utf16(&path[..length as usize])?)
            .canonicalize()?;
        ensure!(
            actual == crate::sibling("clyntis-desktop")?.canonicalize()?,
            "untrusted IPC peer path"
        );
    }
    Ok(())
}

#[cfg(windows)]
fn verify_registered_service(pid: u32) -> Result<()> {
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        crate::SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
    )?;
    let status = service.query_status()?;
    ensure!(
        status.current_state == ServiceState::Running,
        "registered network service is not running"
    );
    verify_registered_pid(pid, status.process_id)?;
    let configured = service.query_config()?.executable_path;
    verify_registered_path(&configured, &crate::sibling("clyntis-service")?)
}

#[cfg(windows)]
fn verify_registered_pid(pipe_pid: u32, service_pid: Option<u32>) -> Result<()> {
    ensure!(
        pipe_pid != 0 && service_pid == Some(pipe_pid),
        "named pipe server does not match the registered service PID"
    );
    Ok(())
}

#[cfg(windows)]
fn verify_registered_path(configured: &std::path::Path, expected: &std::path::Path) -> Result<()> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    // QueryServiceConfig returns a command line, including quotes for spaces.
    // Clyntis registers no launch arguments; any extra arguments fail this check.
    let command: Vec<u16> = configured.as_os_str().encode_wide().collect();
    let command =
        if command.len() >= 2 && command.first() == Some(&34) && command.last() == Some(&34) {
            &command[1..command.len() - 1]
        } else {
            &command[..]
        };
    let actual = std::path::PathBuf::from(std::ffi::OsString::from_wide(command));
    ensure!(
        actual.canonicalize()? == expected.canonicalize()?,
        "registered service belongs to a different installation directory"
    );
    Ok(())
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn a_pipe_from_another_or_exited_process_is_rejected() {
        verify_registered_pid(123, Some(123)).unwrap();
        assert!(verify_registered_pid(123, Some(124)).is_err());
        assert!(verify_registered_pid(123, None).is_err());
        assert!(verify_registered_pid(0, Some(0)).is_err());
    }

    #[test]
    fn registered_service_path_accepts_quotes_and_rejects_other_files_or_arguments() {
        let directory = tempfile::tempdir().unwrap();
        let expected = directory.path().join("服务 with spaces.exe");
        std::fs::write(&expected, b"test fixture").unwrap();
        verify_registered_path(&expected, &expected).unwrap();
        verify_registered_path(
            std::path::Path::new(&format!("\"{}\"", expected.display())),
            &expected,
        )
        .unwrap();
        let other = directory.path().join("other.exe");
        std::fs::write(&other, b"test fixture").unwrap();
        assert!(verify_registered_path(&other, &expected).is_err());
        assert!(
            verify_registered_path(
                std::path::Path::new(&format!("\"{}\" --extra", expected.display())),
                &expected
            )
            .is_err()
        );
    }
}
