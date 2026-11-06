//! Per-user login registration. auto-launch 0.5 writes unquoted Windows paths
//! and its presence check cannot detect a stale executable path.
use anyhow::{Context, Result, ensure};
use std::{ffi::OsString, io::ErrorKind, os::windows::ffi::OsStrExt, path::Path};
use winreg::{
    RegKey, RegValue,
    enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_BINARY},
};

const NAME: &str = "Clyntis";
const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APPROVAL: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
const ENABLED: [u8; 12] = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

pub fn set(enabled: bool) -> Result<()> {
    Registration::new()
        .set(enabled, &std::env::current_exe()?)
        .context(tr!(
            "无法保存 Windows 登录启动设置",
            "Cannot save Windows login startup settings"
        ))
}

pub fn reconcile(enabled: bool) -> Result<()> {
    Registration::new()
        .reconcile(enabled, &std::env::current_exe()?)
        .context(tr!(
            "无法同步 Windows 登录启动设置",
            "Cannot reconcile Windows login startup settings"
        ))
}

fn command(executable: &Path) -> Result<OsString> {
    let executable = clyntis_desktop_service::windows_security::local_path(executable)?;
    ensure!(
        !executable
            .as_os_str()
            .encode_wide()
            .any(|c| c == 0 || c == u16::from(b'"')),
        "Invalid startup executable path"
    );
    let mut command = OsString::from("\"");
    command.push(executable);
    command.push("\"");
    ensure!(
        command.encode_wide().count() <= 260,
        "Startup command exceeds the Windows Run key limit"
    );
    Ok(command)
}

struct Registration {
    root: RegKey,
    run: String,
    approval: String,
}
impl Registration {
    fn new() -> Self {
        Self {
            root: RegKey::predef(HKEY_CURRENT_USER),
            run: RUN.into(),
            approval: APPROVAL.into(),
        }
    }

    fn read(&self, path: &str) -> Result<Option<RegValue<'static>>> {
        match self.root.open_subkey_with_flags(path, KEY_READ) {
            Ok(key) => match key.get_raw_value(NAME) {
                Ok(value) => Ok(Some(value)),
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            },
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn restore(&self, path: &str, value: Option<&RegValue<'_>>) -> Result<()> {
        if let Some(value) = value {
            self.root
                .create_subkey(path)?
                .0
                .set_raw_value(NAME, value)?;
        } else {
            self.remove(path)?;
        }
        Ok(())
    }

    fn remove(&self, path: &str) -> Result<()> {
        match self.root.open_subkey_with_flags(path, KEY_SET_VALUE) {
            Ok(key) => match key.delete_value(NAME) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            },
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn approved(&self) -> Result<bool> {
        let Some(value) = self.read(&self.approval)? else {
            return Ok(true);
        };
        ensure!(
            value.vtype == REG_BINARY && value.bytes.len() == 12,
            "Invalid Windows startup approval record"
        );
        match value.bytes[0] {
            2 | 6 => Ok(true),
            3 | 7 => Ok(false),
            _ => anyhow::bail!("Unrecognized Windows startup approval state"),
        }
    }

    fn write_command(&self, command: &OsString) -> Result<()> {
        let (key, _) = self.root.create_subkey(&self.run)?;
        let previous: Option<OsString> = key.get_value(NAME).ok();
        if previous.as_ref() != Some(command) {
            key.set_value(NAME, command)?;
        }
        ensure!(
            key.get_value::<OsString, _>(NAME)? == *command,
            "Windows startup command verification failed"
        );
        Ok(())
    }

    fn set(&self, enabled: bool, executable: &Path) -> Result<()> {
        if !enabled {
            return self.remove(&self.run);
        }
        let command = command(executable)?;
        let previous_run = self.read(&self.run)?;
        let previous_approval = self.read(&self.approval)?;
        let result = (|| {
            self.write_command(&command)?;
            self.root.create_subkey(&self.approval)?.0.set_raw_value(
                NAME,
                &RegValue {
                    vtype: REG_BINARY,
                    bytes: ENABLED.as_slice().into(),
                },
            )?;
            ensure!(self.approved()?, "Windows login startup remains disabled");
            Ok(())
        })();
        if let Err(error) = result {
            // A partial write must not enable startup while settings still report failure.
            let restore_errors = [
                self.restore(&self.run, previous_run.as_ref()).err(),
                self.restore(&self.approval, previous_approval.as_ref())
                    .err(),
            ]
            .into_iter()
            .flatten()
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
            if !restore_errors.is_empty() {
                return Err(error.context(format!(
                    "Startup registration rollback failed: {}",
                    restore_errors.join("; ")
                )));
            }
            return Err(error);
        }
        Ok(())
    }

    fn reconcile(&self, enabled: bool, executable: &Path) -> Result<()> {
        if !enabled {
            return self.remove(&self.run);
        }
        ensure!(
            self.approved()?,
            "{}",
            tr!(
                "Windows 已禁用 Clyntis 登录启动，请在任务管理器的启动应用中启用，或在应用设置中重新保存登录启动选项",
                "Windows disabled Clyntis login startup; enable it in Task Manager Startup apps or save the login startup option again"
            )
        );
        // Startup repairs missing/moved entries without undoing a Task Manager opt-out.
        self.write_command(&command(executable)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRegistry {
        path: String,
        registration: Registration,
    }
    impl TestRegistry {
        fn new() -> Self {
            let path = format!(r"Software\Clyntis\AutostartTests\{}", uuid::Uuid::new_v4());
            let root = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(&path)
                .unwrap()
                .0;
            Self {
                path,
                registration: Registration {
                    root,
                    run: "Run".into(),
                    approval: "Approval".into(),
                },
            }
        }
        fn run(&self) -> OsString {
            self.registration
                .root
                .open_subkey("Run")
                .unwrap()
                .get_value(NAME)
                .unwrap()
        }
        fn approval(&self, state: u8) {
            let mut bytes = ENABLED;
            bytes[0] = state;
            self.registration
                .root
                .create_subkey("Approval")
                .unwrap()
                .0
                .set_raw_value(
                    NAME,
                    &RegValue {
                        vtype: REG_BINARY,
                        bytes: bytes.to_vec().into(),
                    },
                )
                .unwrap();
        }
    }
    impl Drop for TestRegistry {
        fn drop(&mut self) {
            assert!(self.path.starts_with(r"Software\Clyntis\AutostartTests\"));
            RegKey::predef(HKEY_CURRENT_USER)
                .delete_subkey_all(&self.path)
                .unwrap();
        }
    }

    #[test]
    fn quotes_spaces_unicode_and_normalizes_extended_paths() {
        assert_eq!(
            command(Path::new(r"C:\Program Files\Clyntis\clyntis-desktop.exe")).unwrap(),
            OsString::from(r#""C:\Program Files\Clyntis\clyntis-desktop.exe""#)
        );
        assert_eq!(
            command(Path::new(r"\\?\C:\应用 空格\clyntis.exe")).unwrap(),
            OsString::from(r#""C:\应用 空格\clyntis.exe""#)
        );
        assert!(command(Path::new(r"relative\clyntis.exe")).is_err());
    }

    #[test]
    fn startup_repairs_missing_and_stale_entries() {
        let fixture = TestRegistry::new();
        let r = &fixture.registration;
        fixture.approval(2);
        let exe = Path::new(r"C:\Program Files\Clyntis\clyntis-desktop.exe");
        r.reconcile(true, exe).unwrap();
        assert_eq!(fixture.run(), command(exe).unwrap());
        r.root
            .open_subkey_with_flags("Run", KEY_SET_VALUE)
            .unwrap()
            .set_value(NAME, &format!("{} ", exe.display()))
            .unwrap();
        r.reconcile(true, exe).unwrap();
        assert_eq!(fixture.run(), command(exe).unwrap());
        let moved = Path::new(r"D:\应用\clyntis-desktop.exe");
        r.reconcile(true, moved).unwrap();
        assert_eq!(fixture.run(), command(moved).unwrap());
        r.reconcile(true, moved).unwrap();
    }

    #[test]
    fn repeated_enable_and_disable_preserve_unrelated_apps() {
        let fixture = TestRegistry::new();
        let r = &fixture.registration;
        let exe = Path::new(r"D:\Clyntis\clyntis-desktop.exe");
        r.set(false, exe).unwrap();
        r.set(true, exe).unwrap();
        r.root
            .open_subkey_with_flags("Run", KEY_SET_VALUE)
            .unwrap()
            .set_value("Other app", &"keep")
            .unwrap();
        r.set(true, exe).unwrap();
        assert_eq!(fixture.run(), command(exe).unwrap());
        r.set(false, exe).unwrap();
        r.set(false, exe).unwrap();
        r.set(true, exe).unwrap();
        r.reconcile(false, exe).unwrap();
        assert!(r.read("Run").unwrap().is_none());
        assert_eq!(
            r.root
                .open_subkey("Run")
                .unwrap()
                .get_value::<String, _>("Other app")
                .unwrap(),
            "keep"
        );
    }

    #[test]
    fn startup_respects_task_manager_disable_but_explicit_save_enables() {
        let fixture = TestRegistry::new();
        let r = &fixture.registration;
        let exe = Path::new(r"D:\Clyntis\clyntis-desktop.exe");
        for state in [3, 7] {
            fixture.approval(state);
            assert!(r.reconcile(true, exe).is_err());
            assert!(!r.approved().unwrap());
            r.set(true, exe).unwrap();
            assert!(r.approved().unwrap());
        }
        fixture.approval(6);
        r.reconcile(true, exe).unwrap();
    }
}
