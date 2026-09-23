use std::{
    io::Write,
    process::{Command, Stdio},
};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_clyntis"));
    for name in [
        "CLASH_HOME_DIR",
        "CLASH_CONFIG_FILE",
        "CLASH_CONFIG_STRING",
        "CLASH_OVERRIDE_EXTERNAL_CONTROLLER",
        "CLASH_OVERRIDE_SECRET",
    ] {
        command.env_remove(name);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command
}

#[test]
fn version_stdin_and_unknown_configuration() {
    let version = command().arg("-v").output().unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("clyntis "));
    for (input, valid) in [
        ("mixed-port: 7890\n", true),
        ("proxy-providers: {}\n", false),
        ("tun:\n  enable: true\n", true),
        (
            "tun:\n  enable: true\n  auto-detect-interface: false\n",
            false,
        ),
    ] {
        let mut child = command()
            .args(["-f", "-", "-t"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.success(),
            valid,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn legacy_encryption_roundtrip_wrong_password_and_no_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("config.yaml");
    let encrypted = directory.path().join("config-encrypt.yaml");
    let decrypted = directory.path().join("config-decrypt.yaml");
    let plaintext = b"mixed-port: 7890\nmode: rule\nrules: ['MATCH,DIRECT']\n";
    std::fs::write(&source, plaintext).unwrap();
    let output = command()
        .arg("-f")
        .arg(&source)
        .args(["--action", "encrypt", "-p", "test-password"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        command()
            .arg("-f")
            .arg(&encrypted)
            .args(["-t", "-p", "test-password"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !command()
            .arg("-f")
            .arg(&encrypted)
            .args(["--action", "decrypt", "-p", "wrong"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!decrypted.exists());
    assert!(
        command()
            .arg("-f")
            .arg(&encrypted)
            .args(["--action", "decrypt", "-p", "test-password"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(std::fs::read(&decrypted).unwrap(), plaintext);
    assert!(
        !command()
            .arg("-f")
            .arg(&source)
            .args(["--action", "encrypt", "-p", "new-password"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(std::fs::read(source).unwrap(), plaintext);
}
