use super::*;
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{Icmpv4Packet, Icmpv4Repr, IpProtocol, Ipv4Packet, Ipv4Repr},
};
use std::{
    ffi::c_void,
    sync::atomic::AtomicUsize,
    time::{Duration, Instant},
};

fn create(config: &[u8], hooks: *const MetaPlatformV1) -> u64 {
    let mut id = 0;
    assert_eq!(
        unsafe { meta_create_v1(config.as_ptr(), config.len(), hooks, &mut id) },
        OK
    );
    id
}
fn snapshot(id: u64) -> serde_json::Value {
    let mut length = 0;
    assert_eq!(
        unsafe { meta_snapshot_v1(id, std::ptr::null_mut(), 0, &mut length) },
        BUFFER_TOO_SMALL
    );
    let mut bytes = vec![0; length + 1024];
    assert_eq!(
        unsafe { meta_snapshot_v1(id, bytes.as_mut_ptr(), bytes.len(), &mut length) },
        OK
    );
    serde_json::from_slice(&bytes[..length]).unwrap()
}

#[test]
fn decrypt_config_preserves_plaintext_and_caller_buffer_contract() {
    let plaintext = b"# preserve comments\nauthentication: ['user:secret']\nmode: rule\nrules: ['MATCH,DIRECT']\n";
    for password in [
        "test-password",
        "12345678901234567",
        "1234567890123456789012345",
        "密码测试",
    ] {
        let encoded = clyntis_config::crypto::encrypt(plaintext, password).unwrap();
        let wrapped = format!(" \n{}\r\n{}\t", &encoded[..16], &encoded[16..]);
        let mut length = 99;
        let mut short = [0xaa; 2];
        assert_eq!(
            unsafe {
                meta_decrypt_config_v1(
                    wrapped.as_ptr(),
                    wrapped.len(),
                    password.as_ptr(),
                    password.len(),
                    short.as_mut_ptr(),
                    short.len(),
                    &mut length,
                )
            },
            BUFFER_TOO_SMALL
        );
        assert_eq!(length, plaintext.len());
        assert_eq!(short, [0xaa; 2]);
        let mut bytes = vec![0; length];
        assert_eq!(
            unsafe {
                meta_decrypt_config_v1(
                    wrapped.as_ptr(),
                    wrapped.len(),
                    password.as_ptr(),
                    password.len(),
                    bytes.as_mut_ptr(),
                    bytes.len(),
                    &mut length,
                )
            },
            OK
        );
        assert_eq!(&bytes[..length], plaintext);
    }
    // Independent Alpha/Go golden vector, rather than a Rust-only round trip.
    let encoded = b"fzpHye22WU1hKPevr2RwfVJhLri0X0NMDQS3D4iMfGPUsXSwpivnmPeok4ej8i4i8P8bgw==";
    let mut length = 0;
    let mut bytes = [0; 256];
    assert_eq!(
        unsafe {
            meta_decrypt_config_v1(
                encoded.as_ptr(),
                encoded.len(),
                b"test-password".as_ptr(),
                13,
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut length,
            )
        },
        OK
    );
    assert_eq!(
        &bytes[..length],
        b"mixed-port: 7890\nmode: rule\nrules: ['MATCH,DIRECT']\n"
    );
}

#[test]
fn encrypt_config_round_trips_through_decrypt() {
    let plaintext = b"mixed-port: 7890\nmode: rule\nrules: ['MATCH,DIRECT']\n";
    let password = "导出密码";
    let mut length = 0;
    assert_eq!(
        unsafe {
            meta_encrypt_config_v1(
                plaintext.as_ptr(),
                plaintext.len(),
                password.as_ptr(),
                password.len(),
                std::ptr::null_mut(),
                0,
                &mut length,
            )
        },
        BUFFER_TOO_SMALL
    );
    let mut encoded = vec![0; length];
    assert_eq!(
        unsafe {
            meta_encrypt_config_v1(
                plaintext.as_ptr(),
                plaintext.len(),
                password.as_ptr(),
                password.len(),
                encoded.as_mut_ptr(),
                encoded.len(),
                &mut length,
            )
        },
        OK
    );
    let mut decoded = [0; 256];
    assert_eq!(
        unsafe {
            meta_decrypt_config_v1(
                encoded.as_ptr(),
                length,
                password.as_ptr(),
                password.len(),
                decoded.as_mut_ptr(),
                decoded.len(),
                &mut length,
            )
        },
        OK
    );
    assert_eq!(&decoded[..length], plaintext);
    for (config, password) in [(&b"not: [valid"[..], "p"), (&plaintext[..], "")] {
        assert_ne!(
            unsafe {
                meta_encrypt_config_v1(
                    config.as_ptr(),
                    config.len(),
                    password.as_ptr(),
                    password.len(),
                    encoded.as_mut_ptr(),
                    encoded.len(),
                    &mut length,
                )
            },
            OK
        );
        assert_eq!(length, 0);
    }
}

#[test]
fn decrypt_config_rejects_bad_password_and_invalid_input_without_plaintext() {
    let valid = clyntis_config::crypto::encrypt(b"mode: direct\n", "correct").unwrap();
    let invalid =
        clyntis_config::crypto::encrypt(b"unknown-field: private-secret\n", "correct").unwrap();
    for (data, password) in [
        (valid.as_bytes(), "wrong"),
        (invalid.as_bytes(), "correct"),
        (b"not-base64!".as_slice(), "correct"),
    ] {
        let mut length = 99;
        let mut bytes = [0xaa; 256];
        assert_eq!(
            unsafe {
                meta_decrypt_config_v1(
                    data.as_ptr(),
                    data.len(),
                    password.as_ptr(),
                    password.len(),
                    bytes.as_mut_ptr(),
                    bytes.len(),
                    &mut length,
                )
            },
            ERROR
        );
        assert_eq!(length, 0);
        assert_eq!(bytes, [0xaa; 256]);
        assert!(!ERROR_TEXT.with(|text| text.borrow().contains("private-secret")));
    }
    let mut length = 99;
    assert_eq!(
        unsafe {
            meta_decrypt_config_v1(
                valid.as_ptr(),
                valid.len(),
                b"correct".as_ptr(),
                7,
                std::ptr::null_mut(),
                512,
                &mut length,
            )
        },
        ERROR
    );
    assert_eq!(length, 0);
    assert_eq!(
        unsafe {
            meta_decrypt_config_v1(
                std::ptr::null(),
                1,
                b"pwd".as_ptr(),
                3,
                std::ptr::null_mut(),
                0,
                &mut length,
            )
        },
        ERROR
    );
    assert_eq!(length, 0);
    assert_eq!(
        unsafe {
            meta_decrypt_config_v1(
                b"x".as_ptr(),
                24 * 1024 * 1024 + 1,
                b"pwd".as_ptr(),
                3,
                std::ptr::null_mut(),
                0,
                &mut length,
            )
        },
        ERROR
    );
    assert_eq!(length, 0);
}

#[test]
fn checked_handles_independent_runtimes_and_caller_buffers() {
    assert_eq!(meta_abi_version_v1(), 1);
    let a = create(b"authentication: ['user:secret']\n", std::ptr::null());
    let b = create(b"{}", std::ptr::null());
    assert_ne!(a, b);
    assert_eq!(meta_start_v1(a), OK);
    assert_eq!(meta_start_v1(a), ERROR);
    assert_eq!(meta_start_v1(b), OK);
    let update = br#"{"mode":"direct"}"#;
    assert_eq!(
        unsafe { meta_update_v1(a, update.as_ptr(), update.len()) },
        OK
    );
    assert_eq!(snapshot(a)["config"]["mode"], "direct");
    assert!(snapshot(a)["config"].get("authentication").is_none());
    assert_eq!(meta_stop_v1(a), OK);
    assert_eq!(snapshot(a)["stopped"], true);
    assert_eq!(snapshot(b)["stopped"], false);
    assert_eq!(meta_destroy_v1(a), OK);
    assert_eq!(meta_destroy_v1(a), ERROR);
    assert_eq!(meta_start_v1(a), ERROR);
    assert_eq!(meta_destroy_v1(b), OK);
    let mut id = 99;
    assert_eq!(
        unsafe { meta_create_v1(std::ptr::null(), 4, std::ptr::null(), &mut id) },
        ERROR
    );
    assert_eq!(id, 0);
    let short_hooks: u32 = 4;
    assert_eq!(
        unsafe {
            meta_create_v1(
                b"{}".as_ptr(),
                2,
                (&short_hooks as *const u32).cast(),
                &mut id,
            )
        },
        ERROR
    );
    assert_eq!(id, 0);
}

/// Held by tests that create packet-tunnel cores: each sets the process-wide
/// panic file to its own directory.
static PANIC_FILE_USERS: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn packet_tunnel_host_keeps_credentials_and_disables_desktop_listeners() {
    let _panic_file = PANIC_FILE_USERS.lock().unwrap_or_else(|e| e.into_inner());
    let directory = std::env::temp_dir().join(format!("clyntis-ios-{}", uuid_for_test()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.to_str().unwrap().as_bytes();
    let config = b"port: 17891\nsocks-port: 17892\nmixed-port: 17893\nallow-lan: true\nexternal-controller: 127.0.0.1:17894\nauthentication: ['user:secret']\ndns: {enable: true}\nproxies: [{name: node, type: vless, server: example.com, port: 443, uuid: '11111111-1111-4111-8111-111111111111'}]\n";
    let mut id = 0;
    assert_eq!(
        unsafe {
            meta_create_packet_tunnel_v1(
                config.as_ptr(),
                config.len(),
                path.as_ptr(),
                path.len(),
                std::ptr::null(),
                &mut id,
            )
        },
        OK,
        "{}",
        ERROR_TEXT.with(|text| text.borrow().clone())
    );
    let owner = handle(id).unwrap();
    let runtime = &owner.core.config;
    assert_eq!(
        (runtime.port, runtime.socks_port, runtime.mixed_port),
        (0, 0, 0)
    );
    assert!(!runtime.allow_lan && !runtime.dns.enable);
    assert!(runtime.external_controller.is_none());
    assert!(runtime.tun.enable);
    assert_eq!(runtime.tun.mtu, 1280);
    assert_eq!(runtime.tun.dns_hijack, ["any:53"]);
    assert_eq!(runtime.directory, directory);
    assert_eq!(runtime.authentication, ["user:secret"]);
    assert_eq!(
        runtime.proxies[0].uuid.unwrap().to_string(),
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(meta_start_v1(id), OK);
    assert_eq!(meta_destroy_v1(id), OK);
    drop(owner);
    std::fs::remove_dir_all(directory).unwrap();
}

fn uuid_for_test() -> u64 {
    static IDS: AtomicU64 = AtomicU64::new(1);
    (std::process::id() as u64) << 32 | IDS.fetch_add(1, Ordering::Relaxed)
}

#[test]
fn packet_tunnel_host_rejects_invalid_resource_directory_and_clears_handle() {
    let _panic_file = PANIC_FILE_USERS.lock().unwrap_or_else(|e| e.into_inner());
    let mut id = 99;
    assert_eq!(
        unsafe {
            meta_create_packet_tunnel_v1(
                b"{}".as_ptr(),
                2,
                b"relative".as_ptr(),
                8,
                std::ptr::null(),
                &mut id,
            )
        },
        ERROR
    );
    assert_eq!(id, 0);
}

struct Callbacks {
    id: AtomicU64,
    notifications: AtomicUsize,
}
unsafe extern "C" fn ready(context: *mut c_void) {
    let context = unsafe { &*(context as *const Callbacks) };
    assert_eq!(meta_stop_v1(context.id.load(Ordering::Relaxed)), ERROR);
    let mut nested = 99;
    assert_eq!(
        unsafe { meta_create_v1(b"{}".as_ptr(), 2, std::ptr::null(), &mut nested) },
        ERROR
    );
    assert_eq!(nested, 0);
    context.notifications.fetch_add(1, Ordering::Relaxed);
}
#[test]
fn packet_buffers_notifications_and_shutdown_ownership() {
    let context = Box::new(Callbacks {
        id: AtomicU64::new(0),
        notifications: AtomicUsize::new(0),
    });
    let hooks = MetaPlatformV1 {
        size: std::mem::size_of::<MetaPlatformV1>() as u32,
        version: 1,
        context: (&*context as *const Callbacks).cast_mut().cast(),
        protect_socket: None,
        packet_ready: Some(ready),
    };
    let id = create(b"tun: {enable: true}\n", &hooks);
    context.id.store(id, Ordering::Relaxed);
    assert_eq!(meta_start_v1(id), OK);
    let icmp = Icmpv4Repr::EchoRequest {
        ident: 42,
        seq_no: 3,
        data: b"host-packet",
    };
    let ip = Ipv4Repr {
        src_addr: "10.0.0.2".parse().unwrap(),
        dst_addr: "198.18.0.1".parse().unwrap(),
        next_header: IpProtocol::Icmp,
        payload_len: icmp.buffer_len(),
        hop_limit: 64,
    };
    let mut packet = vec![0; ip.buffer_len() + icmp.buffer_len()];
    let mut frame = Ipv4Packet::new_unchecked(&mut packet);
    ip.emit(&mut frame, &ChecksumCapabilities::default());
    icmp.emit(
        &mut Icmpv4Packet::new_unchecked(frame.payload_mut()),
        &ChecksumCapabilities::default(),
    );
    assert_eq!(
        unsafe { meta_write_packet_v1(id, packet.as_ptr(), packet.len()) },
        OK
    );
    let until = Instant::now() + Duration::from_secs(3);
    while context.notifications.load(Ordering::Relaxed) == 0 {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut length = 0;
    assert_eq!(
        unsafe { meta_read_packet_v1(id, std::ptr::null_mut(), 0, &mut length) },
        BUFFER_TOO_SMALL
    );
    let mut response = vec![0; length];
    assert_eq!(
        unsafe { meta_read_packet_v1(id, response.as_mut_ptr(), response.len(), &mut length) },
        OK
    );
    let frame = Ipv4Packet::new_checked(&response).unwrap();
    assert_eq!(frame.dst_addr(), ip.src_addr);
    let response = Icmpv4Repr::parse(
        &Icmpv4Packet::new_checked(frame.payload()).unwrap(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    assert!(matches!(
        response,
        Icmpv4Repr::EchoReply {
            ident: 42,
            seq_no: 3,
            data: b"host-packet"
        }
    ));
    assert_eq!(meta_destroy_v1(id), OK);
    let notifications = context.notifications.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(10));
    assert_eq!(context.notifications.load(Ordering::Relaxed), notifications);
}

/// A host that reads only after packet_ready, until META_WOULD_BLOCK, gets
/// every reply although the core notifies once per drain, not per packet.
#[test]
fn coalesced_packet_ready_delivers_every_reply() {
    const ECHOES: u16 = 500;
    let context = Box::new(Callbacks {
        id: AtomicU64::new(0),
        notifications: AtomicUsize::new(0),
    });
    let hooks = MetaPlatformV1 {
        size: std::mem::size_of::<MetaPlatformV1>() as u32,
        version: 1,
        context: (&*context as *const Callbacks).cast_mut().cast(),
        protect_socket: None,
        packet_ready: Some(ready),
    };
    let id = create(b"tun: {enable: true}\n", &hooks);
    context.id.store(id, Ordering::Relaxed);
    assert_eq!(meta_start_v1(id), OK);
    let echo = |seq_no: u16| {
        let icmp = Icmpv4Repr::EchoRequest {
            ident: 7,
            seq_no,
            data: b"burst",
        };
        let ip = Ipv4Repr {
            src_addr: "10.0.0.2".parse().unwrap(),
            dst_addr: "198.18.0.1".parse().unwrap(),
            next_header: IpProtocol::Icmp,
            payload_len: icmp.buffer_len(),
            hop_limit: 64,
        };
        let mut packet = vec![0; ip.buffer_len() + icmp.buffer_len()];
        let mut frame = Ipv4Packet::new_unchecked(&mut packet);
        ip.emit(&mut frame, &ChecksumCapabilities::default());
        icmp.emit(
            &mut Icmpv4Packet::new_unchecked(frame.payload_mut()),
            &ChecksumCapabilities::default(),
        );
        packet
    };
    let (mut sent, mut replies, mut handled) = (0u16, 0u16, 0usize);
    let until = Instant::now() + Duration::from_secs(10);
    let mut buffer = vec![0; 2048];
    while replies < ECHOES {
        assert!(
            Instant::now() < until,
            "stalled at {replies} replies: a lost wakeup"
        );
        if sent < ECHOES {
            let packet = echo(sent);
            if unsafe { meta_write_packet_v1(id, packet.as_ptr(), packet.len()) } == OK {
                sent += 1;
            }
        }
        let notified = context.notifications.load(Ordering::Acquire);
        if notified == handled {
            if sent == ECHOES {
                std::thread::sleep(Duration::from_millis(1));
            }
            continue;
        }
        handled = notified;
        loop {
            let mut length = 0;
            match unsafe { meta_read_packet_v1(id, buffer.as_mut_ptr(), buffer.len(), &mut length) }
            {
                OK => replies += 1,
                WOULD_BLOCK => break,
                status => panic!("read failed: {status}"),
            }
        }
    }
    assert_eq!(meta_destroy_v1(id), OK);
    let notifications = context.notifications.load(Ordering::Relaxed);
    assert!(
        notifications < ECHOES as usize,
        "{notifications} notifications"
    );
}

#[test]
fn prefetch_downloads_rule_providers_into_the_host_directory() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0; 1024];
        let _ = socket.read(&mut request);
        let body = "payload:\n  - DOMAIN-SUFFIX,ads.example\n";
        write!(
            socket,
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let directory = std::env::temp_dir().join(format!("meta-prefetch-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let config = format!(
        "rule-providers:\n  ads:\n    type: http\n    behavior: classical\n    format: yaml\n    url: http://{address}/ads.yaml\n    path: ./rules/ads.yaml\n    interval: 600\nrules:\n  - RULE-SET,ads,REJECT\n  - MATCH,DIRECT\n"
    );
    let path = directory.to_str().unwrap();
    let call = |path: &str| unsafe {
        meta_prefetch_resources_v1(config.as_ptr(), config.len(), path.as_ptr(), path.len())
    };
    assert_eq!(call(path), OK);
    server.join().unwrap();
    let saved = std::fs::read_to_string(directory.join("rules/ads.yaml")).unwrap();
    assert!(saved.contains("ads.example"));
    // Present and fresh: no second download (the server is gone).
    assert_eq!(call(path), OK);
    assert_ne!(call("relative/dir"), OK);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn drain_logs_keeps_lines_until_they_fit() {
    // Drain anything earlier tests logged, then add known lines.
    let mut length = 0;
    let mut scratch = vec![0u8; 1 << 20];
    unsafe { meta_drain_logs_v1(scratch.as_mut_ptr(), scratch.len(), &mut length) };
    logs::record_for_test(r#"{"type":"info","payload":"one"}"#);
    logs::record_for_test(r#"{"type":"error","payload":"two"}"#);
    let mut small = [0u8; 4];
    assert_eq!(
        unsafe { meta_drain_logs_v1(small.as_mut_ptr(), small.len(), &mut length) },
        BUFFER_TOO_SMALL
    );
    let mut buffer = vec![0u8; length + 64];
    assert_eq!(
        unsafe { meta_drain_logs_v1(buffer.as_mut_ptr(), buffer.len(), &mut length) },
        OK
    );
    let text = std::str::from_utf8(&buffer[..length]).unwrap();
    assert!(
        text.contains("\"one\"") && text.contains("\"two\""),
        "{text}"
    );
    // Drained lines are gone (parallel tests may log other lines meanwhile).
    let mut buffer = vec![0u8; 1 << 20];
    assert_eq!(
        unsafe { meta_drain_logs_v1(buffer.as_mut_ptr(), buffer.len(), &mut length) },
        OK
    );
    let text = std::str::from_utf8(&buffer[..length]).unwrap();
    assert!(
        !text.contains("\"one\"") && !text.contains("\"two\""),
        "{text}"
    );
}

#[test]
fn custom_rules_validate_list_targets_and_apply() {
    let rule = b"DOMAIN,example.com,DIRECT";
    assert_eq!(
        unsafe { meta_custom_rule_validate_v1(rule.as_ptr(), rule.len()) },
        OK
    );
    let bad = b"MATCH,DIRECT";
    assert_eq!(
        unsafe { meta_custom_rule_validate_v1(bad.as_ptr(), bad.len()) },
        ERROR
    );
    let config = b"proxy-groups:\n  - {name: Auto, type: select, proxies: [DIRECT]}\nrules:\n  - MATCH,Auto\n";
    let mut buffer = vec![0u8; 4096];
    let mut length = 0;
    assert_eq!(
        unsafe {
            meta_custom_rule_targets_v1(
                config.as_ptr(),
                config.len(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut length,
            )
        },
        OK
    );
    let targets: Vec<String> = serde_json::from_slice(&buffer[..length]).unwrap();
    assert_eq!(targets, ["DIRECT", "REJECT", "Auto"]);
    let rules = br#"["DOMAIN,ads.test,REJECT","DOMAIN,x.test,Gone"]"#;
    assert_eq!(
        unsafe {
            meta_custom_rules_apply_v1(
                config.as_ptr(),
                config.len(),
                rules.as_ptr(),
                rules.len(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut length,
            )
        },
        OK
    );
    let applied: serde_json::Value = serde_json::from_slice(&buffer[..length]).unwrap();
    let merged =
        clyntis_config::Config::parse(applied["yaml"].as_str().unwrap().as_bytes()).unwrap();
    assert_eq!(merged.rules, ["DOMAIN,ads.test,REJECT", "MATCH,Auto"]);
    assert_eq!(applied["skipped"][0]["rule"], "DOMAIN,x.test,Gone");
}

#[test]
fn overrides_replace_profile_settings() {
    let config = b"log-level: debug\nipv6: false\nmode: rule\n";
    let overrides = br#"{"logLevel":"error","ipv6":true}"#;
    let mut buffer = vec![0u8; 4096];
    let mut length = 0;
    assert_eq!(
        unsafe {
            meta_overrides_apply_v1(
                config.as_ptr(),
                config.len(),
                overrides.as_ptr(),
                overrides.len(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut length,
            )
        },
        OK
    );
    let merged = clyntis_config::Config::parse(&buffer[..length]).unwrap();
    assert_eq!(merged.log.log_level, "error");
    assert!(merged.ipv6);
    let invalid = br#"{"logLevel":"loud"}"#;
    assert_ne!(
        unsafe {
            meta_overrides_apply_v1(
                config.as_ptr(),
                config.len(),
                invalid.as_ptr(),
                invalid.len(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut length,
            )
        },
        OK
    );
}

#[test]
fn yaml_check_reports_the_first_error() {
    let check = |config: &[u8]| {
        let mut buffer = vec![0u8; 4096];
        let mut length = 0;
        assert_eq!(
            unsafe {
                meta_yaml_check_v1(
                    config.as_ptr(),
                    config.len(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut length,
                )
            },
            OK
        );
        serde_json::from_slice::<serde_json::Value>(&buffer[..length]).unwrap()
    };
    assert!(check(b"mode: rule\n").is_null());
    let error = check(b"mode: rule\nrules: [a\n");
    assert!(error["line"].as_u64().unwrap() >= 2, "{error}");
    assert!(error["message"].is_string(), "{error}");
}

#[test]
fn resource_state_reports_missing_files_without_parsing_them() {
    let dir = std::env::temp_dir().join(format!("clyntis-ffi-state-{}", uuid_for_test()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = b"geo-auto-update: true\nrules: ['GEOSITE,cn,DIRECT', 'MATCH,DIRECT']\n";
    let path = dir.to_str().unwrap().as_bytes();
    let state = || {
        let mut state = u32::MAX;
        let result = unsafe {
            meta_resources_state_v1(
                config.as_ptr(),
                config.len(),
                path.as_ptr(),
                path.len(),
                &mut state,
            )
        };
        assert_eq!(result, OK);
        state
    };
    assert_eq!(state(), 2);
    // An empty (unparseable) file still counts as present and current.
    std::fs::write(dir.join("geosite.dat"), b"").unwrap();
    assert_eq!(state(), 0);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn closing_connections_accepts_one_id_or_all() {
    let config = b"mode: rule\n";
    let mut id = 0;
    assert_eq!(
        unsafe { meta_create_v1(config.as_ptr(), config.len(), std::ptr::null(), &mut id) },
        OK
    );
    assert_eq!(meta_close_connections_v1(id), OK);
    let unknown = b"no-such-connection";
    assert_eq!(
        unsafe { meta_close_connection_v1(id, unknown.as_ptr(), unknown.len()) },
        OK
    );
    assert_eq!(meta_destroy_v1(id), OK);
}

#[test]
fn route_test_reports_the_rule_and_node_as_json() {
    let id = create(
        b"proxy-groups:\n- {name: Pick, type: select, proxies: [REJECT, DIRECT]}\nrules: ['DOMAIN-KEYWORD,video,Pick', 'MATCH,DIRECT']\n",
        std::ptr::null(),
    );
    let test = |request: &str| {
        let mut bytes = vec![0; 4096];
        let mut length = 0;
        let status = unsafe {
            meta_test_route_v1(
                id,
                request.as_ptr(),
                request.len(),
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut length,
            )
        };
        (status, bytes[..length].to_vec())
    };
    let (status, bytes) = test(r#"{"target":"video.example:8443"}"#);
    assert_eq!(status, OK);
    let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["rule"], "DOMAIN-KEYWORD,video,Pick");
    assert_eq!(result["chain"], serde_json::json!(["Pick", "REJECT"]));
    assert_eq!(
        (result["node"].as_str(), result["port"].as_u64()),
        (Some("REJECT"), Some(8443))
    );
    assert_eq!(test(r#"{"target":""}"#).0, ERROR);
    let mut bytes = vec![0; 4096];
    let mut length = 0;
    assert_eq!(
        unsafe { meta_dns_leak_v1(id, 0, bytes.as_mut_ptr(), bytes.len(), &mut length) },
        OK
    );
    let leak: serde_json::Value = serde_json::from_slice(&bytes[..length]).unwrap();
    assert_eq!(leak["audit"]["leaking"], false);
    assert!(leak.get("test").is_none());
    assert_eq!(test(r#"{"target":"a.example","port":0}"#).0, ERROR);
    assert_eq!(meta_destroy_v1(id), OK);
    assert_eq!(test(r#"{"target":"a.example"}"#).0, ERROR);
}

#[test]
fn panics_reach_the_panic_file_even_if_the_process_dies() {
    let _panic_file = PANIC_FILE_USERS.lock().unwrap_or_else(|e| e.into_inner());
    let directory = std::env::temp_dir().join(format!("clyntis-panic-{}", uuid_for_test()));
    std::fs::create_dir(&directory).unwrap();
    logs::init("info");
    logs::set_panic_file(directory.join("panic.log"));
    let marker = format!("test panic {}", uuid_for_test());
    let message = marker.clone();
    let result = std::thread::Builder::new()
        .name("panicking-worker".into())
        .spawn(move || panic!("{message}"))
        .unwrap()
        .join();
    assert!(result.is_err());
    let written = std::fs::read_to_string(directory.join("panic.log")).unwrap();
    assert!(
        written.contains(&marker) && written.contains("panicking-worker"),
        "{written}"
    );
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn network_changes_never_block_or_fail_on_a_busy_worker() {
    let id = create(b"rules: ['MATCH,DIRECT']\n", std::ptr::null());
    let started = Instant::now();
    // More than the command queue holds: none may be refused.
    for _ in 0..100 {
        assert_eq!(meta_network_changed_v1(id), OK);
    }
    assert!(started.elapsed() < Duration::from_secs(1));
    let mut bytes = vec![0; 256];
    let mut length = 0;
    assert_eq!(
        unsafe { meta_status_v1(id, bytes.as_mut_ptr(), bytes.len(), &mut length) },
        OK
    );
    let status: serde_json::Value = serde_json::from_slice(&bytes[..length]).unwrap();
    assert_eq!(
        status,
        serde_json::json!({"stopped": false, "connections": 0, "upload": 0, "download": 0})
    );
    assert_eq!(meta_destroy_v1(id), OK);
    assert_eq!(meta_network_changed_v1(id), ERROR);
}

#[test]
fn the_reported_network_selects_overrides_and_shows_in_the_snapshot() {
    let id = create(
        concat!(
            "networks: {home: {ssid: Home}}\n",
            "network-overrides: [{network: home, hosts: {nas.example: 192.168.2.10}}]\n",
            "rules: ['MATCH,DIRECT']\n",
        )
        .as_bytes(),
        std::ptr::null(),
    );
    let network =
        br#"{"type":"wifi","ssid":"Home","addresses":["192.168.2.7"],"gateways":["192.168.2.1"]}"#;
    assert_eq!(
        unsafe { meta_set_network_v1(id, network.as_ptr(), network.len()) },
        OK
    );
    let mut bytes = vec![0; 1 << 20];
    let mut length = 0;
    assert_eq!(
        unsafe { meta_snapshot_v1(id, bytes.as_mut_ptr(), bytes.len(), &mut length) },
        OK
    );
    let snapshot: serde_json::Value = serde_json::from_slice(&bytes[..length]).unwrap();
    assert_eq!(snapshot["network"]["networks"], serde_json::json!(["home"]));
    assert_eq!(snapshot["network"]["override"], "home");
    assert!(snapshot.get("traffic").is_none());
    let invalid = b"{\"addresses\":[\"not an address\"]}";
    assert_eq!(
        unsafe { meta_set_network_v1(id, invalid.as_ptr(), invalid.len()) },
        ERROR
    );
    assert_eq!(meta_destroy_v1(id), OK);
}

#[test]
fn cos_targets_come_from_cos_urls_and_uploads_need_credentials() {
    let url = b"https://image-1308520206.cos.ap-shanghai.myqcloud.com/config-enc.txt";
    let mut bytes = vec![0; 512];
    let mut length = 0;
    assert_eq!(
        unsafe {
            meta_cos_target_v1(
                url.as_ptr(),
                url.len(),
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut length,
            )
        },
        OK
    );
    let target: serde_json::Value = serde_json::from_slice(&bytes[..length]).unwrap();
    assert_eq!(
        target,
        serde_json::json!({"bucket": "image-1308520206", "region": "ap-shanghai", "key": "config-enc.txt"})
    );
    let other = b"https://example.com/config.txt";
    assert_eq!(
        unsafe {
            meta_cos_target_v1(
                other.as_ptr(),
                other.len(),
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut length,
            )
        },
        OK
    );
    assert_eq!(&bytes[..length], b"null");
    // Refused before any network access.
    let request = serde_json::to_vec(&serde_json::json!({
        "target": target,
        "credentials": {"secret_id": "", "secret_key": ""},
    }))
    .unwrap();
    let data = b"encrypted";
    assert_eq!(
        unsafe { meta_cos_put_v1(request.as_ptr(), request.len(), data.as_ptr(), data.len()) },
        ERROR
    );
}

/// One call with room to spare, as the apps make it: a new CA differs in
/// length from call to call (its serial is random), so a size query followed
/// by a second call does not always fit.
fn read_json(call: impl Fn(*mut u8, usize, *mut usize) -> i32) -> serde_json::Value {
    let mut length = 0;
    let mut bytes = vec![0; 64 * 1024];
    assert_eq!(call(bytes.as_mut_ptr(), bytes.len(), &mut length), OK);
    serde_json::from_slice(&bytes[..length]).unwrap()
}

#[test]
fn decryption_settings_change_live_and_the_request_log_is_readable() {
    let ca = read_json(|b, c, l| unsafe { meta_mitm_generate_ca_v1(b, c, l) });
    let check = serde_json::to_vec(&ca).unwrap();
    let checked =
        read_json(|b, c, l| unsafe { meta_mitm_check_ca_v1(check.as_ptr(), check.len(), b, c, l) });
    assert_eq!(checked["host"], clyntis_core::mitm_check_host());
    assert!(checked["leaf"].as_str().is_some_and(|s| !s.is_empty()));
    let bad = br#"{"cert":"x","key":"y"}"#;
    let mut length = 0;
    assert_eq!(
        unsafe {
            meta_mitm_check_ca_v1(
                bad.as_ptr(),
                bad.len(),
                std::ptr::null_mut(),
                0,
                &mut length,
            )
        },
        ERROR
    );

    let id = create(b"mode: rule\n", std::ptr::null());
    assert_eq!(snapshot(id)["mitm"]["active"], false);
    let update = serde_json::to_vec(&serde_json::json!({"mitm": {
        "enable": true, "hostname": ["*.ads.test"], "ca-cert": ca["cert"], "ca-key": ca["key"],
    }}))
    .unwrap();
    assert_eq!(
        unsafe { meta_update_v1(id, update.as_ptr(), update.len()) },
        OK
    );
    let status = snapshot(id)["mitm"].clone();
    assert_eq!(status["active"], true);
    assert_eq!(status["hostname"][0], "*.ads.test");
    let off = br#"{"mitm":{"enable":false}}"#;
    assert_eq!(unsafe { meta_update_v1(id, off.as_ptr(), off.len()) }, OK);
    assert_eq!(snapshot(id)["mitm"]["active"], false);

    let log = read_json(|b, c, l| unsafe { meta_requests_v1(id, 0, 100, b, c, l) });
    assert_eq!(log["requests"].as_array().unwrap().len(), 0);
    let har = read_json(|b, c, l| unsafe { meta_requests_export_v1(id, 0, b, c, l) });
    assert_eq!(har["log"]["version"], "1.2");
    let mut csv = vec![0u8; 4096];
    assert_eq!(
        unsafe { meta_requests_export_v1(id, 1, csv.as_mut_ptr(), csv.len(), &mut length) },
        OK
    );
    assert!(csv[..length].starts_with(b"id,time,"));
    assert_eq!(
        unsafe { meta_requests_export_v1(id, 9, csv.as_mut_ptr(), csv.len(), &mut length) },
        ERROR
    );
    assert_eq!(meta_clear_requests_v1(id), OK);
    assert_eq!(meta_clear_mitm_bypass_v1(id), OK);
    assert_eq!(
        unsafe { meta_request_detail_v1(id, 7, std::ptr::null_mut(), 0, &mut length) },
        ERROR
    );
    assert_eq!(meta_destroy_v1(id), OK);
}

#[test]
fn traffic_details_is_separate_from_snapshot_and_supports_host_filter() {
    let id = create(b"rules: ['MATCH,DIRECT']\n", std::ptr::null());
    let snap = snapshot(id);
    assert!(snap.get("traffic").is_none());

    let query = |host: &[u8]| -> serde_json::Value {
        let mut length = 0;
        assert_eq!(
            unsafe {
                meta_traffic_details_v1(
                    id,
                    if host.is_empty() {
                        std::ptr::null()
                    } else {
                        host.as_ptr()
                    },
                    host.len(),
                    std::ptr::null_mut(),
                    0,
                    &mut length,
                )
            },
            BUFFER_TOO_SMALL
        );
        let mut bytes = vec![0u8; length];
        assert_eq!(
            unsafe {
                meta_traffic_details_v1(
                    id,
                    if host.is_empty() {
                        std::ptr::null()
                    } else {
                        host.as_ptr()
                    },
                    host.len(),
                    bytes.as_mut_ptr(),
                    bytes.len(),
                    &mut length,
                )
            },
            OK
        );
        serde_json::from_slice(&bytes[..length]).unwrap()
    };

    let global = query(b"");
    assert_eq!(global["uploadTotal"], 0);
    assert_eq!(global["downloadTotal"], 0);
    assert!(global["hosts"].is_array());
    assert!(global["connections"].is_array());
    assert!(global.get("connectionHost").is_none());

    let filtered = query(b"Example.Test.");
    assert_eq!(filtered["connectionHost"], "example.test");
    assert_eq!(filtered["matchingActiveConnections"], 0);
    assert_eq!(filtered["matchingClosedConnections"], 0);

    assert_eq!(meta_destroy_v1(id), OK);
}

#[test]
fn buffer_too_small_retry_reuses_cached_output_once_and_clears_after() {
    let mut length = 0;
    let mut tiny = [0u8; 8];
    assert_eq!(
        unsafe { meta_mitm_generate_ca_v1(tiny.as_mut_ptr(), tiny.len(), &mut length) },
        BUFFER_TOO_SMALL
    );
    assert!(length > tiny.len());
    assert!(PENDING_OUTPUT.with(|slot| slot.borrow().is_some()));

    // Immediate retry with sufficient capacity consumes the exact cached output
    // without generating a second random CA, and clears the thread-local cache.
    let mut out = vec![0u8; length];
    assert_eq!(
        unsafe { meta_mitm_generate_ca_v1(out.as_mut_ptr(), out.len(), &mut length) },
        OK
    );
    assert!(PENDING_OUTPUT.with(|slot| slot.borrow().is_none()));
    let ca: serde_json::Value = serde_json::from_slice(&out[..length]).unwrap();
    assert!(ca["cert"].as_str().is_some_and(|s| !s.is_empty()));

    assert_eq!(
        unsafe { meta_mitm_generate_ca_v1(tiny.as_mut_ptr(), tiny.len(), &mut length) },
        BUFFER_TOO_SMALL
    );
    assert!(PENDING_OUTPUT.with(|slot| slot.borrow().is_some()));
    meta_discard_pending_output_v1();
    assert!(PENDING_OUTPUT.with(|slot| slot.borrow().is_none()));

    // An unconsumed pending buffer is also cleared if another FFI call intervenes.
    assert_eq!(
        unsafe { meta_mitm_generate_ca_v1(tiny.as_mut_ptr(), tiny.len(), &mut length) },
        BUFFER_TOO_SMALL
    );
    assert!(PENDING_OUTPUT.with(|slot| slot.borrow().is_some()));
    let rule = b"DOMAIN,example.com,DIRECT";
    assert_eq!(
        unsafe { meta_custom_rule_validate_v1(rule.as_ptr(), rule.len()) },
        OK
    );
    assert!(PENDING_OUTPUT.with(|slot| slot.borrow().is_none()));
}

#[test]
fn output_above_the_retry_cache_limit_still_reports_its_length() {
    let mut length = 0;
    let mut tiny = [0u8; 8];
    let status = boundary(|| unsafe {
        cached_output(
            (3, 1, 0, 0),
            SNAPSHOT_CACHE_LIMIT,
            tiny.as_mut_ptr(),
            tiny.len(),
            &mut length,
            || Ok(vec![0; SNAPSHOT_CACHE_LIMIT + 1]),
        )
    });
    assert_eq!(status, BUFFER_TOO_SMALL);
    assert_eq!(length, SNAPSHOT_CACHE_LIMIT + 1);
    assert!(PENDING_OUTPUT.with(|slot| slot.borrow().is_none()));
}

#[test]
fn snapshot_config_is_lightweight_and_omits_rules_and_secrets() {
    let config = concat!(
        "mixed-port: 7890\n",
        "log-level: warning\n",
        "authentication: ['user:secret']\n",
        "proxies:\n",
        "  - {name: node, type: vless, server: example.com, port: 443, uuid: '11111111-1111-4111-8111-111111111111'}\n",
        "proxy-groups:\n",
        "  - {name: Auto, type: select, proxies: [node, DIRECT]}\n",
        "rules:\n",
        "  - DOMAIN,example.com,Auto\n",
        "  - MATCH,DIRECT\n",
    );
    let id = create(config.as_bytes(), std::ptr::null());
    let snap = snapshot(id);
    assert_eq!(snap["config"]["mode"], "rule");
    assert_eq!(snap["config"]["log-level"], "warning");
    assert_eq!(snap["config"]["mixed-port"], 7890);
    assert_eq!(snap["config"]["proxy-groups"][0]["name"], "Auto");
    assert_eq!(snap["config"]["proxies"][0]["name"], "node");
    assert!(snap["config"].get("rules").is_none());
    assert!(snap["config"].get("authentication").is_none());
    assert!(snap["config"].get("dns").is_none());
    assert_eq!(meta_destroy_v1(id), OK);
}

#[test]
fn validate_config_checks_yaml_without_creating_a_core_handle() {
    let valid = b"mode: rule\nrules: ['MATCH,DIRECT']\n";
    assert_eq!(
        unsafe { meta_validate_config_v1(valid.as_ptr(), valid.len()) },
        OK
    );

    for invalid in [
        &b""[..],
        &b"not: [valid"[..],
        &b"unknown-field: true\n"[..],
        &b"proxies: [{name: bad, type: socks5}]\n"[..],
    ] {
        assert_eq!(
            unsafe { meta_validate_config_v1(invalid.as_ptr(), invalid.len()) },
            ERROR
        );
        let err = ERROR_TEXT.with(|text| text.borrow().clone());
        assert!(!err.is_empty());
    }
    assert_eq!(
        unsafe { meta_validate_config_v1(std::ptr::null(), 4) },
        ERROR
    );
}

#[test]
fn packet_io_does_not_clear_pending_output_and_records_errors() {
    let id = create(b"tun: {enable: true}\n", std::ptr::null());

    let mut length = 0;
    let mut tiny = [0u8; 8];
    assert_eq!(
        unsafe { meta_mitm_generate_ca_v1(tiny.as_mut_ptr(), tiny.len(), &mut length) },
        BUFFER_TOO_SMALL
    );
    assert!(PENDING_OUTPUT.with(|slot| slot.borrow().is_some()));

    // Packet calls use packet_boundary and leave PENDING_OUTPUT untouched.
    let mut read_len = 0;
    let mut buf = [0u8; 64];
    assert_eq!(
        unsafe { meta_read_packet_v1(id, buf.as_mut_ptr(), buf.len(), &mut read_len) },
        WOULD_BLOCK
    );
    assert!(PENDING_OUTPUT.with(|slot| slot.borrow().is_some()));
    assert_eq!(
        unsafe { meta_write_packet_v1(id, b"short".as_ptr(), 5) },
        ERROR
    );
    assert!(ERROR_TEXT.with(|text| text.borrow().contains("invalid IP packet length")));
    assert!(PENDING_OUTPUT.with(|slot| slot.borrow().is_some()));

    meta_discard_pending_output_v1();
    assert_eq!(meta_destroy_v1(id), OK);
}

#[test]
fn node_links_import_inspect_append_and_update_via_ffi() {
    fn read_json(call: impl Fn(*mut u8, usize, *mut usize) -> i32) -> serde_json::Value {
        let mut len = 0usize;
        assert_eq!(call(std::ptr::null_mut(), 0, &mut len), BUFFER_TOO_SMALL);
        let mut buf = vec![0u8; len];
        assert_eq!(call(buf.as_mut_ptr(), buf.len(), &mut len), OK);
        serde_json::from_slice(&buf[..len]).unwrap()
    }

    let links = b"vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&sni=example.com#Node1";
    let mode = b"whitelist";
    let imported = read_json(|buf, cap, out| unsafe {
        meta_import_node_links_v1(
            links.as_ptr(),
            links.len(),
            mode.as_ptr(),
            mode.len(),
            std::ptr::null(),
            0,
            buf,
            cap,
            out,
        )
    });
    assert_eq!(imported["autoRouting"], "whitelist");
    assert_eq!(imported["nodes"][0]["name"], "Node1");
    let yaml1 = imported["yaml"].as_str().unwrap().as_bytes().to_vec();

    let info = read_json(|buf, cap, out| unsafe {
        meta_profile_nodes_v1(yaml1.as_ptr(), yaml1.len(), buf, cap, out)
    });
    assert_eq!(info["isAuto"], true);
    assert_eq!(info["nodes"].as_array().unwrap().len(), 1);

    let extra = b"hy2://secret@hy.example.com:443?sni=hy.example.com#Node2";
    let appended = read_json(|buf, cap, out| unsafe {
        meta_profile_add_links_v1(
            yaml1.as_ptr(),
            yaml1.len(),
            extra.as_ptr(),
            extra.len(),
            std::ptr::null(),
            0,
            buf,
            cap,
            out,
        )
    });
    assert_eq!(appended["nodes"][0]["name"], "Node2");
    let yaml2 = appended["yaml"].as_str().unwrap().as_bytes().to_vec();

    // Plaintext & encrypted export + encrypted re-import/append via FFI.
    let plain_exp = read_json(|buf, cap, out| unsafe {
        meta_export_node_links_v1(
            yaml2.as_ptr(),
            yaml2.len(),
            std::ptr::null(),
            0,
            buf,
            cap,
            out,
        )
    });
    assert_eq!(plain_exp["count"], 2);
    assert_eq!(plain_exp["encrypted"], false);

    let pw = b"ffi-pass";
    let enc_exp = read_json(|buf, cap, out| unsafe {
        meta_export_node_links_v1(
            yaml2.as_ptr(),
            yaml2.len(),
            pw.as_ptr(),
            pw.len(),
            buf,
            cap,
            out,
        )
    });
    assert_eq!(enc_exp["count"], 2);
    assert_eq!(enc_exp["encrypted"], true);
    let enc_text = enc_exp["text"].as_str().unwrap().as_bytes();
    let reimported = read_json(|buf, cap, out| unsafe {
        meta_import_node_links_v1(
            enc_text.as_ptr(),
            enc_text.len(),
            mode.as_ptr(),
            mode.len(),
            pw.as_ptr(),
            pw.len(),
            buf,
            cap,
            out,
        )
    });
    assert_eq!(reimported["nodes"].as_array().unwrap().len(), 2);

    let reappended = read_json(|buf, cap, out| unsafe {
        meta_profile_add_links_v1(
            yaml1.as_ptr(),
            yaml1.len(),
            enc_text.as_ptr(),
            enc_text.len(),
            pw.as_ptr(),
            pw.len(),
            buf,
            cap,
            out,
        )
    });
    assert_eq!(reappended["nodes"].as_array().unwrap().len(), 2);

    let req = br#"{"removeNames":["Node1"],"autoRouting":"blacklist"}"#;
    let mut len = 0usize;
    assert_eq!(
        unsafe {
            meta_profile_update_nodes_v1(
                yaml2.as_ptr(),
                yaml2.len(),
                req.as_ptr(),
                req.len(),
                std::ptr::null_mut(),
                0,
                &mut len,
            )
        },
        BUFFER_TOO_SMALL
    );
    let mut out = vec![0u8; len];
    assert_eq!(
        unsafe {
            meta_profile_update_nodes_v1(
                yaml2.as_ptr(),
                yaml2.len(),
                req.as_ptr(),
                req.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut len,
            )
        },
        OK
    );
    let info2 = read_json(|buf, cap, out_len| unsafe {
        meta_profile_nodes_v1(out.as_ptr(), len, buf, cap, out_len)
    });
    assert_eq!(info2["autoRouting"], "blacklist");
    assert_eq!(info2["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(info2["nodes"][0]["name"], "Node2");
}

fn make_icmp_echo(seq_no: u16, payload: &[u8]) -> Vec<u8> {
    let icmp = Icmpv4Repr::EchoRequest {
        ident: 9,
        seq_no,
        data: payload,
    };
    let ip = Ipv4Repr {
        src_addr: "10.0.0.2".parse().unwrap(),
        dst_addr: "198.18.0.1".parse().unwrap(),
        next_header: IpProtocol::Icmp,
        payload_len: icmp.buffer_len(),
        hop_limit: 64,
    };
    let mut packet = vec![0; ip.buffer_len() + icmp.buffer_len()];
    let mut frame = Ipv4Packet::new_unchecked(&mut packet);
    ip.emit(&mut frame, &ChecksumCapabilities::default());
    icmp.emit(
        &mut Icmpv4Packet::new_unchecked(frame.payload_mut()),
        &ChecksumCapabilities::default(),
    );
    packet
}

fn frame_packets(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for pkt in packets {
        out.extend_from_slice(&(pkt.len() as u16).to_le_bytes());
        out.extend_from_slice(pkt);
    }
    out
}

#[test]
fn batched_packet_io_roundtrips_multiple_packets_and_rearms_wake() {
    let context = Box::new(Callbacks {
        id: AtomicU64::new(0),
        notifications: AtomicUsize::new(0),
    });
    let hooks = MetaPlatformV1 {
        size: std::mem::size_of::<MetaPlatformV1>() as u32,
        version: 1,
        context: (&*context as *const Callbacks).cast_mut().cast(),
        protect_socket: None,
        packet_ready: Some(ready),
    };
    let id = create(b"tun: {enable: true}\n", &hooks);
    context.id.store(id, Ordering::Relaxed);
    assert_eq!(meta_start_v1(id), OK);

    let batch: Vec<Vec<u8>> = (0..10u16).map(|i| make_icmp_echo(i, b"batch")).collect();
    let framed = frame_packets(&batch);
    let mut written = 0usize;
    assert_eq!(
        unsafe { meta_write_packets_v1(id, framed.as_ptr(), framed.len(), &mut written) },
        OK
    );
    assert_eq!(written, 10);

    let until = Instant::now() + Duration::from_secs(3);
    let mut read_buf = vec![0u8; 64 * 1024];
    let mut replies = Vec::new();
    while replies.len() < 10 {
        assert!(
            Instant::now() < until,
            "timed out waiting for batched replies"
        );
        let mut length = 0usize;
        let mut count = 0usize;
        match unsafe {
            meta_read_packets_v1(
                id,
                read_buf.as_mut_ptr(),
                read_buf.len(),
                &mut length,
                &mut count,
                64,
            )
        } {
            OK => {
                assert!(count > 0);
                let mut offset = 0usize;
                for _ in 0..count {
                    let pkt_len =
                        u16::from_le_bytes([read_buf[offset], read_buf[offset + 1]]) as usize;
                    offset += 2;
                    let pkt = &read_buf[offset..offset + pkt_len];
                    offset += pkt_len;
                    let frame = Ipv4Packet::new_checked(pkt).unwrap();
                    let icmp = Icmpv4Repr::parse(
                        &Icmpv4Packet::new_checked(frame.payload()).unwrap(),
                        &ChecksumCapabilities::default(),
                    )
                    .unwrap();
                    if let Icmpv4Repr::EchoReply { seq_no, data, .. } = icmp {
                        assert_eq!(data, b"batch");
                        replies.push(seq_no);
                    }
                }
                assert_eq!(offset, length);
            }
            WOULD_BLOCK => std::thread::sleep(Duration::from_millis(1)),
            status => panic!("unexpected read status: {status}"),
        }
    }
    replies.sort_unstable();
    assert_eq!(replies, (0..10).collect::<Vec<_>>());

    let mut length = 0usize;
    let mut count = 0usize;
    assert_eq!(
        unsafe {
            meta_read_packets_v1(
                id,
                read_buf.as_mut_ptr(),
                read_buf.len(),
                &mut length,
                &mut count,
                64,
            )
        },
        WOULD_BLOCK
    );
    assert_eq!(length, 0);
    assert_eq!(count, 0);
    assert_eq!(meta_destroy_v1(id), OK);
}

#[test]
fn batched_packet_io_handles_buffer_too_small_and_partial_capacity() {
    let context = Box::new(Callbacks {
        id: AtomicU64::new(0),
        notifications: AtomicUsize::new(0),
    });
    let hooks = MetaPlatformV1 {
        size: std::mem::size_of::<MetaPlatformV1>() as u32,
        version: 1,
        context: (&*context as *const Callbacks).cast_mut().cast(),
        protect_socket: None,
        packet_ready: Some(ready),
    };
    let id = create(b"tun: {enable: true}\n", &hooks);
    context.id.store(id, Ordering::Relaxed);
    assert_eq!(meta_start_v1(id), OK);

    let p1 = make_icmp_echo(1, b"one");
    let p2 = make_icmp_echo(2, b"two");
    let framed = frame_packets(&[p1.clone(), p2.clone()]);
    let mut written = 0usize;
    assert_eq!(
        unsafe { meta_write_packets_v1(id, framed.as_ptr(), framed.len(), &mut written) },
        OK
    );
    assert_eq!(written, 2);

    let until = Instant::now() + Duration::from_secs(3);
    while context.notifications.load(Ordering::Relaxed) == 0 {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(1));
    }
    // Wait briefly for both replies to land in output queue.
    std::thread::sleep(Duration::from_millis(20));

    // Too small for even 1 packet -> BUFFER_TOO_SMALL, leaves packet queued.
    let mut length = 0usize;
    let mut count = 0usize;
    let mut tiny = [0u8; 4];
    assert_eq!(
        unsafe {
            meta_read_packets_v1(
                id,
                tiny.as_mut_ptr(),
                tiny.len(),
                &mut length,
                &mut count,
                64,
            )
        },
        BUFFER_TOO_SMALL
    );
    assert_eq!(length, 2 + p1.len());
    assert_eq!(count, 0);

    // Exact capacity for 1 packet -> reads 1, leaves second queued.
    let mut one_buf = vec![0u8; length];
    assert_eq!(
        unsafe {
            meta_read_packets_v1(
                id,
                one_buf.as_mut_ptr(),
                one_buf.len(),
                &mut length,
                &mut count,
                64,
            )
        },
        OK
    );
    assert_eq!(count, 1);
    assert_eq!(length, one_buf.len());

    // Read remaining packet.
    let mut rem_buf = vec![0u8; 2048];
    assert_eq!(
        unsafe {
            meta_read_packets_v1(
                id,
                rem_buf.as_mut_ptr(),
                rem_buf.len(),
                &mut length,
                &mut count,
                64,
            )
        },
        OK
    );
    assert_eq!(count, 1);
    assert_eq!(meta_destroy_v1(id), OK);
}

#[test]
fn batched_packet_io_rejects_malformed_framing_and_reports_would_block() {
    let hooks = MetaPlatformV1 {
        size: std::mem::size_of::<MetaPlatformV1>() as u32,
        version: 1,
        context: std::ptr::null_mut(),
        protect_socket: None,
        packet_ready: None,
    };
    let id = create(b"tun: {enable: true}\n", &hooks);
    // Do NOT start core so input queue (capacity 256) fills deterministically.
    let mut written = 0usize;
    // Truncated header (1 byte)
    assert_eq!(
        unsafe { meta_write_packets_v1(id, [0x10].as_ptr(), 1, &mut written) },
        ERROR
    );
    // Truncated payload
    assert_eq!(
        unsafe { meta_write_packets_v1(id, [20, 0, 0x45].as_ptr(), 3, &mut written) },
        ERROR
    );
    // Invalid IP version (version 3)
    let mut bad_ip = [0u8; 22];
    bad_ip[0..2].copy_from_slice(&20u16.to_le_bytes());
    bad_ip[2] = 0x30;
    assert_eq!(
        unsafe { meta_write_packets_v1(id, bad_ip.as_ptr(), bad_ip.len(), &mut written) },
        ERROR
    );

    // Fill 250 packets, then 20 packets -> partial WOULD_BLOCK with written == 6.
    let pkt = make_icmp_echo(1, b"fill");
    let batch250 = frame_packets(&vec![pkt.clone(); 250]);
    assert_eq!(
        unsafe { meta_write_packets_v1(id, batch250.as_ptr(), batch250.len(), &mut written) },
        OK
    );
    assert_eq!(written, 250);

    let batch20 = frame_packets(&vec![pkt; 20]);
    assert_eq!(
        unsafe { meta_write_packets_v1(id, batch20.as_ptr(), batch20.len(), &mut written) },
        WOULD_BLOCK
    );
    assert_eq!(written, 6);

    assert_eq!(meta_destroy_v1(id), OK);
}
