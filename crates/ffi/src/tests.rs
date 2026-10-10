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
        let encoded = meta_config::crypto::encrypt(plaintext, password).unwrap();
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
    let valid = meta_config::crypto::encrypt(b"mode: direct\n", "correct").unwrap();
    let invalid =
        meta_config::crypto::encrypt(b"unknown-field: private-secret\n", "correct").unwrap();
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

#[test]
fn packet_tunnel_host_keeps_credentials_and_disables_desktop_listeners() {
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
    let merged = meta_config::Config::parse(applied["yaml"].as_str().unwrap().as_bytes()).unwrap();
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
    let merged = meta_config::Config::parse(&buffer[..length]).unwrap();
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
fn resource_state_reports_missing_files_without_parsing_them() {
    let dir = std::env::temp_dir().join(format!("meta-ffi-state-{}", uuid_for_test()));
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
    assert_eq!(test(r#"{"target":"a.example","port":0}"#).0, ERROR);
    assert_eq!(meta_destroy_v1(id), OK);
    assert_eq!(test(r#"{"target":"a.example"}"#).0, ERROR);
}
