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
