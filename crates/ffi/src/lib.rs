//! Versioned caller-buffer C ABI. See include/clyntis.h for the host contract.
mod host;
mod logs;
use anyhow::{Context, Result, ensure};
use host::{Handle, HostHooks, MetaHooksV1};
use std::{
    cell::RefCell,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::mpsc;
#[cfg(test)]
mod tests;
pub use host::MetaHooksV1 as MetaPlatformV1;

pub const OK: i32 = 0;
pub const ERROR: i32 = 1;
pub const WOULD_BLOCK: i32 = 2;
pub const BUFFER_TOO_SMALL: i32 = 3;
const LIMIT: usize = 16 * 1024 * 1024;
thread_local! { static ERROR_TEXT: RefCell<String> = const { RefCell::new(String::new()) }; }
static HANDLES: OnceLock<Mutex<std::collections::HashMap<u64, Arc<Handle>>>> = OnceLock::new();
static NEXT: AtomicU64 = AtomicU64::new(1);
fn handles() -> &'static Mutex<std::collections::HashMap<u64, Arc<Handle>>> {
    HANDLES.get_or_init(Mutex::default)
}
fn handle(id: u64) -> Result<Arc<Handle>> {
    handles()
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .context("invalid or destroyed core handle")
}
fn boundary(operation: impl FnOnce() -> Result<i32>) -> i32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            ERROR_TEXT.with(|text| *text.borrow_mut() = format!("{error:#}"));
            ERROR
        }
        Err(_) => {
            ERROR_TEXT.with(|text| *text.borrow_mut() = "panic contained at C ABI boundary".into());
            ERROR
        }
    }
}
unsafe fn input<'a>(data: *const u8, len: usize) -> Result<&'a [u8]> {
    unsafe { input_with_limit(data, len, LIMIT) }
}
unsafe fn input_with_limit<'a>(data: *const u8, len: usize, limit: usize) -> Result<&'a [u8]> {
    ensure!(
        len <= limit && (len == 0 || !data.is_null()),
        "invalid input buffer"
    );
    if len == 0 {
        Ok(&[])
    } else {
        Ok(unsafe { std::slice::from_raw_parts(data, len) })
    }
}
unsafe fn output(
    bytes: &[u8],
    buffer: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> Result<i32> {
    ensure!(!length.is_null(), "output length is required");
    unsafe {
        *length = bytes.len();
    }
    if capacity < bytes.len() {
        return Ok(BUFFER_TOO_SMALL);
    }
    ensure!(
        bytes.is_empty() || !buffer.is_null(),
        "invalid output buffer"
    );
    if !bytes.is_empty() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len());
        }
    }
    Ok(OK)
}
#[unsafe(no_mangle)]
pub extern "C" fn meta_abi_version_v1() -> u32 {
    1
}

/// Decrypt and validate the existing AES-CFB/Base64 configuration format.
///
/// # Safety
/// Input buffers must be readable for their lengths. Output buffer and length
/// must be writable, nonoverlapping, and must not overlap either input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_decrypt_config_v1(
    data: *const u8,
    len: usize,
    password: *const u8,
    password_len: usize,
    buffer: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> i32 {
    boundary(|| {
        ensure!(!length.is_null(), "output length is required");
        unsafe { *length = 0 };
        ensure!(capacity == 0 || !buffer.is_null(), "invalid output buffer");
        let ciphertext = unsafe { input_with_limit(data, len, 24 * 1024 * 1024)? };
        let password = std::str::from_utf8(unsafe { input(password, password_len)? })?;
        // Remote text files may have a final newline or wrapped Base64 lines.
        let ciphertext: Vec<u8> = ciphertext
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        let plaintext = meta_config::crypto::decrypt(&ciphertext, password).map_err(|_| {
            anyhow::anyhow!("cannot decrypt configuration: check password and format")
        })?;
        ensure!(
            !plaintext.is_empty() && plaintext.len() <= LIMIT,
            "decrypted configuration is empty or exceeds 16 MiB"
        );
        // CFB has no authentication tag. Never expose unvalidated plaintext.
        meta_config::Config::parse(&plaintext).map_err(|_| {
            anyhow::anyhow!("cannot decrypt configuration: check password and format")
        })?;
        unsafe { output(&plaintext, buffer, capacity, length) }
    })
}

/// # Safety
/// Same pointer contract as `meta_decrypt_config_v1`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_encrypt_config_v1(
    data: *const u8,
    len: usize,
    password: *const u8,
    password_len: usize,
    buffer: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> i32 {
    boundary(|| {
        ensure!(!length.is_null(), "output length is required");
        unsafe { *length = 0 };
        ensure!(capacity == 0 || !buffer.is_null(), "invalid output buffer");
        let plaintext = unsafe { input_with_limit(data, len, LIMIT)? };
        let password = std::str::from_utf8(unsafe { input(password, password_len)? })?;
        ensure!(!password.is_empty(), "password is required");
        // Refuse to produce an export that could never be imported again.
        meta_config::Config::parse(plaintext)?;
        let encoded = meta_config::crypto::encrypt(plaintext, password)?;
        unsafe { output(encoded.as_bytes(), buffer, capacity, length) }
    })
}

/// # Safety
/// Inputs and the hooks size field must be readable and aligned. If the size is
/// supported, hooks must point to a complete valid MetaHooksV1. Callback context
/// must stay live until stop/destroy returns. The handle output is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_create_v1(
    data: *const u8,
    len: usize,
    hooks: *const MetaHooksV1,
    out: *mut u64,
) -> i32 {
    unsafe { create(data, len, hooks, out, None) }
}

/// Create a host-owned packet tunnel without opening desktop proxy listeners.
///
/// # Safety
/// The same requirements as meta_create_v1 apply. directory must contain a
/// readable UTF-8 absolute path to an existing host-owned resource directory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_create_packet_tunnel_v1(
    data: *const u8,
    len: usize,
    directory: *const u8,
    directory_len: usize,
    hooks: *const MetaHooksV1,
    out: *mut u64,
) -> i32 {
    // Parse the directory inside the boundary so invalid input remains a C error.
    unsafe { create(data, len, hooks, out, Some((directory, directory_len))) }
}

/// Check the syntax of one custom rule (UTF-8 `TYPE,VALUE,TARGET[,no-resolve]`).
/// MATCH is refused. Whether the target exists is checked when applying.
///
/// # Safety
/// `rule` must be readable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_custom_rule_validate_v1(rule: *const u8, len: usize) -> i32 {
    boundary(|| {
        meta_config::custom::validate(std::str::from_utf8(unsafe { input(rule, len)? })?)?;
        Ok(OK)
    })
}

/// Write the rule targets offered by `config` as a JSON array of strings:
/// DIRECT, REJECT, then proxy groups and proxies.
///
/// # Safety
/// Inputs must be readable; buffer and length output writable and nonoverlapping.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_custom_rule_targets_v1(
    config: *const u8,
    len: usize,
    buffer: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> i32 {
    boundary(|| {
        let yaml = std::str::from_utf8(unsafe { input(config, len)? })?;
        let targets = meta_config::custom::targets(yaml)?;
        unsafe { output(&serde_json::to_vec(&targets)?, buffer, capacity, length) }
    })
}

/// Prepend custom rules (`rules`: JSON array of strings) to `config`. Writes
/// JSON `{"yaml": "...", "skipped": [{"rule": "...", "reason": "..."}]}`;
/// rules the profile cannot use are skipped rather than failing it.
///
/// # Safety
/// Inputs must be readable; buffer and length output writable and nonoverlapping.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_custom_rules_apply_v1(
    config: *const u8,
    len: usize,
    rules: *const u8,
    rules_len: usize,
    buffer: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> i32 {
    boundary(|| {
        let yaml = std::str::from_utf8(unsafe { input(config, len)? })?;
        let rules: Vec<String> = serde_json::from_slice(unsafe { input(rules, rules_len)? })?;
        let applied = meta_config::custom::apply(yaml, &rules)?;
        let value = serde_json::json!({"yaml": applied.yaml, "skipped": applied.skipped});
        unsafe { output(&serde_json::to_vec(&value)?, buffer, capacity, length) }
    })
}

/// Apply app settings (`overrides`: JSON `{"logLevel","ipv6","sniffing"}`, each
/// optional) over `config`. Writes the resulting YAML; unset values keep the
/// profile's own.
///
/// # Safety
/// Inputs must be readable; buffer and length output writable and nonoverlapping.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_overrides_apply_v1(
    config: *const u8,
    len: usize,
    overrides: *const u8,
    overrides_len: usize,
    buffer: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> i32 {
    boundary(|| {
        let yaml = std::str::from_utf8(unsafe { input(config, len)? })?;
        let overrides: meta_config::overrides::Overrides =
            serde_json::from_slice(unsafe { input(overrides, overrides_len)? })?;
        let yaml = overrides.apply(yaml)?;
        unsafe { output(yaml.as_bytes(), buffer, capacity, length) }
    })
}

/// Move buffered core log lines into `buffer` as newline-separated JSON objects
/// (`time` in Unix seconds, `type` debug/info/warning/error, `payload`). Lines
/// are removed only when they fit; otherwise `length` reports the size needed.
///
/// # Safety
/// Buffer and length output must be writable and nonoverlapping.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_drain_logs_v1(
    buffer: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> i32 {
    boundary(|| {
        let mut status = OK;
        logs::drain(|bytes| {
            status = unsafe { output(bytes, buffer, capacity, length)? };
            Ok(status == OK)
        })?;
        Ok(status)
    })
}

/// Download missing or expired routing resources (GeoIP/GeoSite, rule providers)
/// referenced by `config` into `directory`, then validate them. Returns at once
/// when every referenced file is present and current. Blocks until done. Hosts
/// call this before starting a packet tunnel so the memory- and
/// time-constrained tunnel process starts from local files.
///
/// # Safety
/// `data` and `directory` must be readable for their lengths; `directory` is
/// a UTF-8 absolute path to an existing directory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_prefetch_resources_v1(
    data: *const u8,
    len: usize,
    directory: *const u8,
    directory_len: usize,
) -> i32 {
    boundary(|| {
        let mut config = meta_config::Config::parse(unsafe { input(data, len)? })?;
        let path = std::path::PathBuf::from(std::str::from_utf8(unsafe {
            input(directory, directory_len)?
        })?);
        ensure!(
            path.is_absolute() && path.is_dir(),
            "resource directory must exist and be absolute"
        );
        config.directory = path;
        config.tun.enable = false;
        let core = meta_core::Core::new(config, std::sync::Arc::new(meta_platform::DefaultHooks))?;
        // Current files were validated when they were downloaded, and the
        // tunnel parses them again anyway; parsing ~20 MB of geo data here
        // only delayed every connect.
        if core.resource_freshness()? == meta_core::Freshness::Current {
            return Ok(OK);
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(core.prepare_resources(true))?;
        Ok(OK)
    })
}

/// Report whether the routing files `config` references exist in `directory`
/// and are within their update intervals: `state` receives 0 (current),
/// 1 (present but expired: usable, refresh when convenient) or 2 (missing:
/// prefetch before starting). Cheap; parses no geo data.
///
/// # Safety
/// `data` and `directory` must be readable for their lengths; `state` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_resources_state_v1(
    data: *const u8,
    len: usize,
    directory: *const u8,
    directory_len: usize,
    state: *mut u32,
) -> i32 {
    boundary(|| {
        ensure!(!state.is_null(), "state output is required");
        let mut config = meta_config::Config::parse(unsafe { input(data, len)? })?;
        config.directory = std::path::PathBuf::from(std::str::from_utf8(unsafe {
            input(directory, directory_len)?
        })?);
        config.tun.enable = false;
        let core = meta_core::Core::new(config, std::sync::Arc::new(meta_platform::DefaultHooks))?;
        let value = match core.resource_freshness()? {
            meta_core::Freshness::Current => 0,
            meta_core::Freshness::Expired => 1,
            meta_core::Freshness::Missing => 2,
        };
        unsafe { state.write(value) };
        Ok(OK)
    })
}

unsafe fn create(
    data: *const u8,
    len: usize,
    hooks: *const MetaHooksV1,
    out: *mut u64,
    directory: Option<(*const u8, usize)>,
) -> i32 {
    boundary(|| {
        ensure!(!out.is_null(), "handle output is required");
        unsafe {
            *out = 0;
        }
        host::check_lifecycle()?;
        let mut config = meta_config::Config::parse(unsafe { input(data, len)? })?;
        logs::init(&config.log.log_level);
        if let Some((path, path_len)) = directory {
            let path =
                std::path::PathBuf::from(std::str::from_utf8(unsafe { input(path, path_len)? })?);
            ensure!(
                path.is_absolute() && path.is_dir(),
                "host directory must exist and be absolute"
            );
            config.directory = path;
            config.internal_host_packet_io = true;
            config.port = 0;
            config.socks_port = 0;
            config.mixed_port = 0;
            config.allow_lan = false;
            config.external_controller = None;
            config.external_ui.clear();
            config.log.log_path.clear();
            // Packet DNS interception uses the resolver without a local listener.
            config.dns.enable = false;
            config.tun.enable = true;
            config.tun.auto_route = false;
            config.tun.auto_dns = false;
            config.tun.auto_detect_interface = false;
            config.tun.interface = None;
            config.tun.mtu = 1280;
            config.tun.dns_hijack = vec!["any:53".into()];
        }
        let hooks = if hooks.is_null() {
            HostHooks::default()
        } else {
            let size = unsafe { std::ptr::addr_of!((*hooks).size).read() };
            ensure!(
                size as usize == std::mem::size_of::<MetaHooksV1>(),
                "unsupported host hooks size"
            );
            HostHooks::new(unsafe { *hooks })?
        };
        let mut registry = handles().lock().unwrap();
        ensure!(registry.len() < 16, "core handle capacity reached");
        let id = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| anyhow::anyhow!("core handle identifiers exhausted"))?;
        registry.insert(id, Arc::new(Handle::new(id, config, hooks)?));
        unsafe {
            *out = id;
        }
        Ok(OK)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn meta_start_v1(id: u64) -> i32 {
    boundary(|| {
        handle(id)?.start()?;
        Ok(OK)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn meta_stop_v1(id: u64) -> i32 {
    boundary(|| {
        handle(id)?.shutdown()?;
        Ok(OK)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn meta_destroy_v1(id: u64) -> i32 {
    boundary(|| {
        handle(id)?.shutdown()?;
        handles().lock().unwrap().remove(&id);
        Ok(OK)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn meta_close_connections_v1(id: u64) -> i32 {
    boundary(|| {
        for connection in handle(id)?.core.connections() {
            connection.cancel.cancel();
        }
        Ok(OK)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn meta_network_changed_v1(id: u64) -> i32 {
    boundary(|| {
        handle(id)?.network_changed()?;
        Ok(OK)
    })
}
/// # Safety
/// fd must be a live configured Android TUN descriptor. This function duplicates
/// it before return; the caller keeps ownership of the original descriptor.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_set_tun_fd_v1(id: u64, fd: i32) -> i32 {
    boundary(|| {
        ensure!(fd >= 0, "invalid TUN descriptor");
        let owned = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?;
        handle(id)?.set_fd(owned)?;
        Ok(OK)
    })
}

/// # Safety
/// Buffer and length output must be writable for the specified capacity/size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_error_v1(
    buffer: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> i32 {
    boundary(|| {
        ERROR_TEXT
            .with(|text| unsafe { output(text.borrow().as_bytes(), buffer, capacity, length) })
    })
}
/// # Safety
/// Buffer and length output must be writable and nonoverlapping.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_snapshot_v1(
    id: u64,
    buffer: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> i32 {
    boundary(|| {
        let handle = handle(id)?;
        let value = serde_json::json!({"config":handle.core.configuration(), "selections":handle.core.selections(), "connections":handle.core.connections(), "upload":handle.core.upload.load(Ordering::Relaxed), "download":handle.core.download.load(Ordering::Relaxed), "stopped":handle.core.stop.is_cancelled()});
        unsafe { output(&serde_json::to_vec(&value)?, buffer, capacity, length) }
    })
}
/// # Safety
/// Data must be readable for len bytes and contain UTF-8 JSON.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_update_v1(id: u64, data: *const u8, len: usize) -> i32 {
    boundary(|| {
        let value: serde_json::Value = serde_json::from_slice(unsafe { input(data, len)? })?;
        let object = value.as_object().context("update must be an object")?;
        ensure!(
            object.keys().all(|k| k == "mode" || k == "rules"),
            "only mode and rules can update online"
        );
        let mode = object
            .get("mode")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()?;
        let rules = object
            .get("rules")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()?;
        handle(id)?.core.update_policy(mode, rules)?;
        Ok(OK)
    })
}
/// # Safety
/// Both name buffers must be readable UTF-8 strings of the specified lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_select_v1(
    id: u64,
    group: *const u8,
    group_len: usize,
    node: *const u8,
    node_len: usize,
) -> i32 {
    boundary(|| {
        handle(id)?.core.select(
            std::str::from_utf8(unsafe { input(group, group_len)? })?,
            std::str::from_utf8(unsafe { input(node, node_len)? })?,
        )?;
        Ok(OK)
    })
}
/// # Safety
/// Data must be readable for len bytes. The packet is copied before return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_write_packet_v1(id: u64, data: *const u8, len: usize) -> i32 {
    boundary(|| {
        ensure!((20..=65535).contains(&len), "invalid IP packet length");
        let packet = unsafe { input(data, len)? };
        ensure!(matches!(packet[0] >> 4, 4 | 6), "invalid IP version");
        let handle = handle(id)?;
        ensure!(!handle.core.stop.is_cancelled(), "core is stopped");
        handle.check_packet_queue()?;
        let input = handle.packet_input.as_ref().context("TUN is disabled")?;
        match input.try_send(packet.to_vec()) {
            Ok(()) => Ok(OK),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(WOULD_BLOCK),
            Err(_) => anyhow::bail!("packet channel closed"),
        }
    })
}
/// # Safety
/// Buffer/length must be writable and nonoverlapping. A too-small buffer leaves
/// the packet queued. No Rust allocation is transferred to the host.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn meta_read_packet_v1(
    id: u64,
    buffer: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> i32 {
    boundary(|| {
        ensure!(!length.is_null(), "output length is required");
        unsafe {
            *length = 0;
        }
        let handle = handle(id)?;
        handle.check_packet_queue()?;
        let mut queue = handle.packet_output.lock().unwrap();
        if queue.pending.is_none() {
            match queue.receiver.try_recv() {
                Ok(packet) => queue.pending = Some(packet),
                Err(mpsc::error::TryRecvError::Empty) => return Ok(WOULD_BLOCK),
                Err(_) => anyhow::bail!("packet channel closed"),
            }
        }
        let status = unsafe { output(queue.pending.as_ref().unwrap(), buffer, capacity, length)? };
        if status == OK {
            queue.pending.take();
        }
        Ok(status)
    })
}
