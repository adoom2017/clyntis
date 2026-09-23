//! Versioned caller-buffer C ABI. See include/clyntis.h for the host contract.
mod host;
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
    ensure!(
        len <= LIMIT && (len == 0 || !data.is_null()),
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
    boundary(|| {
        ensure!(!out.is_null(), "handle output is required");
        unsafe {
            *out = 0;
        }
        host::check_lifecycle()?;
        let config = meta_config::Config::parse(unsafe { input(data, len)? })?;
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
        let value = serde_json::json!({"config":handle.core.configuration(), "connections":handle.core.connections(), "upload":handle.core.upload.load(Ordering::Relaxed), "download":handle.core.download.load(Ordering::Relaxed), "stopped":handle.core.stop.is_cancelled()});
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
