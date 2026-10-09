//! The process's physical footprint: the figure jetsam compares against the
//! ~50 MiB iOS Network Extension limit. Elsewhere nothing is measured.

/// Footprint and heap figures, in bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Usage {
    pub footprint: u64,
    /// malloc bytes handed out to callers.
    pub heap_used: u64,
    /// malloc bytes reserved from the system, including free blocks.
    pub heap_reserved: u64,
}

#[cfg(target_vendor = "apple")]
mod apple {
    use super::Usage;

    /// `task_vm_info` up to `phys_footprint` (TASK_VM_INFO_REV1_COUNT); the
    /// kernel fills only as many fields as the count allows.
    #[repr(C, packed(4))]
    #[derive(Default)]
    struct TaskVmInfo {
        virtual_size: u64,
        region_count: i32,
        page_size: i32,
        sizes: [u64; 16],
        phys_footprint: u64,
    }
    const TASK_VM_INFO: libc::task_flavor_t = 22;

    unsafe extern "C" {
        fn malloc_zone_pressure_relief(
            zone: *mut libc::malloc_zone_t,
            goal: libc::size_t,
        ) -> libc::size_t;
    }

    pub fn usage() -> Option<Usage> {
        let mut info = TaskVmInfo::default();
        let mut count = (size_of::<TaskVmInfo>() / size_of::<libc::natural_t>())
            as libc::mach_msg_type_number_t;
        // SAFETY: `info` is a writable buffer of `count` natural_t words.
        let result = unsafe {
            libc::task_info(
                #[allow(deprecated)]
                libc::mach_task_self_,
                TASK_VM_INFO,
                (&raw mut info).cast(),
                &mut count,
            )
        };
        if result != libc::KERN_SUCCESS {
            return None;
        }
        let mut heap = libc::malloc_statistics_t {
            blocks_in_use: 0,
            size_in_use: 0,
            max_size_in_use: 0,
            size_allocated: 0,
        };
        // SAFETY: a null zone asks for the totals of every zone.
        unsafe { libc::malloc_zone_statistics(std::ptr::null_mut(), &mut heap) };
        Some(Usage {
            footprint: info.phys_footprint,
            heap_used: heap.size_in_use as u64,
            heap_reserved: heap.size_allocated as u64,
        })
    }

    pub fn relieve() -> u64 {
        // SAFETY: a null zone with goal 0 returns as much free memory as possible.
        unsafe { malloc_zone_pressure_relief(std::ptr::null_mut(), 0) as u64 }
    }
}

#[cfg(target_vendor = "apple")]
pub use apple::{relieve, usage};

#[cfg(not(target_vendor = "apple"))]
pub fn usage() -> Option<Usage> {
    None
}
/// Returns free heap pages to the system; the bytes released.
#[cfg(not(target_vendor = "apple"))]
pub fn relieve() -> u64 {
    0
}

pub const MIB: u64 = 1024 * 1024;

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(target_vendor = "apple")]
    fn measures_this_process() {
        let usage = super::usage().unwrap();
        assert!(usage.footprint > 0 && usage.heap_reserved >= usage.heap_used);
        let _ = super::relieve();
    }
}
