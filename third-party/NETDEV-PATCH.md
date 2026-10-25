# netdev 0.46.2 macOS SystemConfiguration patch

Source: crates.io `netdev` 0.46.2, upstream commit
`33978113ed1658094c5584328aaa757ff1c5c3b9`.
Published crate SHA256:
`4db4135b187ddae3b6813c4f9d9ac9d5181859fa6a08b4e006c63a130974ed62`.
The original MIT license and source attribution are retained in `netdev/`.
This is a generic OS interface foundation, not a proxy protocol implementation.

On macOS, `get_interfaces` reads interface names and DHCP flags from the
SystemConfiguration plists and, when that read fails, falls back to
`SCNetworkInterfaceCopyAll` plus `SCNetworkInterfaceGetLocalizedDisplayName`.
A read fails when the process has no descriptors left; the localization call
then cannot open ICU data either and dereferences a NULL `CFNumberFormatter`,
killing the desktop runner with SIGSEGV
(`EXC_BAD_ACCESS KERN_INVALID_ADDRESS at 0x8` in
`CFNumberFormatterCreateNumberFromString`).

The fallback is removed: a failed read leaves the friendly name and DHCP
flags unset for that call only. A `tun.interface` given as a service name
such as `Wi-Fi` then matches nothing until the next refresh reads the plists
again; BSD names (`en0`) and indexes are unaffected. Only
`src/os/macos/interface.rs` and `src/os/macos/sc.rs` change; the GitHub
workflow, `.gitignore`, `.gitattributes` and `Cargo.lock` of the published
crate are omitted. Other platforms are unchanged.
