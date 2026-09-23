# route_manager 0.2.9 Linux route dump patch

Source: crates.io `route_manager` 0.2.9, upstream commit
`ad0b4389dc4113587743b6a1c45912c6d8caf4ee`.
Published crate SHA256:
`bb012980f7bfadc330cc5b99e2a93bda641717554338b6ddb0e86de4188af65b`.
The original Apache-2.0 license and source attribution are retained in `route_manager/`.
This is a generic OS routing foundation, not a proxy protocol implementation.

The upstream synchronous and asynchronous Linux list loops interpret the dump
completion boolean backwards: they stop after the first data datagram instead
of waiting for NLMSG_DONE. IPv6 entries in later datagrams are missing, causing
desktop refresh to attempt duplicate route creation and preventing full recovery.
Both loops now stop on completion and receive complete datagrams through
netlink-sys `recv_from_full`, avoiding the previous 4096-byte truncation.

Only `src/linux/mod.rs` and `src/linux/async_route.rs` change. Other platform
implementations are unchanged. The isolated root Linux desktop acceptance script
exercises actual automatic IPv4/IPv6 route creation, repeated refresh, network
replacement and recovery. It failed with duplicate `::/1` creation before this
patch. See `docs/continuation.md` for final verification results and limitations.
