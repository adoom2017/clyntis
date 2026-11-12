# Hysteria2 Status

Hysteria2 is implemented: TCP over QUIC streams, UDP over QUIC datagrams,
Salamander obfuscation, port hopping and Brutal/BBR congestion control, with
QUIC crypto on BoringSSL (`crates/protocol/src/hysteria2`,
`crates/protocol/src/quic.rs`).

Options, behaviour and the interop test against the official server are
documented in [CONFIGURATION.md](../CONFIGURATION.md#hysteria2-outbound).

> History: during the 2026-09 BoringSSL-only migration the earlier quinn/h3
> runtime was removed and Hysteria2 nodes returned `protocol unavailable in
> this build`; that state no longer applies.
