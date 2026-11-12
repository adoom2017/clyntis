# Core Runtime

The host owns the Tokio runtime. `Core::new` validates configuration; `start`
returns a `Running` owner. `Running::shutdown` cancels work, joins listeners and
releases cached QUIC clients. Dropping `Running` also cancels its tasks. A stopped
core cannot restart; create a new core with the newly validated full configuration.

TCP relays and UDP sessions are registered with live upload/download counters.
The controller can cancel one or all connections. Tracker destruction removes
entries on normal completion, errors and task abortion. There are at most 4,096
tracked connections and 4,096 accepted proxy connections. TCP relays have a
300-second idle limit; UDP sends and receives have 20/120-second limits. Outbound
routing, DNS and dialing share a 20-second establishment deadline and observe
core cancellation. HY2 caches serialize establishment per proxy only.

`GET /configs` returns current online mode/rules and omits passwords, UUIDs,
controller secrets and local proxy authentication. `PATCH /configs` accepts only
mode/rules and applies them together after validation. Other fields require host
restart. WebSocket traffic/log streams support ping/pong, core cancellation and
a five-second send deadline. The API is a documented subset, not a full Clash
dashboard compatibility contract.

DNS entry queries and outbound resolution share a bounded cache. Keys preserve
query class, EDNS, recursion and DNSSEC flags; responses retain NXDOMAIN and SOA.
Negative entries require an SOA and expire using its minimum TTL. Cache hits age
record TTLs. The cache holds at most 4,096 entries and 8 MiB of encoded messages.
DoH uses the generic Hyper HTTP implementation, certificate validation and a
65,535-byte response limit. Fake-IP mappings are stable for the core lifetime,
limited to 32,768 names/address families. An exhausted range returns SERVFAIL;
it never silently maps an active address to a new name.

Windows verification on 2026-09-12: eight core tests pass, covering local proxy
entrances, VLESS UDP/XUDP selection and reconnect, live TCP/UDP accounting,
controller cancellation, aborted-task cleanup, stalled DNS cancellation,
atomic policy updates, credential redaction, positive/negative DNS caching,
flag separation, TTL expiration and tiny/high-address fake-IP ranges. Workspace
Clippy passes with warnings denied. Desktop TUN, mobile host integration and
cross-platform runtime acceptance are tracked separately in `rust-progress.md`.
