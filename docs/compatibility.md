# Compatibility Subset

The Go product previously on this branch is retained at `Alpha`, baseline
`3fce2b4fe0eaefd2016f1b60312e1bb991b5c1e3`. Rust regression vectors generated with
Go's standard AES/CFB implementation cover empty, 16/17/24/25/32/40-byte and UTF-8
passwords with the legacy IV, ASCII-zero padding and Base64 encoding; this legacy
format is still read, while new files use the authenticated v2 format
(`crates/config/tests/v2_vectors.rs`). The test
fixtures use synthetic configuration only. No Go compiler is needed by Rust tests.

| Area | Supported |
| --- | --- |
| Nodes | VLESS TCP, WebSocket and gRPC; TLS, REALITY, Vision on TCP, UDP/XUDP; Hysteria2; Tailscale; Trojan parse-only |
| Entrances | HTTP, CONNECT, SOCKS5, mixed, explicitly enabled TUN |
| Rules | DOMAIN/DOMAIN-SUFFIX/DOMAIN-KEYWORD/DOMAIN-REGEX, IP-CIDR/IP-CIDR6, DST-PORT, NETWORK, GEOIP, GEOSITE, RULE-SET, AND/OR/NOT, MATCH, NETWORK-NAME (an addition: the device is on a `networks` entry); first match |
| Groups | select, url-test; duplicate/cycle/reference validation |
| DNS | UDP/TCP, TLS DoT, HTTPS DoH, cache, fake-IP, bootstrap using IP resolvers |
| CLI | -f, -d, -t, -v, -p, --action encrypt/decrypt, --legacy-encryption, --recover-tun |
| Logs | Levels, file rotation/compression and controller log events |
| Hosts | Core lifecycle, PlatformHooks, PacketIo, C ABI v1, Android protect and TUN fd |

Unknown fields and unsupported enum values return a path-aware migration error.
Not included: servers, HY1, XHTTP, subscription providers, VMess,
Shadowsocks, Trojan runtime, TUIC and process rules.

This table is a summary; [CONFIGURATION.md](../CONFIGURATION.md) is the
authoritative reference for options and limits.
Examples from the old Go product are not silently accepted as full compatibility.

| Controller | Operations |
| --- | --- |
| /version | GET |
| /configs | GET, PATCH mode/rules |
| /proxies | GET |
| /network | GET: reported network, matching `networks`, applied override |
| /proxies/{name} | GET, PUT selection |
| /proxies/{name}/delay | GET with url and bounded timeout |
| /connections | GET, DELETE all |
| /connections/{id} | DELETE |
| /traffic, /logs | WebSocket GET |

Bearer secret is checked on all routes. Config responses omit node credentials,
controller secret and listener authentication. This API does not promise full
Clash dashboard compatibility. Full config changes restart a newly validated
core; invalid online mode/rule updates apply nothing.

Platform acceptance, including the current Windows/macOS/iOS gaps, is recorded
in `platform-runtime.md`; Linux native IPv4/IPv6 fragmented UDP has been verified.
