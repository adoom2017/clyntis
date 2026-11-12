# VLESS Implementation and Verification

The Rust implementation owns VLESS, REALITY, Vision and XUDP protocol logic.
Production uses general-purpose TLS and cryptography crates and never starts an
external proxy core. This is an implementation milestone, not full plan acceptance.

## Current Behavior

| Configuration | Transport behavior |
| --- | --- |
| VLESS without `tls` | VLESS v0 over TCP |
| `tls: true` | TLS with certificate and server-name verification |
| `network: ws` | Binary WebSocket frames, early data and V2Ray HTTP Upgrade options |
| `network: grpc` | HTTP/2 Gun service framing, heartbeat and connection pooling |
| `skip-cert-verify: true` | Skip certificate trust/name checking; handshake signatures remain verified |
| `reality-opts` | X25519/HKDF/AES-GCM session authentication and HMAC-authenticated Ed25519 certificate |
| `flow: xtls-rprx-vision` | Requires outer TLS 1.3; padding and independent read/write direct switches |
| UDP without XUDP or Vision | VLESS command 2 with length-prefixed packets |
| `xudp: true` or `packet-encoding: xudp` | VLESS command 3 with XUDP session framing |
| Vision UDP | Automatically uses XUDP, since Vision does not support command 2 |

`client-fingerprint` accepts `chrome`, `firefox`, `safari`, `ios`, `android`,
`edge`, `360`, `qq`, `random` and `randomized`; omission selects Chrome. The
implementation uses BoringSSL profiles for cipher/group/signature/key-share,
GREASE, ALPN, ECH GREASE, ALPS and extension ordering. The former `rustls` value
is rejected with a configuration error.

Ordinary TLS connections cache at most 256 server/profile/ALPN/verification-bound
BoringSSL sessions and offer one cached session on the next matching connection.
REALITY contexts never cache or resume sessions.

XUDP logical sessions share a VLESS command-3 physical connection per selected
proxy. Each flow has an independent 16-bit mux session ID, bounded receive queue
and target, while SOCKS/TUN flows derive a stable 8-byte Global ID from their
inbound source. A broken or partially written physical stream invalidates every
attached flow so the next inbound packet can establish a clean connection.
Frames include the target; responses may include an explicit source address.
These are optimizations beyond the single-session transport implemented here.

## Wire Details

VLESS v0 requests contain version, 16-byte UUID, one-byte addon length, protobuf
flow addon, and command. Commands 1 and 2 then carry a big-endian destination port
and tagged address. Command 3 omits that outer destination. Address tags are 1
(IPv4), 2 (one-byte-length domain), and 3 (IPv6). Responses consume version and
addons lazily so servers waiting for client application data do not deadlock.

XUDP frames contain a two-byte metadata length, two-byte session ID, status and
options. New (1) and Keep (2) data frames carry network 2, the VLESS address, a
two-byte payload length and the payload. This implementation uses session ID 0.
Keep responses without an address inherit the original destination. End (3),
error options, wrong IDs and invalid metadata terminate the receive operation;
Keepalive (4) is handled without recursion. At most 256 control frames are consumed
before requiring data. Metadata is bounded to 512 bytes and UDP payloads to 65,507.
Interrupted packet I/O invalidates that direction so a later call cannot mistake
a partial frame for a new packet.

Vision begins each direction with the UUID, then uses five-byte padding headers:
command, content length, padding length. Commands are Continue (0), End (1), and
Direct (2). TLS 1.3 detection handles byte-level fragmentation and ServerHello
messages split across TLS records. Reads remain active under write backpressure.
The record adapter drains plaintext and completes encrypted writes before direct
switches. Its BoringSSL BIO exposes at most one TLS record per poll so Direct mode
cannot lose raw inner-TLS bytes to TLS read-ahead.

REALITY configs are deliberately single-use: construct one per connection.
Authentication and certificate verification share a key bound to that exact
ClientHello. Resumption, HelloRetryRequest, ECH and TLS 1.2 are rejected on this
path. This prevents key-state sharing across concurrent handshakes.

## Local Checks

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
cargo run -p clyntis --locked --offline -- -f examples/vless.yaml -t
cargo run -p clyntis --locked --offline -- -f examples/vless.yaml
```

The example uses documentation-only credentials and addresses. Replace them
before connecting. Add the following fields to a node for REALITY/Vision:

```yaml
flow: xtls-rprx-vision
reality-opts:
  public-key: SERVER_X25519_PUBLIC_KEY_BASE64URL
  short-id: SERVER_SHORT_ID_HEX
```

Offline commands above use the existing local Cargo cache. They do not establish
offline source availability by themselves. A separately archived source snapshot
has now passed empty-cache builds on Windows and Linux; see `offline-build.md`.
This does not establish completion of the cross-platform release plan.

Recorded on Windows x64, Rust 1.93.1, 2026-09-12:

- Formatting check: passed.
- Clippy, all workspace targets/features with warnings denied: passed.
- Offline locked workspace tests: 36 passed, including both external-oracle tests
  with `XRAY_BIN` set and `-- --include-ignored`.
- Example configuration validation: passed.
- Windows x64 release build: passed with `--locked --offline`; the resulting
  `target/release/meta-rust.exe` passed version and example-configuration checks
  in that historical build; new builds produce `target/release/clyntis.exe`.
- Large-transfer regression: 128 KiB echo over plain TCP and TLS, with a 128-byte
  duplex buffer to expose backpressure and partial TLS-record consumption.
- TLS 1.2: ordinary VLESS accepted; Vision rejected before sending its UUID.
- REALITY: local transcript/certificate authentication and official server
  interoperability passed.
- SOCKS UDP: ordinary UDP and XUDP reconnect three times after the outbound peer
  closes, while the same SOCKS control connection remains open.

## External Interoperability

On Windows x64, the script downloads the official **Xray v25.9.11** release into
the ignored `target/oracles/` directory and verifies both archive and executable
SHA-256 values before running the two suites:

```powershell
./scripts/test-vless.ps1
```

- Release: https://github.com/XTLS/Xray-core/releases/tag/v25.9.11
- Archive: `Xray-windows-64.zip`
- Archive SHA-256: `d8db96eb39d7bc8cae484b2e59b651ff3c04f21e26d66e310f6a44e256ed1cc4`
- Executable SHA-256: `c478ce1f56ff0b09ad804868e16bf4bbc4020a7f1f09c2ae9df20f5068c8e23a`
- Banner: `Xray 25.9.11`, commit `3edfb0e`, Go 1.25.1, Windows amd64.

For an independently verified official binary on macOS or Linux, run:

```bash
bash scripts/test-vless.sh /absolute/path/to/official-xray
```

On Windows, set its absolute path and run (or use `./scripts/test-vless.ps1 -XrayPath ...`):

```powershell
$env:XRAY_BIN = 'C:\path\to\official-xray-v25.9.11\xray.exe'
cargo test -p meta-protocol --locked --offline --test xray_vless -- --ignored --nocapture
cargo test -p meta-protocol --locked --offline --test reality_interop -- --ignored --nocapture
```

The tests reject other version banners, create temporary loopback servers, and
terminate the oracle and local echo tasks after success, failure or timeout. They
cover plain/TLS TCP, IPv4/IPv6, UDP/XUDP, wrong UUIDs, untrusted TLS certificates,
TLS Vision TCP/XUDP without REALITY, REALITY with and without Vision, Vision with
inner TLS and transfers up to 128 KiB, REALITY UDP/XUDP, incorrect short IDs,
public keys and SNI. Fresh sessions work after rejected authentication and after
the actual Xray process is stopped and restarted. A version banner is not a
substitute for checking the downloaded binary's release checksum.

Both suites passed on Windows x64 on 2026-09-12. Ordinary VLESS command-2 UDP
replies were verified up to 8,190 bytes, XUDP up to 8,192 bytes. Xray v25.9.11
silently drops command-2 UDP replies when `payload length + 2 > 8192` (and empty
replies); this is its `MultiLengthPacketWriter` limit in
[`proxy/vless/encoding/addons.go`](https://github.com/XTLS/Xray-core/blob/v25.9.11/proxy/vless/encoding/addons.go).
The Rust codec's 65,507-byte local limit is not a claim that Xray supports packets
of that size end to end. Desktop TUN and other platform runtime acceptance remain
outside this VLESS milestone.

## Coverage-Guided Fuzzing

See `fuzz/README.md` for the isolated cargo-fuzz workspace and reproducible seed
and campaign commands. The default production build does not enable its entry
points or depend on libFuzzer. On 2026-09-12, each target ran with ASan for a
60-second budget in Ubuntu 22.04 WSL, pinned nightly `2026-08-01`, cargo-fuzz
0.13.2, maximum input 16,384 bytes and RSS limit 1,024 MiB:

| Target | Executed inputs | Reported duration | Peak RSS (MiB) |
| --- | ---: | ---: | ---: |
| VLESS address/response | 16,209,266 | 61 s | 517 |
| XUDP frames | 1,393,754 | 61 s | 550 |
| Vision frames/TLS recognition | 3,066,285 | 61 s | 549 |

All three completed without a protocol crash, timeout or sanitizer finding.
An initial harness assertion incorrectly required byte-identical address
re-encoding: a domain-tagged IP literal may canonically re-encode with an IP tag.
The harness now checks semantic target equality; that assertion was not a
production protocol defect. These bounded runs do not establish exhaustive
correctness or replace long-running fuzzing.

## Reference Provenance

Wire behavior was compared with the existing Go implementation in this repository
and the XUDP codec in `metacubex/sing-vmess` v0.2.5 from the local Go module cache.
No external proxy implementation was copied, linked or added to Cargo. The Rust
codec, parsing, cancellation rules, state machines and tests are maintained here.
Official Xray is used only as an optional test oracle. General TLS modifications
are documented in `third-party/BORINGSSL-PATCH.md`.
