# Foundation Dependencies

Production protocol implementations are repository-owned. Cargo dependencies
provide runtimes, serialization, standard cryptography, BoringSSL TLS, HTTP,
DNS wire types, TCP/IP (smoltcp) and operating-system interfaces. The one
exception is WireGuard for the Tailscale outbound: it uses Cloudflare's
`boringtun` crate (its `noise` module only, without the device/TUN features).
Tailscale's own protocols — the ts2021 control transport, DERP relaying, disco
path discovery and STUN — are implemented in `crates/tailscale`, and NaCl boxes
use the `crypto_box` crate. No external proxy kernel, Tailscale daemon or Go
`tsnet` is linked, loaded or launched by the product.

Local foundation patches:

- `boring-sys/`: see `BORINGSSL-PATCH.md` for ClientHello ordering and REALITY hooks.
- `route_manager/`: see `ROUTE-MANAGER-PATCH.md` for complete Linux route dumps.

Original upstream licenses are preserved in each directory. `Cargo.lock` pins
registry versions and checksums. `scripts/prepare-offline.ps1` creates the full
registry source snapshot, package/license inventory, per-file hashes and archive
SHA-256. The archive includes these maintained local patches. An external Xray
binary may be used as an optional test oracle and is excluded from production
source archives and release packages.

Release packaging uses `license-overrides/` when a published crate omits its
upstream license file. `license-overrides/boringtun/LICENSE.md` preserves the
unmodified BSD-3-Clause notice from Cloudflare's
[`boringtun` 0.7.1 release commit](https://github.com/cloudflare/boringtun/blob/051c9d47dc9c5cb36e461b7d36dcd673820dc98b/LICENSE.md)
(`051c9d47dc9c5cb36e461b7d36dcd673820dc98b`). The crates.io package declares
the license but does not include the repository-level file; both release
packaging scripts include this local copy in `third-party-licenses/` and record
its source in `dependencies.json`.

Windows native TUN uses the official Wintun runtime through the general tun-rs
device library. Obtain the signed `wintun.dll` and its license from wintun.net;
the repository does not redistribute an unverified driver binary.
