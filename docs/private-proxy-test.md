# Private configuration testing on Windows

This Windows-only test uses PowerShell 7. The script captures and discards raw CLI/curl diagnostics,
prints only fixed messages and numeric request results, and never starts a
service or changes the configuration, TUN, routes, or system proxy settings.
It does not write configuration copies or diagnostic logs. The local core still
reads the private file for validation; this is not isolation from a local agent
with filesystem access. Run the commands yourself for private configurations.

## Validate first

```powershell
pwsh -NoProfile -File scripts/test-local-proxy.ps1 -ConfigPath 'C:\private\config.yaml'
```

Exit code 0 means validation succeeded; without port arguments no network test
has run. Exit code 1 means validation/request failure and 2 means setup failure.
On validation failure the script stops. Inspect raw errors locally if necessary;
do not share them without reviewing them for secrets.

VLESS UUID accepts a textual UUID or a non-empty custom string. Custom strings
are converted using the Xray UUIDv5 mapping standard (nil UUID namespace), so
the same string and its mapped UUID send the same 16-byte protocol identity.

## Test a running service

When another Clash/mihomo instance is running, use a separate loopback mixed
listener. `--proxy-test-port` disables TUN, DNS listening and the controller;
the configured DNS upstreams and routing rules remain active. `--no-tun` alone
only disables TUN and can still conflict with existing DNS/controller ports.
Start the core yourself in another terminal:

```powershell
./target/debug/clyntis.exe -f 'C:\private\config.yaml' --proxy-test-port 17890
```

Then test its actual listener ports. For a mixed listener, pass the same port
for both options:

```powershell
pwsh -NoProfile -File scripts/test-local-proxy.ps1 -ConfigPath 'C:\private\config.yaml' -HttpProxyPort 17890 -SocksProxyPort 17890
```

The default destinations are http://example.com/ and https://example.com/.
Override them with `-HttpUrl` and `-HttpsUrl` as needed. Requests use explicit
loopback proxies, disable curl's automatic config loading and bypass list, and
use proxy-side DNS for SOCKS5. No response bodies or raw curl errors are printed.
HTTP 2xx/3xx counts as success; redirects are not followed. HTTPS additionally
requires successful certificate verification. Authenticated local listeners are
not supported by this script. Stop your service with Ctrl+C when finished.

The script cannot establish that an existing listener loaded the supplied file
or selected a particular remote node. For real node acceptance, select the
intended node and ensure test destination rules use it with no DIRECT fallback;
verify the route locally. The script neither queries nor prints controller data.

## Test an isolated process

To validate an isolated VLESS process, its rule resources and both local proxy
protocols in one run:

```powershell
pwsh -NoProfile -File scripts/test-local-proxy.ps1 -ConfigPath 'C:\private\config.yaml' -StartProxy -TestResources -HttpUrl 'http://www.google.com/' -HttpsUrl 'https://www.google.com/'
```

The script chooses a free loopback mixed port, forces no-TUN/VLESS-only mode,
tests HTTP and SOCKS5, then stops only the process it created.
