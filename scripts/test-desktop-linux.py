#!/usr/bin/env python3
"""Run only inside a fresh root network namespace; never touches host routes.

sudo unshare --net --fork python3 scripts/test-desktop-linux.py /path/to/clyntis
Requires Linux iproute2, util-linux and Python 3; no third-party Python modules.
"""
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time


def run(*args):
    return subprocess.check_output(args, text=True)


def wait_for(check, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.1)
    raise AssertionError("condition did not become true before deadline")


def other_vpn():
    import fcntl
    import struct
    fd = os.open("/dev/net/tun", os.O_RDWR)
    try:
        fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH", b"other-vpn", 0x1001))
        print("ready", flush=True)
        signal.pause()
    finally:
        os.close(fd)


def peer():
    def tcp(v6):
        listener = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET)
        listener.bind(("2001:db8:203::1" if v6 else "203.0.113.1", 18080))
        listener.listen()
        while True:
            conn, address = listener.accept()
            with conn:
                conn.settimeout(5)
                conn.recv(1024)
                conn.sendall(address[0].encode() + b"\n")

    def udp(v6):
        sock = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("2001:db8:203::1" if v6 else "203.0.113.1", 18081))
        while True:
            data, address = sock.recvfrom(65535)
            sock.sendto(data, address)

    def dns():
        sock = socket.socket(type=socket.SOCK_DGRAM)
        sock.bind(("10.77.0.2", 53))
        while True:
            query, address = sock.recvfrom(4096)
            # The test issues one ordinary A/AAAA question without EDNS.
            if query[-4:-2] not in [b"\0\x01", b"\0\x1c"] or (b"\x05echo6\x04test" in query and query[-4:-2] == b"\0\x01"):
                sock.sendto(query[:2] + bytes.fromhex("81800001000000000000") + query[12:], address)
                continue
            answer = query[:2] + bytes.fromhex("81800001000100000000") + query[12:]
            v6 = query[-4:-2] == b"\0\x1c"
            answer += bytes.fromhex("c00c001c00010000003c0010" if v6 else "c00c000100010000003c0004")
            sock.sendto(answer + ipaddress.ip_address("2001:db8:203::1" if v6 else "203.0.113.1").packed, address)

    for target in (tcp, udp):
        for v6 in (False, True):
            threading.Thread(target=target, args=(v6,), daemon=True).start()
    threading.Thread(target=dns, daemon=True).start()
    print("ready", flush=True)
    signal.pause()


def scenario(binary):
    assert os.geteuid() == 0, "requires root inside an isolated namespace"
    links = json.loads(run("ip", "-j", "link"))
    assert [link["ifname"] for link in links] == ["lo"], "refusing a nonempty network namespace"
    run("ip", "link", "set", "lo", "up")
    processes = []
    with tempfile.TemporaryDirectory(prefix="meta-desktop-acceptance-") as directory:
        root = Path(directory)
        sleeper = subprocess.Popen(["unshare", "--net", "sleep", "600"])
        processes.append(sleeper)
        try:
            wait_for(lambda: os.readlink(f"/proc/{sleeper.pid}/ns/net") != os.readlink("/proc/self/ns/net"))
            prefix = ["nsenter", "-t", str(sleeper.pid), "-n"]
            run(*prefix, "ip", "link", "set", "lo", "up")
            run(*prefix, "ip", "addr", "add", "203.0.113.1/32", "dev", "lo")
            run(*prefix, "ip", "-6", "addr", "add", "2001:db8:203::1/128", "dev", "lo", "nodad")
            for i in range(2):
                run("ip", "link", "add", f"exit{i}", "type", "veth", "peer", "name", f"peer{i}")
                run("ip", "link", "set", f"peer{i}", "netns", str(sleeper.pid))
                run("ip", "addr", "add", f"10.77.{i}.1/24", "dev", f"exit{i}")
                run("ip", "-6", "addr", "add", f"fd77:{i}::1/64", "dev", f"exit{i}", "nodad")
                run("ip", "link", "set", f"exit{i}", "up")
                run(*prefix, "ip", "addr", "add", f"10.77.{i}.2/24", "dev", f"peer{i}")
                run(*prefix, "ip", "-6", "addr", "add", f"fd77:{i}::2/64", "dev", f"peer{i}", "nodad")
                run(*prefix, "ip", "link", "set", f"peer{i}", "up")
                run("ip", "route", "add", "default", "via", f"10.77.{i}.2", "dev", f"exit{i}", "metric", str(100 + i * 100))
                run("ip", "-6", "route", "add", "default", "via", f"fd77:{i}::2", "dev", f"exit{i}", "metric", str(100 + i * 100))
            run("ip", "route", "add", "203.0.113.8/32", "dev", "lo", "metric", "99")
            # A second VPN owns overlapping routes, including our metric value.
            # Keep its device open so Linux treats its routes as usable.
            other = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--other-vpn"], stdout=subprocess.PIPE, text=True)
            processes.append(other)
            assert other.stdout.readline().strip() == "ready"
            run("ip", "link", "set", "other-vpn", "up")
            for family, network, metric in [("-4", "128.0.0.0/1", "77"), ("-4", "203.0.113.88/32", "7"), ("-6", "8000::/1", "77"), ("-6", "2001:db8:88::/64", "7")]:
                run("ip", family, "route", "add", network, "dev", "other-vpn", "metric", metric)
            def foreign_routes():
                return sorted(json.dumps(r, sort_keys=True) for family in ["-4", "-6"]
                              for r in json.loads(run("ip", "-j", family, "route", "show"))
                              if r.get("dev") == "other-vpn")
            original_foreign = foreign_routes()
            # Force a multipart netlink dump larger than the old 4096-byte buffer.
            subprocess.run(["ip", "-batch", "-"], input="".join(
                f"route add 192.0.2.{i}/32 dev lo metric 99\n" for i in range(1, 121)
            ), text=True, check=True)
            run("ip", "link", "set", "exit0", "name", "uplink")
            server = subprocess.Popen(prefix + [sys.executable, str(Path(__file__).resolve()), "--peer"], stdout=subprocess.PIPE, text=True)
            processes.append(server)
            assert server.stdout.readline().strip() == "ready"
            config = root / "config.yaml"
            config.write_text("""log-level: debug
rules: ['MATCH,DIRECT']
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: ['10.77.0.2']
tun:
  enable: true
  device: meta-accept
  auto-route: true
  interface: uplink
  dns-hijack: ['any:53']
  route-exclude-address: ['203.0.113.9/32']
""")
            journal = root / "clyntis-tun-state.json"

            def routes():
                return json.loads(run("ip", "-j", "route", "show"))

            def exclusion(device):
                return any(r.get("dst") == "203.0.113.9" and r.get("dev") == device for r in routes())

            def start():
                log = open(root / f"run-{len(processes)}.log", "w+")
                proc = subprocess.Popen([binary, "-f", str(config), "-d", directory], stdout=log, stderr=log)
                processes.append(proc)
                wait_for(lambda: any(r.get("dst") == "128.0.0.0/1" and r.get("dev") == "meta-accept" for r in routes()))
                # Let the CLI's immediate initial refresh finish before opening
                # sessions (it may discover post-TUN interface metadata).
                time.sleep(0.5)
                assert proc.poll() is None, "CLI exited during initial refresh"
                v6 = json.loads(run("ip", "-j", "-6", "route", "show"))
                assert {"::/1", "8000::/1"} <= {r.get("dst") for r in v6}
                return proc, log

            def restored():
                assert not journal.exists() and not exclusion("uplink")
                assert not any(r.get("metric") == 7 and r.get("dev") != "other-vpn" for r in routes())
                assert not any(r.get("metric") == 7 and r.get("dev") != "other-vpn" for r in json.loads(run("ip", "-j", "-6", "route", "show")))
                assert foreign_routes() == original_foreign
                assert sum(r.get("metric") == 99 for r in routes()) == 121

            def traffic(expected_source, v6=False):
                query = bytes.fromhex("123401000001000000000000") + (b"\x05echo6\x04test\0" if v6 else b"\x04echo\x04test\0") + (b"\0\x1c" if v6 else b"\0\x01") + b"\0\x01"
                with socket.socket(type=socket.SOCK_DGRAM) as dns:
                    dns.settimeout(5)
                    dns.sendto(query, ("203.0.113.53", 53))
                    response = dns.recv(4096)
                assert response[:2] == query[:2] and response[3] & 15 == 0
                fake = str(ipaddress.ip_address(response[-16:] if v6 else response[-4:]))
                assert ipaddress.ip_address(fake) in ipaddress.ip_network("fdfe:dcba:9876::/64" if v6 else "198.18.0.0/15"), fake
                for destination in (fake, "2001:db8:203::1" if v6 else "203.0.113.1"):
                    with socket.create_connection((destination, 18080), timeout=5) as conn:
                        conn.sendall(b"source\n")
                        assert conn.recv(100).strip().decode() == expected_source
                with socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(5)
                    data = bytes(range(250)) * 16
                    udp.sendto(data, (fake, 18081))
                    assert udp.recv(65535) == data

            proc, log = start()
            traffic("10.77.0.1")
            traffic("fd77::1", True)
            assert foreign_routes() == original_foreign
            assert exclusion("uplink")
            print("PASS automatic split routes, DNS hijack/fake-IP, TCP/fragmented UDP, physical egress", flush=True)
            run("ip", "route", "del", "default", "via", "10.77.0.2")
            run("ip", "-6", "route", "del", "default", "via", "fd77::2")
            run("ip", "link", "set", "uplink", "down")
            run("ip", "link", "set", "uplink", "name", "retired")
            run("ip", "link", "set", "retired", "up")
            run("ip", "link", "set", "exit1", "down")
            run("ip", "link", "set", "exit1", "name", "uplink")
            run("ip", "link", "set", "uplink", "up")
            run("ip", "route", "replace", "default", "via", "10.77.1.2", "dev", "uplink", "metric", "200")
            run("ip", "-6", "addr", "replace", "fd77:1::1/64", "dev", "uplink", "nodad")
            run("ip", "-6", "route", "replace", "default", "via", "fd77:1::2", "dev", "uplink", "metric", "200")
            wait_for(lambda: exclusion("uplink") and not exclusion("retired"))
            traffic("10.77.1.1")
            traffic("fd77:1::1", True)
            assert foreign_routes() == original_foreign
            print("PASS network switch, exclusion refresh and reconnect", flush=True)
            proc.send_signal(signal.SIGTERM)
            assert proc.wait(timeout=10) == 0
            restored()
            log.close()
            print("PASS graceful restoration preserves unrelated route", flush=True)
            proc, log = start()
            proc.kill()
            proc.wait(timeout=5)
            assert journal.exists() and exclusion("uplink")
            run(binary, "-d", directory, "--recover-tun")
            restored()
            log.close()
            print("PASS SIGKILL journal recovery preserves unrelated route", flush=True)
            print("PASS competing VPN IPv4/IPv6 overlapping routes and identical metrics preserved", flush=True)
            print("PASS IPv6 fake-IP, TCP/fragmented UDP and egress replacement", flush=True)
        except BaseException:
            print(run("ip", "route", "show"), file=sys.stderr)
            for path in root.glob("*.log"):
                print(path.read_text(), file=sys.stderr)
            raise
        finally:
            for proc in reversed(processes):
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=5)


if __name__ == "__main__":
    if sys.argv[1:] == ["--peer"]:
        peer()
    elif sys.argv[1:] == ["--other-vpn"]:
        other_vpn()
    else:
        scenario(str(Path(sys.argv[1]).resolve()))
