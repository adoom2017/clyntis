"""Loopback-only runner integration tests; no system proxy, TUN, or remote node required."""
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

RUNNER = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else Path("target/debug/clyntis-runner").resolve()
TOKEN = "clyntis-integration-test-secret-0123456789"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"clyntis-loopback-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.port = free_port()
        self.process = subprocess.Popen(
            [str(RUNNER), "--directory", self.directory.name],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8",
        )
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=10)
        for stream in (self.process.stdin, self.process.stdout):
            if stream and not stream.closed:
                stream.close()
        self.directory.cleanup()

    def launch(self, yaml=None):
        yaml = yaml or f"""mixed-port: {self.port}
external-controller: 127.0.0.1:0
secret: {TOKEN}
rules:
- MATCH,DIRECT
"""
        self.send({"command": "start", "version": 1, "yaml": yaml, "profile_id": "11111111-1111-4111-8111-111111111111", "system_proxy_port": None})
        result = json.loads(self.process.stdout.readline())
        if result["event"] == "ready":
            self.controller = "http://" + result["controller"]
        return result

    def send(self, value):
        self.process.stdin.write(json.dumps(value) + "\n")
        self.process.stdin.flush()

    def request(self, path, method="GET", data=None, token=TOKEN):
        request = urllib.request.Request(self.controller + path, method=method,
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            data=json.dumps(data).encode() if data is not None else None)
        return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5)

    def test_ready_auth_policy_and_graceful_stop(self):
        self.assertEqual(self.launch()["event"], "ready")
        with self.request("/version") as response:
            self.assertEqual(json.load(response)["name"], "clyntis")
        with self.assertRaises(urllib.error.HTTPError) as unauthorized:
            self.request("/configs", token="wrong")
        self.assertEqual(unauthorized.exception.code, 401)
        unauthorized.exception.close()
        with self.request("/configs", "PATCH", {"mode": "direct"}) as response:
            self.assertEqual(response.status, 200)
        with self.request("/configs") as response:
            self.assertEqual(json.load(response)["mode"], "direct")
        self.send({"command": "stop", "version": 1})
        self.assertEqual(json.loads(self.process.stdout.readline())["event"], "stopped")
        self.assertEqual(self.process.wait(timeout=10), 0)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", self.port), timeout=1)

    def test_http_proxy_reaches_loopback_origin(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.assertEqual(self.launch()["event"], "ready")
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            host = "127.0.0.1:" + str(server.server_port)
            sock.sendall(f"GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while chunk := sock.recv(4096):
                data += chunk
            self.assertIn(b"clyntis-loopback-ok", data)

    def test_host_disconnect_stops_runner(self):
        self.assertEqual(self.launch()["event"], "ready")
        self.process.stdin.close()
        self.assertEqual(self.process.wait(timeout=10), 0)

    def test_invalid_configuration_has_structured_error(self):
        result = self.launch("unknown-setting: true")
        self.assertEqual(result["event"], "error")
        self.assertNotEqual(self.process.wait(timeout=10), 0)


if __name__ == "__main__":
    unittest.main()
