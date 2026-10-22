"""Security fixes without Blender: loopback URLs are parsed, a redirect never carries a key, and
run_python refuses a lone carriage return the approval card would not show."""

import sys
import threading
import types
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "addons_core"))

fake_bpy = types.ModuleType("bpy")
fake_bpy.app = types.SimpleNamespace(driver_namespace={})
sys.modules.setdefault("bpy", fake_bpy)

from loopcut import cloud_http, config, tools  # noqa: E402


class LoopbackTest(unittest.TestCase):
    def test_only_plain_127_0_0_1(self):
        for url in ("http://127.0.0.1/v1", "http://127.0.0.1:8765/v1"):
            self.assertTrue(config.loopback(url), url)
        for url in ("http://127.0.0.1.nip.io/v1", "http://127.0.0.1@evil.example/v1",
                    "http://127.0.0.1:1@evil.example", "https://127.0.0.1/v1", "http://evil.example/v1"):
            self.assertFalse(config.loopback(url), url)
        self.assertFalse(config.loopback("http://127.0.0.1/v1", port=True))

    def test_base_url_check_parses_the_host(self):
        config._check_base_url("http://127.0.0.1:11434/v1", "Base URL")
        with self.assertRaises(config.ConfigError):
            config._check_base_url("http://127.0.0.1.nip.io/v1", "Base URL")


class RedirectTest(unittest.TestCase):
    def serve(self, handler):
        server = HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}"

    def test_redirect_drops_credentials(self):
        seen = []

        class Target(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append({k.lower(): v for k, v in self.headers.items()})
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        target = self.serve(Target)

        class Redirect(Target):
            def do_GET(self):
                seen.append({k.lower(): v for k, v in self.headers.items()})
                self.send_response(302)
                self.send_header("Location", target + "/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()

        start = self.serve(Redirect)
        request = urllib.request.Request(start + "/v1/me", headers={
            "Authorization": "Bearer lc_secret", "x-api-key": "sk-secret", "Accept": "application/json"})
        with cloud_http.urlopen(request, timeout=5) as response:
            self.assertEqual(response.read(), b"ok")
        self.assertEqual(seen[0]["authorization"], "Bearer lc_secret")
        self.assertEqual(seen[0]["x-api-key"], "sk-secret")
        self.assertNotIn("authorization", seen[1])
        self.assertNotIn("x-api-key", seen[1])
        self.assertEqual(seen[1]["accept"], "application/json")


class CarriageReturnTest(unittest.TestCase):
    def test_lone_carriage_return_is_refused(self):
        result = tools.run_python("x = 1  # just a comment\rimport os")
        self.assertFalse(result.ok)
        self.assertIn("carriage return", result.text)


if __name__ == "__main__":
    unittest.main()
