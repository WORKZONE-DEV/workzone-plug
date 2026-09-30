"""Phase 8.1 desktop host: a plug is checked before it gets a window, and is handed over only once."""
import http.client
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))


class Desktop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["WORKZONE_HOME"] = cls.tmp.name
        import desktop
        import pack
        cls.desktop = desktop
        cls.plug = Path(cls.tmp.name) / "hello.plug"
        cls.plug.write_bytes(pack.build(ROOT / "examples" / "hello", bytes(range(32))))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        os.environ.pop("WORKZONE_HOME", None)

    def call(self, port, method, path, body=None, token=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        h = {"Host": f"127.0.0.1:{port}", "Content-Type": "application/json"}
        if token:
            h["X-WorkZone-Token"] = token
        c.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=h)
        r = c.getresponse()
        raw = r.read()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw

    def test_checked_then_handed_over_once(self):
        m, httpd, url, proc = self.desktop.run(self.plug, open_window=False)
        try:
            self.assertIsNone(proc)
            self.assertEqual(m["id"], "zone.work.hello")
            port = httpd.server_address[1]
            path, hid = url.split("127.0.0.1:%d" % port)[1].split("#h=")
            s, page = self.call(port, "GET", path)
            self.assertEqual(s, 200)
            token = page.split(b"var TOKEN = '")[1].split(b"'")[0].decode()
            self.assertNotEqual(token, "__WORKZONE_TOKEN__", "the desktop page is handed its token")
            self.assertEqual(self.call(port, "POST", "/api/handoff", {"id": hid})[0], 403, "no token, no plug")
            s, r = self.call(port, "POST", "/api/handoff", {"id": hid}, token)
            self.assertEqual(s, 200)
            self.assertEqual(r["b64"][:4], "UEsD", "the plug file itself (a zip)")
            s, r = self.call(port, "POST", "/api/handoff", {"id": hid}, token)
            self.assertEqual(s, 404, "collected once, then forgotten")
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_a_broken_plug_never_gets_a_window(self):
        bad = Path(self.tmp.name) / "bad.plug"
        data = bytearray(self.plug.read_bytes())
        data[len(data) // 2] ^= 1
        bad.write_bytes(bytes(data))
        with self.assertRaises(ValueError):
            self.desktop.run(bad, open_window=False)
        self.assertEqual(self.desktop.main([str(bad)]), 1)

    def test_window_uses_its_own_browser_profile(self):
        cmd = self.desktop.app_command("browser", "http://127.0.0.1:1/x", "mini")
        self.assertIn("--app=http://127.0.0.1:1/x", cmd)
        self.assertIn("--window-size=430,680", cmd)
        prof = [c for c in cmd if c.startswith("--user-data-dir=")][0]
        self.assertTrue(prof.startswith("--user-data-dir=" + self.tmp.name), "never the person's normal profile")


if __name__ == "__main__":
    unittest.main()


class Launcher(unittest.TestCase):
    """The one-click app's own self-check (the cloud build runs the same check on the packed app)."""

    def test_self_check_passes(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, WORKZONE_HOME=d, PYTHONDONTWRITEBYTECODE="1")
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "launch.py"), "--check"],
                               capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("self-check: OK", r.stdout)
