"""Phase 7 helper tests: it only talks to its own page, and only writes into its scratch folder."""
import base64
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))


class Helper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["WORKZONE_HOME"] = cls.tmp.name
        import workzone
        cls.wz = workzone
        cls.httpd, cls.state = workzone.serve(0)
        cls.state.strict = False           # these tests are about the other rules; Guard tests strict mode
        cls.port = cls.state.port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()
        os.environ.pop("WORKZONE_HOME", None)

    def req(self, method, path, body=None, token=True, host=None, origin=None, confirm=True):
        if confirm and method == "POST" and path in self.wz.RISKY and token is True:
            s, got = self.req("POST", "/api/confirm", {"action": path}, confirm=False)   # a person pressed and held
            body = dict(body or {}, **({"pass": got["pass"]} if s == 200 else {}))
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if origin:
            h["Origin"] = origin
        if token:
            h["X-WorkZone-Token"] = self.state.token if token is True else token
        data = json.dumps(body).encode() if body is not None else None
        if data is not None:
            h["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw

    def setUp(self):
        # Every test starts with no key, so no test depends on another one's leftovers.
        kp = self.wz.key_path()
        if kp.exists():
            kp.unlink()
        self.state.passes.clear()          # and with a fresh one-minute counter for risky actions
        self.state.recent.clear()

    def files(self, *pairs):
        return [{"path": p, "b64": base64.b64encode(c.encode()).decode()} for p, c in pairs]

    # ---- the doors
    def test_page_gets_token_and_other_folders_are_hidden(self):
        s, body = self.req("GET", "/", token=False)
        self.assertEqual(s, 200)
        self.assertIn(self.state.token.encode(), body)
        for bad in ["/tools/keys.py", "/tests/test_keys.py", "/../README.md", "/ui/../tools/pack.py", "/%2e%2e/README.md", "/.git/config"]:
            with self.subTest(bad):
                self.assertEqual(self.req("GET", bad, token=False)[0], 404)

    def test_other_websites_are_refused(self):
        self.assertEqual(self.req("GET", "/", host="evil.example", token=False)[0], 403, "DNS-rebinding style Host")
        self.assertEqual(self.req("POST", "/api/status", {}, origin="https://evil.example")[0], 403)
        self.assertEqual(self.req("POST", "/api/status", {}, origin=f"http://127.0.0.1:{self.port}")[0], 200)

    def test_token_required(self):
        self.assertEqual(self.req("POST", "/api/status", {}, token=False)[0], 403)
        self.assertEqual(self.req("POST", "/api/status", {}, token="wrong")[0], 403)

    # ---- the work
    def test_fit_then_build_a_dropped_page(self):
        s, out = self.req("POST", "/api/fit", {"files": self.files(("game/index.html", "<p>hi</p><script>var a=1</script>"))})
        self.assertEqual(s, 200, out)
        self.assertEqual(out["verdict"], "OK")
        s, b = self.req("POST", "/api/build", {"drop_id": out["drop_id"]})
        self.assertEqual(s, 400)
        self.assertTrue(b.get("need_key"), "no key yet -> asks for one, builds nothing")
        s, k = self.req("POST", "/api/key/new", {})
        self.assertEqual(s, 200)
        self.assertEqual(self.req("POST", "/api/key/new", {})[0], 409, "a second key never overwrites the first")
        s, b = self.req("POST", "/api/build", {"drop_id": out["drop_id"]})
        self.assertEqual(s, 200, b)
        self.assertEqual(b["author_key"], k["public_key"])
        s, v = self.req("POST", "/api/verify", {"b64": b["b64"]})
        self.assertTrue(v["ok"])
        bad = bytearray(base64.b64decode(b["b64"])); bad[50] ^= 1
        s, v = self.req("POST", "/api/verify", {"b64": base64.b64encode(bytes(bad)).decode()})
        self.assertFalse(v["ok"])

    def test_things_that_dont_fit_are_explained_not_built(self):
        s, out = self.req("POST", "/api/fit", {"files": self.files(("tool.exe", "MZ"))})
        self.assertEqual(out["verdict"], "STOP")
        self.assertIn("can never go in a plug", out["text"])
        self.req("POST", "/api/key/new", {})
        s, b = self.req("POST", "/api/build", {"drop_id": out["drop_id"]})
        self.assertEqual(s, 400)
        self.assertIn("doesn't fit", b["error"])

    def test_dropped_paths_cannot_escape_the_scratch_folder(self):
        for bad in ["../evil.txt", "a/../../evil.txt", "/etc/passwd", "C:/Windows/evil.txt", "C:\\evil.txt", "..\\evil.txt", "",
                    # red-team: Windows device names, trailing dots/spaces, data streams, odd dots
                    "a/CON", "nul.txt", "COM1.log", "a/x. ", "a/x.", "a/b:c", "a/b::$DATA", "a/.../x", "a/.. /x"]:
            with self.subTest(bad):
                s, out = self.req("POST", "/api/fit", {"files": self.files((bad, "x"))})
                self.assertEqual(s, 400, out)
        self.assertFalse((Path(self.tmp.name).parent / "evil.txt").exists())

    def test_examples_build(self):
        self.req("POST", "/api/key/new", {})
        s, st = self.req("POST", "/api/status", {})
        self.assertIn("hello", st["examples"])
        s, b = self.req("POST", "/api/build-example", {"name": "hello"})
        self.assertEqual(s, 200, b)
        self.assertEqual(b["id"], "zone.work.hello")
        self.assertEqual(self.req("POST", "/api/build-example", {"name": "../tools"})[0], 404)

    def test_case_clash_and_bad_content_are_clean_errors(self):
        s, out = self.req("POST", "/api/fit", {"files": self.files(("s/A.txt", "1"), ("s/a.txt", "2"))})
        self.assertEqual(s, 400, out)
        self.assertIn("capitals", out["error"])
        s, out = self.req("POST", "/api/fit", {"files": [{"path": "a.html", "b64": 5}]})
        self.assertEqual(s, 400, out)

    def test_bad_drop_id_is_a_clean_error(self):
        self.req("POST", "/api/key/new", {})
        for d in [[1], {"a": 1}, 5, None]:
            with self.subTest(d):
                s, out = self.req("POST", "/api/build", {"drop_id": d})
                self.assertIn(s, (400, 404), out)

    def test_junk_is_a_clean_error(self):
        for body in [[], "x", {"files": "nope"}, {"files": [{"path": "a.html", "b64": "***"}]}]:
            with self.subTest(body):
                s, out = self.req("POST", "/api/fit", body)
                self.assertIn(s, (400, 404))
                self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()


class Guard(unittest.TestCase):
    """Risky actions need a person: a one-time pass, for one action, for 30 seconds, 5 a minute at most."""
    setUpClass = classmethod(Helper.setUpClass.__func__)
    tearDownClass = classmethod(Helper.tearDownClass.__func__)
    req = Helper.req

    def setUp(self):
        Helper.setUp(self)
        self.state.strict = False
        self.state.ask = lambda what: False
        self.state.passes.clear()
        self.state.recent.clear()

    def test_no_pass_no_action(self):
        for path in self.wz.RISKY:
            if path == "/api/strict":
                continue
            s, out = self.req("POST", path, {}, confirm=False)
            self.assertEqual(s, 403, path)
            self.assertTrue(out.get("need_confirm"), path)
        self.assertFalse(self.wz.key_path().exists(), "no key was made without a person")

    def test_pass_works_once_and_only_for_its_action(self):
        s, got = self.req("POST", "/api/confirm", {"action": "/api/key/new"}, confirm=False)
        self.assertEqual(s, 200)
        self.assertEqual(self.req("POST", "/api/update-check", {"pass": got["pass"]}, confirm=False)[0], 403, "wrong action")
        s, got = self.req("POST", "/api/confirm", {"action": "/api/key/new"}, confirm=False)
        self.assertEqual(self.req("POST", "/api/key/new", {"pass": got["pass"]}, confirm=False)[0], 200)
        self.wz.key_path().unlink()
        self.assertEqual(self.req("POST", "/api/key/new", {"pass": got["pass"]}, confirm=False)[0], 403, "used twice")
        self.assertFalse(self.wz.key_path().exists())

    def test_made_up_or_expired_pass_is_refused(self):
        self.assertEqual(self.req("POST", "/api/key/new", {"pass": "made-up"}, confirm=False)[0], 403)
        s, got = self.req("POST", "/api/confirm", {"action": "/api/key/new"}, confirm=False)
        a, _ = self.state.passes[got["pass"]]
        self.state.passes[got["pass"]] = (a, 0)                     # its 30 seconds are up
        self.assertEqual(self.req("POST", "/api/key/new", {"pass": got["pass"]}, confirm=False)[0], 403)

    def test_runaway_loop_is_stopped(self):
        codes = [self.req("POST", "/api/confirm", {"action": "/api/update-check"}, confirm=False)[0] for _ in range(self.wz.RATE + 2)]
        self.assertEqual(codes[:self.wz.RATE], [200] * self.wz.RATE)
        self.assertEqual(codes[self.wz.RATE:], [403, 403], "more than 5 a minute is refused")

    def test_catalog_actions_need_a_person_and_an_opened_catalog(self):
        self.assertIn("/api/catalog", self.wz.RISKY)
        self.assertIn("/api/catalog-get", self.wz.RISKY)
        self.state.catalog = None
        s, out = self.req("POST", "/api/catalog-get", {"id": "zone.work.notes"})
        self.assertEqual(s, 400)
        self.assertIn("open the catalog first", out["error"])

    def test_only_listed_actions_can_be_confirmed(self):
        self.assertEqual(self.req("POST", "/api/confirm", {"action": "/api/anything"}, confirm=False)[0], 400)

    def test_strict_mode_needs_a_yes_in_the_terminal(self):
        self.state.strict = True
        asked = []
        self.state.ask = lambda what: asked.append(what) or False
        s, out = self.req("POST", "/api/confirm", {"action": "/api/key/new"}, confirm=False)
        self.assertEqual(s, 403)
        self.assertIn("terminal", out["error"])
        self.assertEqual(asked, [self.wz.RISKY["/api/key/new"]], "the terminal was asked, in plain words")
        self.state.ask = lambda what: True
        self.assertEqual(self.req("POST", "/api/confirm", {"action": "/api/key/new"}, confirm=False)[0], 200)

    def test_strict_mode_off_needs_a_person_on_does_not(self):
        self.state.strict = True
        self.assertEqual(self.req("POST", "/api/strict", {"on": False}, confirm=False)[0], 403, "an AI can't just switch it off")
        self.assertTrue(self.state.strict)
        self.assertEqual(self.req("POST", "/api/strict", {"on": True}, confirm=False)[0], 200, "making it safer is always allowed")
        self.state.ask = lambda what: True
        self.assertEqual(self.req("POST", "/api/strict", {"on": False})[0], 200)
        self.assertFalse(self.state.strict)
        self.assertFalse(json.loads((Path(self.tmp.name) / "settings.json").read_text())["strict"])
        self.req("POST", "/api/strict", {"on": True}, confirm=False)

    def test_strict_asks_one_question_at_a_time_and_counts_refusals(self):
        self.state.strict = True
        self.state.ask = lambda what: False
        for _ in range(self.wz.RATE):
            self.req("POST", "/api/confirm", {"action": "/api/update-check"}, confirm=False)
        self.state.ask = lambda what: True
        s, out = self.req("POST", "/api/confirm", {"action": "/api/update-check"}, confirm=False)
        self.assertEqual(s, 403, "refused attempts count too, so a flood of questions is capped")
        self.state.asking = True
        s, out = self.req("POST", "/api/confirm", {"action": "/api/key/new"}, confirm=False)
        self.assertEqual(s, 403)
        self.assertIn("already asking", out["error"])
        self.state.asking = False

    def test_the_terminal_shows_the_code_from_the_page(self):
        self.state.strict = True
        asked = []
        self.state.ask = lambda what: asked.append(what) or True
        self.req("POST", "/api/confirm", {"action": "/api/key/new", "code": "K7Q2"}, confirm=False)
        self.req("POST", "/api/confirm", {"action": "/api/key/new", "code": "bad code!"}, confirm=False)
        self.assertIn("(code K7Q2)", asked[0])
        self.assertNotIn("code", asked[1], "odd codes are dropped, not printed")

    def test_parallel_confirms_cannot_beat_the_limit(self):
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(12) as ex:
            codes = list(ex.map(lambda _: self.req("POST", "/api/confirm", {"action": "/api/update-check"}, confirm=False)[0], range(12)))
        self.assertEqual(codes.count(200), self.wz.RATE)

    def test_a_broken_settings_file_keeps_strict_on(self):
        for bad in ('{"strict": 0}', '{"strict": "no"}', 'not json'):
            (Path(self.tmp.name) / "settings.json").write_text(bad)
            self.assertTrue(self.wz.State(0, clear_drops=False).strict, bad)
        (Path(self.tmp.name) / "settings.json").unlink()

    def test_strict_is_on_by_default(self):
        (Path(self.tmp.name) / "settings.json").unlink(missing_ok=True)
        self.assertTrue(self.wz.State(0, clear_drops=False).strict)

    def test_no_terminal_means_no(self):
        old = sys.stdin
        try:
            sys.stdin = None
            self.assertFalse(self.wz.ask_in_terminal("anything"))
        finally:
            sys.stdin = old


class Extras(unittest.TestCase):
    """Update reminder (tells, never installs) and the devices switches."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["WORKZONE_HOME"] = self.tmp.name
        import workzone
        self.wz = workzone

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("WORKZONE_HOME", None)

    def test_update_check_reads_githubs_latest_release(self):
        import io

        class Fake:
            def open(self, req, timeout=0):
                self.url = req.full_url
                return io.BytesIO(json.dumps({"tag_name": "v99.0.0", "body": "big news"}).encode())
        fake, old = Fake(), self.wz._SAFE_OPENER
        self.wz._SAFE_OPENER = fake
        try:
            r = self.wz.update_check()
        finally:
            self.wz._SAFE_OPENER = old
        self.assertEqual(fake.url, self.wz.DEFAULT_UPDATE)
        self.assertTrue(r["newer"])
        self.assertEqual(r["latest"], "99.0.0")
        self.assertIn("releases", r["page"])

    def test_update_check_only_uses_https(self):
        (Path(self.tmp.name) / "update.json").write_text(json.dumps({"url": "http://example.com/x"}))
        r = self.wz.update_check()
        self.assertFalse(r["configured"])
        self.assertIn("https", r["error"])

    def test_devices_switches_are_saved_and_junk_ignored(self):
        (Path(self.tmp.name) / "devices.json").write_text(json.dumps({"devices": [
            {"name": "TV", "kind": "tv", "powers": {"microphone": True, "BAD KEY!": True}}, "junk", {"no": "name"},
            {"name": "Broken", "powers": [1]}]}))
        devs = self.wz.load_devices()
        self.assertEqual([d["name"] for d in devs], ["TV"])
        self.assertEqual(devs[0]["powers"], {"microphone": True})
        self.wz.set_device_power("TV", "microphone", False)
        self.assertFalse(self.wz.load_devices()[0]["powers"]["microphone"])
        with self.assertRaises(ValueError):
            self.wz.set_device_power("TV", "camera", True)
