"""Official catalog tests: a pull only runs if fingerprint, signature and official key all check out."""
import hashlib
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import catalog  # noqa: E402
import keys  # noqa: E402
import pack  # noqa: E402


class Catalog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.seed = keys.new_key(d / "official.key")
        self.other = keys.new_key(d / "someone.key")
        self.real_key = catalog.OFFICIAL_KEY
        catalog.OFFICIAL_KEY = keys.public_key_str(self.seed)       # stand-in for the real official key

    def tearDown(self):
        catalog.OFFICIAL_KEY = self.real_key
        self.tmp.cleanup()

    def entry(self, data, **over):
        m, _ = pack.verify(data)
        e = {"id": m["id"], "name": m["name"], "version": m["version"], "category": "Starter", "description": "",
             "file": f"{m['id']}-{m['version']}.plug", "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        e.update(over)
        return e

    def test_official_list_is_complete_and_leaves_out_the_attack_demo(self):
        items = catalog.official_list()
        folders = [i["folder"] for i in items]
        self.assertGreaterEqual(len(items), 21)
        self.assertNotIn("escape-test", folders)
        for i in items:
            self.assertTrue((ROOT / "examples" / i["folder"] / "plug.json").exists(), i["folder"])
            self.assertIn(i["category"], catalog.CATEGORIES)

    def test_build_then_verify_with_the_download_rules(self):
        out = Path(self.tmp.name) / "out"
        cat = catalog.build(out, Path(self.tmp.name) / "official.key", "v9.9.9")
        self.assertEqual(len(cat["plugs"]), len(catalog.official_list()))
        _, problems = catalog.verify_dir(out)
        self.assertEqual(problems, [])

    def test_build_refuses_a_key_that_isnt_official(self):
        with self.assertRaises(ValueError):
            catalog.build(Path(self.tmp.name) / "o", Path(self.tmp.name) / "someone.key", "v1.0.0")

    def test_every_tampering_is_refused(self):
        good = pack.build(ROOT / "examples" / "hello", self.seed)
        catalog.verify_official(good, self.entry(good))                                   # the good one passes
        bad = bytearray(good)
        bad[len(bad) // 2] ^= 1
        with self.assertRaises(ValueError):
            catalog.verify_official(bytes(bad), self.entry(good))                         # changed bytes
        forged = pack.build(ROOT / "examples" / "hello", self.other)
        with self.assertRaisesRegex(ValueError, "official"):
            catalog.verify_official(forged, self.entry(forged))                           # right fingerprint, wrong signer
        with self.assertRaisesRegex(ValueError, "promised"):
            catalog.verify_official(good, self.entry(good, id="zone.work.notes"))          # swapped plug
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            catalog.verify_official(good, self.entry(good, sha256="0" * 64))

    def test_only_githubs_download_hosts(self):
        self.assertTrue(catalog.allowed("https://github.com/WORKZONE-DEV/workzone-plug/releases/download/v1/x.plug"))
        self.assertTrue(catalog.allowed("https://objects.githubusercontent.com/abc"))
        for bad in ("http://github.com/x", "https://evil.example/x", "https://github.com.evil.example/x",
                    "https://user:pw" + chr(64) + "github.com/x", "https://github.com:8443/x", "file:///c:/x"):
            self.assertFalse(catalog.allowed(bad), bad)
        with self.assertRaises(ValueError):
            catalog.fetch("https://evil.example/catalog.json", 100)
        h = catalog._OnlyOurHosts()
        for bad in ("https://evil.example/x.plug", "http://github.com/x.plug"):
            with self.assertRaises(urllib.error.URLError):
                h.redirect_request(None, None, 302, "", {}, bad)

    def test_catalog_file_is_checked(self):
        good = {"catalog": "0", "tag": "v1.0.0", "plugs": [{"id": "zone.work.hello", "name": "Hello", "version": "0.1.0",
                "category": "Starter", "description": "", "file": "zone.work.hello-0.1.0.plug", "sha256": "a" * 64, "size": 10, "powers": ["events"]}]}
        self.assertEqual(catalog.check_catalog(good), [])
        for change in ({"file": "../../x.plug"}, {"category": "Anything"}, {"sha256": "nothex"}, {"size": 10 ** 12},
                       {"powers": "none"}, {"powers": ["camera"]}):
            bad = json.loads(json.dumps(good))
            bad["plugs"][0].update(change)
            self.assertTrue(catalog.check_catalog(bad), change)
        twice = json.loads(json.dumps(good))
        twice["plugs"] *= 2
        self.assertTrue(catalog.check_catalog(twice))
        self.assertTrue(catalog.check_catalog({"catalog": "0", "tag": "latest", "plugs": good["plugs"]}))

    def test_an_older_catalog_is_refused(self):
        data = pack.build(ROOT / "examples" / "hello", self.seed)
        cat = {"catalog": "0", "tag": "v1.0.0", "plugs": [dict(self.entry(data), powers=["events"])]}
        old = catalog.fetch
        catalog.fetch = lambda url, limit: json.dumps(cat).encode()
        try:
            self.assertEqual(catalog.load(not_older_than="1.0.0")["tag"], "v1.0.0")
            with self.assertRaisesRegex(ValueError, "older"):
                catalog.load(not_older_than="1.17.0")
        finally:
            catalog.fetch = old

    def test_get_downloads_and_verifies(self):
        data = pack.build(ROOT / "examples" / "hello", self.seed)
        cat = {"catalog": "0", "tag": "v1.0.0", "plugs": [self.entry(data)]}
        asked = []
        old = catalog.fetch
        catalog.fetch = lambda url, limit: asked.append(url) or data
        try:
            got, m = catalog.get(cat, "zone.work.hello")
            self.assertEqual(got, data)
            self.assertIn("/releases/download/v1.0.0/zone.work.hello-0.1.0.plug", asked[0])
            with self.assertRaisesRegex(ValueError, "isn't in the official catalog"):
                catalog.get(cat, "zone.work.anything")
        finally:
            catalog.fetch = old


if __name__ == "__main__":
    unittest.main()
