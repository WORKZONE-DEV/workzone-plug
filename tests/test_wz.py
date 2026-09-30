"""wz terminal app tests: every command works from a terminal, in a throwaway home folder."""
import contextlib
import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))


class Wz(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("WORKZONE_HOME")
        os.environ["WORKZONE_HOME"] = self.tmp.name
        import keys
        importlib.reload(keys)
        import wz
        self.wz = importlib.reload(wz)
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)

    def tearDown(self):
        os.chdir(self.cwd)
        if self.old is None:
            os.environ.pop("WORKZONE_HOME", None)
        else:
            os.environ["WORKZONE_HOME"] = self.old
        import keys
        importlib.reload(keys)
        self.tmp.cleanup()

    def run_wz(self, *args, answers=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            if answers is not None:
                it = iter(answers)
                code = self.wz.menu(ask=lambda _q: next(it))
            else:
                code = self.wz.main(list(args))
        return code, out.getvalue()

    def test_key_pack_verify_list_from_the_terminal(self):
        code, out = self.run_wz("pack", str(ROOT / "examples" / "hello"))
        self.assertEqual(code, 1)
        self.assertIn("Make your key first", out)
        self.assertEqual(self.run_wz("key")[0], 0)
        self.assertIn("already have a key", self.run_wz("key")[1], "a second key never overwrites the first")
        code, out = self.run_wz("pack", str(ROOT / "examples" / "hello"), "hello.plug")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.run_wz("verify", "hello.plug")[0], 0)
        code, out = self.run_wz("list")
        self.assertIn("zone.work.hello", out)
        bad = bytearray(Path("hello.plug").read_bytes()); bad[70] ^= 1
        Path("bad.plug").write_bytes(bytes(bad))
        self.assertIn("NO", self.run_wz("list")[1], "a tampered plug is shown as NO")
        self.assertEqual(self.run_wz("verify", "bad.plug")[0], 1)

    def test_fit_and_remix_and_api(self):
        site = Path("site"); site.mkdir(); (site / "index.html").write_text("<p>hi</p>")
        self.assertEqual(self.run_wz("fit", "site")[0], 0)
        self.run_wz("key")
        self.run_wz("pack", str(ROOT / "examples" / "hello"), "hello.plug")
        self.assertEqual(self.run_wz("remix", "hello.plug", "mine")[0], 0)
        self.assertTrue(json.loads(Path("mine/plug.json").read_text())["built_on"])
        Path("api.json").write_text(json.dumps({"openapi": "3.0.0", "servers": [{"url": "https://api.example.com"}],
                                                "paths": {"/x": {"get": {}}}}))
        self.assertEqual(self.run_wz("api", "api.json", "apiplug")[0], 0)

    def test_menu_by_numbers(self):
        code, out = self.run_wz(answers=["3", "0"])        # 3 = key, then quit
        self.assertEqual(code, 0)
        self.assertIn("Your key is ready", out)
        code, out = self.run_wz(answers=["1", "", "0"])     # fit, then an empty answer cancels
        self.assertIn("Cancelled", out)

    def test_unknown_command_shows_help(self):
        code, out = self.run_wz("dance")
        self.assertEqual(code, 2)
        self.assertIn("wz: the whole Work Zone", out)


if __name__ == "__main__":
    unittest.main()
