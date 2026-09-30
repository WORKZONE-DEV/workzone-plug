"""Fit checker tests. The most important one: your original is never changed."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import fit  # noqa: E402
import pack  # noqa: E402

SEED = bytes(range(32))


def tree_hash(p):
    """Fingerprint of every file name + content + folder under p."""
    p = Path(p)
    h = hashlib.sha256()
    items = sorted(p.rglob("*")) if p.is_dir() else [p]
    for f in items:
        h.update(str(f.relative_to(p) if p.is_dir() else f.name).encode())
        if f.is_file():
            h.update(f.read_bytes())
    return h.hexdigest()


def titles(info):
    return " | ".join(f["level"] + ":" + f["title"] for f in info["findings"])


class Detects(unittest.TestCase):
    """Each rule: one case that should trigger it, one that shouldn't (both ways)."""
    CASES = {
        "saves data in the browser": ("localStorage.setItem('a',1)", "var store = {}"),
        "builds code from text": ("eval('1+1')", "evaluate(1)"),
        "talks to the internet directly": ("fetch('/x')", "prefetched = 1"),
        "opens pop-ups": ("alert('hi')", "alerted = true"),
        "reaches into the page around it": ("parent.document.body", "parent.postMessage({topic:'x'},'*')"),
        "puts frames inside itself": ("<iframe src=x></iframe>", "<div>frame</div>"),
        "has a form that submits": ('<form action="/go"></form>', "<form></form>"),
        "uses background workers": ("new Worker('w.js')", "worker = 1"),
        "uses camera": ("navigator.geolocation.getCurrentPosition()", "var locationName = 1"),
        "is split into modules": ("import x from './x.js'", "var imported = 1"),
        # added after the red-team
        "sends the page somewhere else": ("location.href = 'next.html'", "if (location.href == x) {}"),
        "opens links in new tabs": ('<a href="#" target="_blank">x</a>', '<a href="#top">x</a>'),
        "loads a style sheet from another site": ("<style>@import url(fonts.example.com/css);</style>", "<style>@import 'local.css';</style>"),
    }

    def test_meta_refresh_and_timer_strings(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "i.html"
            p.write_text('<meta http-equiv="refresh" content="0;url=x"><script>setInterval("tick()", 9)</script>')
            t = titles(fit.inspect(p))
            self.assertIn("sends the page somewhere else", t)
            self.assertIn("builds code from text", t)

    def test_raw_ip_urls_are_listed(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "i.html"
            p.write_text('<img src="https://1.2.3.4/a.png">')
            self.assertIn("1.2.3.4", fit.inspect(p)["hosts"])

    def test_junction_pointing_outside_is_caught(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            secret = Path(d) / "secret"; secret.mkdir()
            (secret / "s.txt").write_text("private")
            src = Path(d) / "site"; src.mkdir()
            (src / "index.html").write_text("<p>x</p>")
            link = src / "link"
            if sys.platform == "win32":
                r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(secret)], capture_output=True)
            else:
                r = subprocess.run(["ln", "-s", str(secret), str(link)], capture_output=True)
            if r.returncode != 0:
                self.skipTest("could not create a junction/symlink here")
            info = fit.inspect(src)
            self.assertIn("shortcut", titles(info))
            self.assertEqual(fit.verdict(info["findings"]), fit.STOP)
            with self.assertRaises(ValueError):          # port refuses: it doesn't fit
                fit.port(src, Path(d) / "out", info)
            (src / "plug.json").write_text("{}")
            (src / "app").mkdir()
            (src / "app" / "index.html").write_text("<p>x</p>")
            if sys.platform == "win32":
                subprocess.run(["cmd", "/c", "mklink", "/J", str(src / "app" / "l2"), str(secret)], capture_output=True)
            else:
                (src / "app" / "l2").symlink_to(secret)
            with self.assertRaises(ValueError):          # the packer refuses too
                pack.collect(src)
            self.assertEqual((secret / "s.txt").read_text(), "private", "the outside file was never touched")

    def test_both_ways(self):
        for title, (bad, good) in self.CASES.items():
            with self.subTest(title), tempfile.TemporaryDirectory() as d:
                b = Path(d) / "bad.html"
                b.write_text(f"<script>{bad}</script>" if "<" not in bad else bad)
                g = Path(d) / "good.html"
                g.write_text(f"<script>{good}</script>" if "<" not in good else good)
                self.assertIn(title, titles(fit.inspect(b)), "should have been flagged")
                self.assertNotIn(title, titles(fit.inspect(g)), "false alarm")

    def test_every_rule_has_why_and_fix(self):
        for pattern, level, title, why, fix in fit.RULES:
            self.assertTrue(why and fix, title)

    def test_outside_hosts_are_listed(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "i.html"
            p.write_text('<script src="https://cdn.example.com/x.js"></script><img src="//img.example.org/a.png">')
            info = fit.inspect(p)
            self.assertEqual(info["hosts"], ["cdn.example.com", "img.example.org"])


class Kinds(unittest.TestCase):
    def check(self, name, content, expect_level, expect_text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / name
            if isinstance(content, bytes):
                p.write_bytes(content)
            else:
                p.write_text(content)
            info = fit.inspect(p)
            self.assertEqual(fit.verdict(info["findings"]), expect_level, titles(info))
            self.assertIn(expect_text, titles(info) + info["kind"])

    def test_kinds(self):
        self.check("clean.html", "<p>hi</p>", fit.OK, "single web page")
        self.check("tool.exe", b"MZ", fit.STOP, "can never go in a plug")
        self.check("run.bat", "del *", fit.STOP, "can never go in a plug")
        self.check("app.py", "print(1)", fit.STOP, "Python")
        self.check("x.zip", b"PK", fit.WARN, "a zip")
        self.check("s.js", "var a=1", fit.WARN, "needs a page")
        self.check("doc.docx", b"PK", fit.STOP, "not something a web plug can use")
        self.check("pic.png", b"\x89PNG", fit.WARN, "media file")

    def test_missing(self):
        info = fit.inspect(ROOT / "does-not-exist")
        self.assertEqual(fit.verdict(info["findings"]), fit.STOP)

    def test_real_plug_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "h.plug"
            p.write_bytes(pack.build(ROOT / "examples" / "hello", SEED))
            self.assertIn("already a valid plug", titles(fit.inspect(p)))
            bad = bytearray(p.read_bytes()); bad[100] ^= 1
            p.write_bytes(bytes(bad))
            self.assertIn("fails verification", titles(fit.inspect(p)))

    def test_npm_project(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "package.json").write_text("{}")
            (Path(d) / "src").mkdir()
            (Path(d) / "src" / "App.jsx").write_text("import React from 'react'")
            info = fit.inspect(d)
            self.assertIn("needs building first", titles(info))

    def test_folder_name_problems(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "index.html").write_text("<p>x</p>")
            (Path(d) / "my photo.png").write_bytes(b"x")
            t = titles(fit.inspect(d))
            self.assertIn("file name needs changing", t)

    def test_case_clash_folder(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "index.html").write_text("<p>x</p>")
            (Path(d) / "A.js").write_text("1")
            (Path(d) / "a.js").write_text("2")
            # On Windows/Mac the second write silently REPLACED the first: that overwrite is the
            # exact danger this check exists for. So prove it on this machine, then test the
            # check itself with a file LIST (no disk), which works on every computer.
            if len(list(Path(d).glob("*.js"))) < 2:
                self.assertEqual((Path(d) / "A.js").read_text(), "2", "Windows really did overwrite A.js with a.js")
        names = ["index.html", "A.js", "a.js", "img/Logo.png", "img/logo.PNG"]
        found = fit.name_findings(names)
        self.assertIn("same name apart from capitals", " | ".join(f["title"] for f in found))
        self.assertEqual(fit.name_findings(["index.html", "A.js", "b.js"]), [], "no false alarm")


class NeverTouchesOriginal(unittest.TestCase):
    def test_inspect_and_port_leave_source_identical(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "mysite"
            src.mkdir()
            (src / "index.html").write_text('<link rel="stylesheet" href="s.css"><script src="a.js"></script><p>hi</p>')
            (src / "s.css").write_text("p{color:red}")
            (src / "a.js").write_text("localStorage.x=1")
            before = tree_hash(src)
            info = fit.inspect(src)
            fit.render(info)
            out = fit.port(src, Path(d) / "ported", info)
            self.assertEqual(tree_hash(src), before, "the original must be byte-for-byte unchanged")
            # The copy is a real plug source: valid draft, and it packs and verifies.
            m = json.loads((out / "plug.json").read_text())
            self.assertEqual(m["permissions"].get("storage"), "1MB", "storage use was noticed and drafted")
            pack.verify(pack.build(out, SEED, inline=True))

    def test_port_refuses_to_overwrite_or_nest(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "s"; src.mkdir()
            (src / "index.html").write_text("<p>x</p>")
            existing = Path(d) / "taken"; existing.mkdir()
            (existing / "keep.txt").write_text("mine")
            info = fit.inspect(src)
            with self.assertRaises(FileExistsError):
                fit.port(src, existing, info)
            self.assertEqual((existing / "keep.txt").read_text(), "mine")
            with self.assertRaises(ValueError):
                fit.port(src, src / "inside", info)

    def test_port_refuses_things_that_dont_fit(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.exe"; p.write_bytes(b"MZ")
            with self.assertRaises(ValueError):
                fit.port(p, Path(d) / "out", fit.inspect(p))
            self.assertFalse((Path(d) / "out").exists())

    def test_single_script_gets_wrapped(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "game.js"; p.write_text("document.body.textContent='hi'")
            out = fit.port(p, Path(d) / "out", fit.inspect(p))
            self.assertTrue((out / "app" / "index.html").exists())
            pack.verify(pack.build(out, SEED, inline=True))


if __name__ == "__main__":
    unittest.main()
