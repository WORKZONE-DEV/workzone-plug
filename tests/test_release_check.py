"""Release check tests: it must catch private words, secrets and private files, and fail closed."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import release_check as rc  # noqa: E402


def repo(files, commit=True):
    d = tempfile.TemporaryDirectory()
    root = Path(d.name)
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    g = ["git", "-c", f"safe.directory={root.as_posix()}", "-c", "user.name=t", "-c", "user.email=noreply@localhost"]
    subprocess.run(g + ["init", "-q"], cwd=root, check=True)
    subprocess.run(g + ["add", "-A", "-f"], cwd=root, check=True)
    if commit:
        subprocess.run(g + ["commit", "-q", "-m", "x"], cwd=root, check=True)
    return d, root


class ReleaseCheck(unittest.TestCase):
    def check(self, files, words=("secretproject",), commit=True):
        d, root = repo(files, commit)
        deny = root / "deny.txt"
        deny.write_text("\n".join(words))
        # deny.txt itself is untracked, so it isn't "published"
        problems, notes, _ = rc.run(root, deny)
        d.cleanup()
        return problems, notes

    def test_clean_repo_passes(self):
        p, n = self.check({"README.md": "Hello. Contact: noreply@localhost", "a.py": "x = 1"})
        self.assertEqual(p, [])

    def test_each_problem_is_caught(self):
        cases = {
            "private word": {"README.md": "powered by SecretProject tech"},
            "email": {"README.md": "mail me: someone" + "@" + "realmail.co"},
            "private key": {"k.txt": "-----BEGIN OPENSSH " + "PRIVATE KEY-----"},
            "token": {"cfg.txt": "token=" + "ghp" + "_abcdefghijklmnopqrstuvwxyz123456"},
            "private folder": {"_private/notes.md": "nothing"},
            "key file": {"me.key": "00"},
            "built plug": {"x.plug": "PK"},
            "hidden character": {"a.js": "var ok = 1; // " + chr(0x202E) + "evil"},
            "zero width": {"b.js": "var a" + chr(0x200B) + "b = 1"},
        }
        for name, files in cases.items():
            with self.subTest(name):
                p, n = self.check(files)
                self.assertTrue(p, name + " was not caught")

    def test_word_inside_another_word_is_not_a_false_alarm(self):
        p, n = self.check({"README.md": "birdhouse"}, words=("bird",))
        self.assertEqual(p, [])

    def test_no_word_list_fails_closed(self):
        d, root = repo({"README.md": "hi"})
        problems, _, _ = rc.run(root, root / "missing.txt")
        d.cleanup()
        self.assertTrue(problems and "fail closed" in problems[0])

    def test_history_is_checked(self):
        d, root = repo({"README.md": "about secretproject"})
        (root / "README.md").write_text("clean now")
        g = ["git", "-c", f"safe.directory={root.as_posix()}", "-c", "user.name=t", "-c", "user.email=noreply@localhost"]
        subprocess.run(g + ["commit", "-q", "-am", "clean"], cwd=root, check=True)
        deny = root / "deny.txt"; deny.write_text("secretproject")
        problems, notes, files = rc.run(root, deny)
        self.assertEqual(problems, [], "today's files are clean")
        self.assertTrue(any("history" in n for n in notes), "but old commits still mention it")
        out = Path(tempfile.mkdtemp()) / "clean"
        rc.export(files, out, root)
        self.assertEqual((out / "README.md").read_text(), "clean now")
        self.assertFalse((out / ".git").exists(), "the export starts with no history")
        with self.assertRaises(FileExistsError):
            rc.export(files, out, root)
        d.cleanup()


class ThisRepo(unittest.TestCase):
    @unittest.skipUnless(rc.DENYLIST.exists(), "private word list not on this machine")
    def test_this_repo_passes_today(self):
        problems, notes, files = rc.run()
        self.assertEqual(problems, [], "\n".join(problems))


if __name__ == "__main__":
    unittest.main()
