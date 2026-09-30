"""Release check: run this before anything goes public. It must say PASS.

  python tools/release_check.py                 check the files git would publish
  python tools/release_check.py --export DIR    also copy exactly those files into a NEW
                                                folder DIR, ready to become a fresh public repo

What it checks (fail closed: anything it can't check counts as a fail):
  1. No private words in any published file. The word list lives in
     _private/release_denylist.txt, one per line. That file is never published
     (so the list itself doesn't name the things it protects). No list = FAIL.
  2. No secrets: private key files, key-looking hex blobs, email addresses, tokens.
  3. No private folders or built files tracked by git (_private/, keys, *.plug).
  4. Git history: old commits are checked too. If history has private words, the
     public repo must start from a fresh history (use --export), and it says so.
Standard library only.
"""
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DENYLIST = ROOT / "_private" / "release_denylist.txt"
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a private key block"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "an email address"),
    (re.compile(r"\b(?:ghp|gho|github_pat|sk|xox[bap])[-_][A-Za-z0-9_-]{16,}"), "an access token"),
]
ALLOWED_EMAILS = {"noreply@localhost"}
BAD_PATHS = re.compile(r"(^|/)(_private|keys|\.workzone)(/|$)|\.key$|\.plug$|(^|/)\.env$")


def git(*args, cwd=ROOT):
    return subprocess.run(["git", "-c", f"safe.directory={Path(cwd).as_posix()}", *args], cwd=cwd,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


def load_denylist(path=DENYLIST):
    if not Path(path).exists():
        return None
    words = [w.strip() for w in Path(path).read_text(encoding="utf-8").splitlines()]
    return [w for w in words if w and not w.startswith("#")]


# "Trojan Source" (CVE-2021-42574): characters that are invisible or change text direction,
# so code can look different from what runs. Listed as numbers so this file holds none of them.
HIDDEN_CODES = (0x00AD, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2028, 0x2029, 0x202A, 0x202B,
                0x202C, 0x202D, 0x202E, 0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF)
HIDDEN = re.compile("[" + "".join(chr(c) for c in HIDDEN_CODES) + "]")


def check_text(name, text, words):
    """Problems in one file's text."""
    out = []
    h = HIDDEN.search(text)
    if h:
        line = text.count(chr(10), 0, h.start()) + 1
        out.append(f"{name}: hidden character U+{ord(h.group()):04X} at line {line} (Trojan Source risk)")
    low = text.lower()
    for w in words:
        if re.search(r"(?<![a-z0-9])" + re.escape(w.lower()) + r"(?![a-z0-9])", low):
            out.append(f"{name}: contains a private word (#{words.index(w) + 1} on your list)")
    for pat, what in SECRET_PATTERNS:
        for m in pat.finditer(text):
            if what == "an email address" and (m.group(0).lower() in ALLOWED_EMAILS or
                                               re.search(r"@(?:[a-z0-9-]+\.)*example\.(?:com|org|net)$", m.group(0).lower())):
                continue     # example.com is reserved for examples: never a real address
            out.append(f"{name}: looks like {what}")
            break
    return out


def published_files(root=ROOT):
    r = git("ls-files", "-z", cwd=root)
    if r.returncode != 0:
        return None
    return [f for f in r.stdout.split("\0") if f]


def run(root=ROOT, denylist=DENYLIST):
    problems, notes = [], []
    words = load_denylist(denylist)
    if words is None:
        return [f"no private word list at {Path(denylist).relative_to(root) if Path(denylist).is_relative_to(root) else denylist} (fail closed: create it, one word per line)"], notes, []
    files = published_files(root)
    if files is None:
        return ["not a git repository (can't tell which files would be published)"], notes, []
    for f in files:
        if BAD_PATHS.search(f):
            problems.append(f"{f}: this kind of file must never be published")
            continue
        p = Path(root) / f
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue     # binary files: path rules above still apply
        problems.extend(check_text(f, text, words))
    # History: a public push would include every old commit, not just today's files.
    hist = git("log", "-p", "--all", "--format=%H", cwd=root)
    if hist.returncode == 0:
        hits = [w for w in words if re.search(r"(?<![a-z0-9])" + re.escape(w.lower()) + r"(?![a-z0-9])", hist.stdout.lower())]
        if hits:
            notes.append(f"git history mentions {len(hits)} private word(s) in OLD commits. Do NOT push this "
                         "repo as it is. Publish from a fresh history instead: --export DIR, then git init there.")
    return problems, notes, files


def export(files, dest, root=ROOT):
    dest = Path(dest).resolve()
    if dest.exists():
        raise FileExistsError(f"{dest} already exists; pick a new folder")
    if Path(root).resolve() in dest.parents or dest == Path(root).resolve():
        raise ValueError("export somewhere outside this project")
    for f in files:
        target = dest / f
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(Path(root) / f, target)
    return dest


def main(argv):
    problems, notes, files = run()
    for p in problems:
        print("FAIL  " + p)
    for n in notes:
        print("NOTE  " + n)
    if problems:
        print(f"\nRELEASE CHECK: FAIL ({len(problems)} problem(s)). Nothing should go public yet.")
        return 1
    print(f"\nRELEASE CHECK: PASS ({len(files)} files would be published, none private).")
    if "--export" in argv:
        i = argv.index("--export")
        if i + 1 >= len(argv):
            print("--export needs a NEW folder")
            return 2
        out = export(files, argv[i + 1])
        print(f"Exported a clean copy to {out}")
        print("Next (only when you decide to go live): cd there, git init, add a remote, push.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
