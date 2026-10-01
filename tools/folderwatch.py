#!/usr/bin/env python3
"""folderwatch - live ASCII tree + activity log for a folder.

Usage: python tools/folderwatch.py [PATH] [--interval 0.5] [--depth 4]
No dependencies; works on Windows, macOS and Linux. Ctrl+C to quit.
"""
import argparse
import difflib
import os
import shutil
import sys
import time
from collections import deque

IGNORE = {".git", "__pycache__", "node_modules", ".venv"}
C = {"add": "\033[92m", "del": "\033[91m", "mod": "\033[93m", "mov": "\033[96m",
     "dim": "\033[90m", "b": "\033[1m", "x": "\033[0m"}
ICON = {"add": "+", "del": "-", "mod": "~", "mov": ">"}


def snapshot(root, depth):
    snap = {}
    root_depth = root.rstrip(os.sep).count(os.sep)
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in IGNORE)
        if d.count(os.sep) - root_depth >= depth:
            dirs[:] = []
        for name in dirs + files:
            p = os.path.join(d, name)
            try:
                st = os.stat(p)
            except OSError:
                continue
            rel = os.path.relpath(p, root)
            snap[rel] = (name in dirs, st.st_size, st.st_mtime, st.st_ino)
    return snap


def read_text(path, limit=200_000):
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, encoding="utf-8") as f:
            return f.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return None


def diff(old, new):
    added = {p for p in new if p not in old}
    removed = {p for p in old if p not in new}
    events = []
    # Detect moves/renames: same inode (or same size+name) gone in one place, new in another
    for r in list(removed):
        for a in list(added):
            o, n = old[r], new[a]
            same = (o[3] and o[3] == n[3]) or (os.path.basename(r) == os.path.basename(a) and o[1] == n[1])
            if o[0] == n[0] and same:
                events.append(("mov", f"{r}  ->  {a}"))
                removed.discard(r)
                added.discard(a)
                break
    events += [("add", p) for p in sorted(added)]
    events += [("del", p) for p in sorted(removed)]
    events += [("mod", p) for p in sorted(new) if p in old and not new[p][0]
               and new[p][1:3] != old[p][1:3]]
    return events


def render_tree(root, snap, hot):
    lines = [f"{C['b']}{os.path.basename(os.path.abspath(root)) or root}/{C['x']}"]
    children = {}
    for rel in snap:
        parent = os.path.dirname(rel)
        children.setdefault(parent, []).append(rel)

    def walk(parent, prefix):
        kids = sorted(children.get(parent, []), key=lambda p: (not snap[p][0], p.lower()))
        for i, rel in enumerate(kids):
            last = i == len(kids) - 1
            is_dir = snap[rel][0]
            name = os.path.basename(rel) + ("/" if is_dir else "")
            color = C[hot[rel]] if rel in hot else ""
            mark = f" {ICON[hot[rel]]}" if rel in hot else ""
            lines.append(f"{prefix}{'└── ' if last else '├── '}{color}{name}{mark}{C['x']}")
            if is_dir:
                walk(rel, prefix + ("    " if last else "│   "))
    walk("", "")
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--depth", type=int, default=4)
    args = ap.parse_args()
    if os.name == "nt":
        os.system("")  # enable ANSI colors on Windows terminals

    root = args.path
    snap = snapshot(root, args.depth)
    cache = {rel: read_text(os.path.join(root, rel)) for rel, v in snap.items() if not v[0]}
    last_diff = ("", [])
    log = deque(maxlen=200)
    hot = {}  # rel path -> (kind, expires_at)
    log.append((time.strftime("%H:%M:%S"), "dim", f"watching {os.path.abspath(root)}"))

    try:
        while True:
            new = snapshot(root, args.depth)
            now = time.time()
            for kind, text in diff(snap, new):
                log.append((time.strftime("%H:%M:%S"), kind, text))
                target = text.split("  ->  ")[-1]
                full = os.path.join(root, target)
                if kind == "mov":
                    cache[target] = cache.pop(text.split("  ->  ")[0], None)
                elif kind == "del":
                    cache.pop(target, None)
                elif not new.get(target, (True,))[0]:
                    before = cache.get(target) or []
                    after = read_text(full)
                    cache[target] = after
                    if after is None:
                        last_diff = (target, ["(binary or large file)"])
                    else:
                        lines = list(difflib.unified_diff(before, after, lineterm="", n=1))[2:]
                        if lines:
                            last_diff = (target, lines)
                hot[target] = (kind, now + 4)
            snap = new
            hot = {p: v for p, v in hot.items() if v[1] > now}

            cols, rows = shutil.get_terminal_size((100, 40))
            tree = render_tree(root, snap, {p: v[0] for p, v in hot.items()})
            log_rows = max(6, rows // 4)
            diff_rows = max(6, rows // 3)
            tree = tree[: max(3, rows - log_rows - diff_rows - 6)]
            name, dl = last_diff
            out = ["\033[H\033[2J", *tree, "",
                   f"{C['b']}── diff {name} {'─' * max(0, cols - 10 - len(name))}{C['x']}"]
            for ln in dl[-diff_rows:]:
                col = C["add"] if ln.startswith("+") else C["del"] if ln.startswith("-") else \
                    C["mov"] if ln.startswith("@@") else C["dim"]
                out.append(f"{col}{ln[:cols]}{C['x']}")
            out += [""] * (diff_rows - len(dl[-diff_rows:])) + [
                   f"{C['b']}── activity {'─' * max(0, cols - 13)}{C['x']}"]
            for ts, kind, text in list(log)[-log_rows:]:
                icon = ICON.get(kind, "·")
                out.append(f"{C['dim']}{ts}{C['x']} {C[kind]}{icon} {text}{C['x']}"[: cols + 20])
            sys.stdout.write("\n".join(out) + "\n")
            sys.stdout.flush()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
