"""Fit checker: drop in any file or folder and find out, in plain English, whether it
fits in a plug, why not, and how to fix it. Before you change anything.

READ-ONLY on what you give it. It never edits, moves or deletes your original.
(Too many people only find out a change won't work AFTER making it, and lose
work. Check first, then change.)

Usage:
  python tools/fit.py PATH                 report only
  python tools/fit.py PATH --port OUT      also copy it into a NEW plug folder OUT
                                           (app/ + a draft plug.json), ready to pack
Exit: 0 = fits, 1 = fits with changes needed, 2 = does not fit.
"""
import json
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pack  # noqa: E402
import validate  # noqa: E402

OK, WARN, STOP = "OK", "WARN", "STOP"
ICON = {OK: "[ok]  ", WARN: "[fix] ", STOP: "[no]  "}
WEB_TEXT = {".html", ".htm", ".js", ".mjs", ".css", ".json", ".svg", ".txt", ".md"}
WEB_BIN = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".ogg", ".wav", ".mp4", ".webm", ".wasm", ".glb",
           ".wad", ".bin", ".csv", ".ogv", ".m4a"}   # data a plug reads with plugFile() (game levels, tables...)
NEVER = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".msi", ".scr", ".com", ".vbs", ".sh", ".app", ".apk", ".jar"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode"}
URL = re.compile(r"""(?:https?:)?//([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})""", re.I)

# (pattern, level, title, why, fix). Checked against every web text file.
RULES = [
    (r"\blocalStorage\b|\bsessionStorage\b|\bindexedDB\b|document\.cookie",
     WARN, "saves data in the browser", "a plug runs boxed in, so browser storage and cookies are blocked",
     "use the socket's storage: send {topic:'storage.set', key, value} and add \"storage\": \"1MB\" to permissions"),
    (r"\blocation\s*\.\s*(?:href\s*=(?!=)|assign\s*\(|replace\s*\()|\blocation\s*=(?!=)|<meta\b[^>]*http-equiv\s*=\s*[\"']?refresh",
     STOP, "sends the page somewhere else (redirect / location.href)", "a plug that navigates away is treated as trying to escape, and the watchdog pulls it",
     "keep everything on one page: show and hide sections instead of changing pages"),
    (r"target\s*=\s*[\"']?_(?:blank|top|parent)|navigator\.sendBeacon",
     WARN, "opens links in new tabs or sends background pings", "new tabs and background pings are blocked inside a plug",
     "show the link as text for the user to copy, or ask the host to open it with an event"),
    (r"@import\s+(?:url\()?\s*[\"']?(?!data:)[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?!(?:css|js|mjs|html?|json|svg|png|jpe?g|gif|webp|woff2?|ttf)\b)[a-z]{2,}[/\"')]",
     WARN, "loads a style sheet from another site (@import)", "outside style sheets are blocked",
     "download the CSS into the folder and point @import at the local file"),
    (r"\beval\s*\(|new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*['\"`]",
     WARN, "builds code from text (eval / new Function)", "the plug's safety rules (CSP) block running text as code",
     "rewrite that part as normal functions; many libraries have a 'no eval' or 'CSP' build"),
    (r"\bfetch\s*\(|XMLHttpRequest|axios\.|new\s+WebSocket|new\s+EventSource",
     WARN, "talks to the internet directly", "direct network calls are blocked; everything goes through the gateway",
     "send {topic:'net.fetch', url, id} to the socket instead, and list each host under permissions.network"),
    (r"\bwindow\.open\s*\(|\balert\s*\(|\bconfirm\s*\(|\bprompt\s*\(",
     WARN, "opens pop-ups or alert boxes", "pop-ups and browser alert boxes are blocked inside a plug",
     "show messages inside the page instead (a small div), or ask the host with an event"),
    (r"\b(?:parent|top|opener)\s*\.\s*(?:document|location|window)",
     STOP, "reaches into the page around it", "a plug can never read or change the host page; that is the whole point of the box",
     "talk to the host only with parent.postMessage({topic: ...}, '*') and declared events"),
    (r"<iframe\b|<frame\b|<object\b|<embed\b",
     WARN, "puts frames inside itself", "frames inside a plug are blocked (they could be used to sneak out)",
     "show that content directly, or make it its own plug"),
    (r"<form\b[^>]*\baction\s*=",
     WARN, "has a form that submits somewhere", "form submissions are blocked",
     "handle the form in JavaScript and send the data with net.fetch to a declared host"),
    (r"serviceWorker|new\s+(?:Shared)?Worker\s*\(",
     WARN, "uses background workers", "workers and service workers are blocked in a plug (v0)",
     "run that code on the main page for now"),
    (r"RTCPeerConnection|getUserMedia|geolocation|Notification\.requestPermission|navigator\.(?:bluetooth|usb|serial|hid)",
     STOP, "uses camera, microphone, location, notifications, peer-to-peer or device access",
     "a plug gets none of these, on purpose (privacy first)",
     "leave that feature out of the plug, or wait for a permission type for it"),
    (r"<script\b[^>]*\btype\s*=\s*[\"']module[\"'][^>]*\bsrc\s*=|(?:^|[\s;>{}])import\s+[\w{*$][^;\n]*?\sfrom\s+['\"]|(?:^|[\s;>{}])import\s*\(\s*['\"]|\brequire\s*\(\s*['\"]",
     WARN, "is split into modules (import / require)", "the packer can fold plain script files into one page, but not module imports",
     "bundle it into one file first (for example with esbuild or your framework's build), then run fit on the output"),
]


def finding(level, title, why="", fix="", where=""):
    return {"level": level, "title": title, "why": why, "fix": fix, "where": where}


def _walk(root):
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        yield p


def _read_text(p):
    try:
        return p.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def inspect(path):
    """Look at PATH (never changes it). Returns {kind, entry, files, findings, hosts}."""
    path = Path(path)
    out = {"path": str(path), "kind": "?", "entry": None, "files": [], "findings": [], "hosts": []}
    F = out["findings"]
    if not path.exists():
        F.append(finding(STOP, "nothing there", f"{path} does not exist", "check the path"))
        return out

    # ---- single file
    if path.is_file():
        ext = path.suffix.lower()
        if ext == ".plug":
            out["kind"] = "a packed plug"
            try:
                m, files = pack.verify(path.read_bytes())
                F.append(finding(OK, f"already a valid plug: {m['id']} {m['version']}", "signature, fingerprints and shape all check out"))
            except ValueError as e:
                F.append(finding(STOP, "a plug file, but it fails verification", str(e), "re-pack it from its source folder"))
            return out
        if ext in NEVER:
            out["kind"] = "a program or script for your computer"
            F.append(finding(STOP, f"{ext} files can never go in a plug",
                             "plugs run in a sandbox and never run programs on your computer; that's a safety rule, not a missing feature",
                             "if it's a tool you need, it can be wrapped as a service later (Phase 8 adapters), outside any plug"))
            return out
        if ext == ".py":
            out["kind"] = "Python code"
            F.append(finding(STOP, "Python can't run inside a browser plug (yet)",
                             "plugs run in a browser box, which runs JavaScript and WebAssembly",
                             "two routes: run it as a local service the host talks to, or compile it to WebAssembly (Phase 8 adapter)"))
            return out
        if ext == ".zip":
            out["kind"] = "a zip archive"
            F.append(finding(WARN, "a zip, not a plug", "fit won't open archives (that's how nasty surprises get in)",
                             "unzip it into a folder yourself, then run fit on that folder"))
            return out
        if ext in (".html", ".htm"):
            out["kind"] = "a single web page"
            out["entry"] = path.name
            out["files"] = [path.name]
            _check_web(path.parent, [path], out)
            return out
        if ext in (".js", ".mjs", ".css"):
            out["kind"] = "a " + ("script" if ext != ".css" else "style sheet") + " on its own"
            F.append(finding(WARN, "needs a page to live in", "a plug starts from an HTML page",
                             "use --port: fit will wrap it in a simple index.html for you"))
            _check_web(path.parent, [path], out)
            return out
        out["kind"] = f"a {ext or 'no-extension'} file"
        if ext in WEB_BIN:
            F.append(finding(WARN, "a media file on its own", "a plug needs a page to show it", "use --port to wrap it in a page"))
        else:
            F.append(finding(STOP, "not something a web plug can use", f"{ext or 'this file type'} isn't a web format",
                             "convert it to a web format (HTML, JS, CSS, images, audio, video, WASM) first"))
        return out

    # ---- folder
    out["kind"] = "a folder"
    files = [p for p in _walk(path) if p.is_file() or p.is_symlink()]
    rels = [p.relative_to(path).as_posix() for p in files]
    out["files"] = rels
    if (path / "plug.json").exists():
        out["kind"] = "a plug source folder"
        errs = validate.validate_file(path / "plug.json")
        if errs:
            for e in errs:
                F.append(finding(STOP, "plug.json has a problem", e, "fix that line in plug.json"))
        else:
            F.append(finding(OK, "plug.json is valid"))
    pkg = path / "package.json"
    if pkg.exists():
        built = [d for d in ("dist", "build", "out", "public") if (path / d / "index.html").exists()]
        out["kind"] = "a JavaScript project (npm)"
        F.append(finding(WARN, "this is source code that needs building first",
                         "npm projects (React, Vue, Svelte...) are turned into plain files by a build step",
                         f"run fit on the built folder: {path / built[0]}" if built else "run its build (usually `npm run build`), then run fit on the output folder (dist/ or build/)"))
    real_root = path.resolve()
    for p in files:
        rel = p.relative_to(path).as_posix()
        if p.is_symlink() or real_root not in p.resolve().parents:
            F.append(finding(STOP, "contains a shortcut (symlink or junction)", "it points to a file outside this folder, which would sneak outside files into the plug",
                             "replace it with a real copy of the file, or leave it out", rel))
        elif p.suffix.lower() in NEVER:
            F.append(finding(STOP, "contains a program or script for your computer", "plugs never carry programs", "remove it from the plug folder", rel))
    F.extend(name_findings([r[4:] if r.startswith("app/") else r for r in rels]))
    total = sum(p.stat().st_size for p in files if p.is_file())
    if total > pack.MAX_TOTAL:
        F.append(finding(STOP, "too big", f"{total // (1024 * 1024)} MB; a plug is at most {pack.MAX_TOTAL // (1024 * 1024)} MB", "leave out large media or split it into several plugs"))
    base = path / "app" if (path / "app").is_dir() else path
    htmls = [p for p in files if p.suffix.lower() in (".html", ".htm") and base in p.parents or p.parent == base and p.suffix.lower() in (".html", ".htm")]
    entry = None
    for name in ("index.html", "index.htm"):
        if (base / name).is_file():
            entry = base / name
    if entry is None and htmls:
        entry = htmls[0]
        F.append(finding(WARN, f"no index.html, so {entry.name} would be the start page", "", "rename your main page to index.html to be sure"))
    if entry is None and not pkg.exists():
        F.append(finding(STOP, "no web page to start from", "a plug starts from an HTML page", "add an index.html (or use --port on a single script)"))
    if entry is not None:
        out["entry"] = entry.relative_to(base).as_posix()
    _check_web(base, [p for p in files if p.is_file() and p.suffix.lower() in WEB_TEXT], out)
    others = [p for p in files if p.is_file() and p.suffix.lower() not in WEB_TEXT | WEB_BIN | NEVER and p.name != "plug.json"]
    for p in others[:10]:
        F.append(finding(WARN, "a file the plug probably can't use", f"{p.suffix or 'no extension'} isn't a web format", "leave it out of the plug", p.relative_to(path).as_posix()))
    webfiles = [p for p in files if p.is_file() and p.suffix.lower() in WEB_TEXT | WEB_BIN]
    if len(webfiles) > 1:
        F.append(finding(OK, f"{len(webfiles)} files: all of them get sealed into the one plug file",
                         "scripts, style sheets, images, fonts and media are fingerprinted and signed together"))
    return out


def name_findings(names):
    """Problems with a list of file names (no disk needed, so it's testable on every computer)."""
    out = []
    for r in names:
        if r == "plug.json":
            continue
        if not pack._safe_name(r):
            out.append(finding(WARN, "a file name needs changing", "plug file names use plain letters, digits, . _ - only (no spaces or accents), so every computer reads them the same",
                               "rename it, e.g. " + re.sub(r"[^A-Za-z0-9._/-]", "-", r), r))
    clash = pack._case_clash([n for n in names if n != "plug.json"])
    if clash:
        out.append(finding(STOP, "two files have the same name apart from capitals", "on Windows and Mac one would overwrite the other", "rename one of them", clash))
    return out


def _check_web(base, paths, out):
    F, hosts = out["findings"], set(out["hosts"])
    seen = set()
    for p in paths:
        text = _read_text(p)
        if text is None:
            continue
        rel = p.name if p.parent == base else p.relative_to(base).as_posix() if base in p.parents else p.name
        for pattern, level, title, why, fix in RULES:
            m = re.search(pattern, text, re.I | re.M)
            if m and (title, rel) not in seen:
                seen.add((title, rel))
                line = text.count("\n", 0, m.start()) + 1
                F.append(finding(level, title, why, fix, f"{rel} line {line}"))
        for m in URL.finditer(text):
            h = m.group(1).lower().rstrip(".")
            if h not in ("www.w3.org",):   # namespace strings in SVG/XHTML, not real requests
                hosts.add(h)
    out["hosts"] = sorted(hosts)
    if out["hosts"]:
        F.append(finding(WARN, "mentions outside web addresses: " + ", ".join(out["hosts"][:8]) + ("..." if len(out["hosts"]) > 8 else ""),
                         "anything loaded from outside is blocked unless you list the host and it goes through the gateway",
                         "either copy those files into the folder (best, works offline), or list the hosts under permissions.network"))


def verdict(findings):
    levels = {f["level"] for f in findings}
    return STOP if STOP in levels else WARN if WARN in levels else OK


def draft_manifest(path, info):
    name = re.sub(r"[^A-Za-z0-9 ]+", " ", Path(path).stem).strip() or "My Plug"
    slug = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-") or "my-plug"
    perms = {"ui": "panel"}
    if any("saves data" in f["title"] for f in info["findings"]):
        perms["storage"] = "1MB"
    if info["hosts"]:
        perms["network"] = [h for h in info["hosts"] if validate.HOSTNAME.match(h)][:20]
    return {
        "plug": "0", "id": f"zone.work.{slug}", "name": name[:60], "version": "0.1.0",
        "kind": "tool", "entry": info["entry"] or "index.html", "views": ["panel"], "hosts": ["any"],
        "permissions": perms,
        "author_key": "ed25519:" + "0" * 64,
        "description": "Draft made by tools/fit.py. Check the permissions before you pack it."[:280],
    }


def port(src, out_dir, info):
    """Copy (never move) src into a NEW folder out_dir as a plug source. Returns out_dir."""
    src, out_dir = Path(src).resolve(), Path(out_dir).resolve()
    if out_dir.exists():
        raise FileExistsError(f"{out_dir} already exists; pick a new folder so nothing gets overwritten")
    if src.is_dir() and (out_dir == src or src in out_dir.parents):
        raise ValueError("the new folder can't be inside the one you're checking")
    if verdict(info["findings"]) == STOP:
        raise ValueError("it doesn't fit yet; fix the [no] items first")
    app = out_dir / "app"
    app.mkdir(parents=True)
    if src.is_file():
        if src.suffix.lower() in (".html", ".htm"):
            shutil.copy2(src, app / "index.html")
            info["entry"] = "index.html"
        elif src.suffix.lower() in (".js", ".mjs"):
            shutil.copy2(src, app / src.name)
            (app / "index.html").write_text(f'<!doctype html>\n<meta charset="utf-8">\n<title>{src.stem}</title>\n<script src="{src.name}"></script>\n', encoding="utf-8")
            info["entry"] = "index.html"
        elif src.suffix.lower() == ".css":
            shutil.copy2(src, app / src.name)
            (app / "index.html").write_text(f'<!doctype html>\n<meta charset="utf-8">\n<link rel="stylesheet" href="{src.name}">\n<p>Styled page</p>\n', encoding="utf-8")
            info["entry"] = "index.html"
        else:
            shutil.copy2(src, app / src.name)
    else:
        base = src / "app" if (src / "app").is_dir() else src
        real_base = base.resolve()
        skip = shutil.ignore_patterns(*SKIP_DIRS, "plug.json", *("*" + e for e in NEVER))

        def ignore(d, names):
            out = set(skip(d, names))
            for n in names:   # never follow a shortcut/junction out of the folder
                q = Path(d) / n
                if q.is_symlink() or (q.resolve() != real_base and real_base not in q.resolve().parents):
                    out.add(n)
            return out
        shutil.copytree(base, app, dirs_exist_ok=True, symlinks=True, ignore=ignore)
    manifest = draft_manifest(src, info)
    (out_dir / "plug.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return out_dir


def render(info):
    lines = [f"Checked: {info['path']}", f"It looks like: {info['kind']}"]
    if info["entry"]:
        lines.append(f"Start page: {info['entry']}")
    lines.append("")
    order = {STOP: 0, WARN: 1, OK: 2}
    for f in sorted(info["findings"], key=lambda f: order[f["level"]]):
        lines.append(ICON[f["level"]] + f["title"] + (f"   ({f['where']})" if f["where"] else ""))
        if f["why"]:
            lines.append("       why: " + f["why"])
        if f["fix"]:
            lines.append("       fix: " + f["fix"])
    v = verdict(info["findings"])
    lines.append("")
    lines.append({OK: "VERDICT: fits. You can pack it as it is.",
                  WARN: "VERDICT: fits after the [fix] items. Nothing here is a dead end.",
                  STOP: "VERDICT: doesn't fit yet. Start with the [no] items."}[v])
    lines.append("(Your original was only read, never changed.)")
    return "\n".join(lines)


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 2
    info = inspect(args[0])
    print(render(info))
    if "--port" in argv:
        i = argv.index("--port")
        if i + 1 >= len(argv):
            print("\n--port needs a NEW folder name")
            return 2
        try:
            out = port(args[0], argv[i + 1], info)
        except (ValueError, FileExistsError) as e:
            print(f"\nNot ported: {e}")
            return 2
        errs = validate.validate_file(out / "plug.json")
        print(f"\nPorted a COPY to {out}")
        print("  plug.json draft: " + ("valid" if not errs else "needs attention: " + "; ".join(errs)))
        print(f"  next: check the permissions in {out / 'plug.json'}, then")
        print(f"        python tools/pack.py pack {out} YOUR.key {out.name}.plug --inline")
    return {OK: 0, WARN: 1, STOP: 2}[verdict(info["findings"])]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
