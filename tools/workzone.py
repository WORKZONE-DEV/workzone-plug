"""Work Zone local helper (Phase 7): serves the dashboard and lets it use the Python tools.

  python tools/workzone.py            then open the address it prints

Local only:
  - listens on 127.0.0.1 (this computer only), never the network
  - every API call needs the secret token baked into the page it served
  - refuses requests whose Host or Origin isn't this address (stops other websites
    and DNS tricks from talking to it)
  - dropped files are written only into a fresh scratch folder under WORKZONE_HOME;
    the browser only ever sends copies, so originals can't be touched
  - your signing key lives in WORKZONE_HOME/keys and never leaves this machine
  - risky actions (make a key, sign code, go online, scan or change devices) need a person:
    the page asks you to press and hold, then gets a one-time pass that works once, for that
    action only, for 30 seconds. At most 5 a minute. Strict mode (on unless you switch it off)
    also asks you to type "yes" in this terminal window, which an AI driving the browser can't reach.

Standard library only.
"""
import base64
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import catalog  # noqa: E402
import fit  # noqa: E402
import keys  # noqa: E402
import mcp_bridge  # noqa: E402
import pack  # noqa: E402
import registry  # noqa: E402

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))   # the packed app unpacks here
STATIC = {"ui", "socket"}  # the only folders the helper serves
TOKEN_PAGES = {"ui/index.html", "ui/desktop.html"}   # the only pages handed the token
MAX_BODY = 60 * 1024 * 1024
# Actions that need a person to confirm them, in plain words.
# (/api/build-example is left out on purpose: it only seals the examples shipped in this folder,
#  never code from outside, and it runs every time you open one from the Library.)
RISKY = {
    "/api/key/new": "create your signing key",
    "/api/build": "seal code into a plug with your key",
    "/api/update-check": "check online for a newer version",
    "/api/devices/scan": "scan your home network for devices",
    "/api/devices/set": "change a device switch",
    "/api/catalog": "look up the official plug catalog online (GitHub)",
    "/api/catalog-get": "download an official plug and put it on your shelf",
    "/api/strict": "switch strict mode OFF (risky actions would no longer need you to type yes here)",
}
PASS_LIFE = 30          # seconds a pass stays valid
RATE = 5                # risky actions of one kind per minute, at most
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8", ".json": "application/json", ".svg": "image/svg+xml",
         ".png": "image/png", ".ico": "image/x-icon"}


def home():
    return Path(os.environ.get("WORKZONE_HOME", Path.home() / ".workzone"))


def key_path():
    return home() / "keys" / "workzone.key"


class State:
    def __init__(self, port, clear_drops=True):
        self.port = port
        self.token = secrets.token_urlsafe(24)
        self.drops = {}                        # drop id -> scratch folder
        self.handoffs = {}                     # one-time id -> verified plug bytes (wz run)
        self.lock = threading.Lock()
        self.passes = {}                       # one-time pass -> (action, expires)
        self.catalog = None                    # the last official catalog you opened (checked)
        self.recent = {}                       # action -> times it was confirmed
        self.strict = load_settings().get("strict", True) is not False   # safe by default; only an exact "false" turns it off
        self.asking = False                    # strict mode asks one question at a time
        self.ask = ask_in_terminal             # how strict mode asks you (tests swap this)
        drops = home() / "drops"
        drops.mkdir(parents=True, exist_ok=True)
        # Scratch copies from earlier sessions are not needed any more: clear them on start.
        for old in (drops.iterdir() if clear_drops else []):
            if old.is_dir():
                shutil.rmtree(old, ignore_errors=True)

    def confirm(self, action, code=""):
        """A person confirmed `action`: returns a one-time pass, or raises with a plain reason.
        Every attempt counts toward the limit, refused ones too, and strict mode asks one at a time."""
        now = time.monotonic()
        with self.lock:                                   # check and count in one step
            times = [t for t in self.recent.get(action, []) if now - t < 60]
            if len(times) >= RATE:
                raise PermissionError("too many of these in one minute; wait a moment (this stops runaway loops)")
            if self.strict and self.asking:
                raise PermissionError("Work Zone is already asking something in the terminal; answer that first")
            self.recent[action] = times + [now]
            if self.strict:
                self.asking = True
        if self.strict:
            try:
                ok = self.ask(RISKY[action] + (f" (code {code})" if code else ""))
            finally:
                with self.lock:
                    self.asking = False
            if not ok:
                raise PermissionError('not confirmed in the Work Zone terminal window (strict mode: type "yes" there)')
        with self.lock:
            self.passes = {k: v for k, v in self.passes.items() if v[1] > now}
            p = secrets.token_urlsafe(18)
            self.passes[p] = (action, now + PASS_LIFE)
        print(f"[{time.strftime('%H:%M:%S')}] confirmed: {RISKY[action]}", flush=True)
        return p

    def use_pass(self, p, action):
        """True once for a valid pass for exactly this action; the pass is gone afterwards."""
        with self.lock:
            got = self.passes.pop(p, None) if isinstance(p, str) else None
        return bool(got) and got[0] == action and got[1] > time.monotonic()

    def origin_ok(self, host, origin):
        allowed = {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}
        if host not in allowed:
            return False
        return origin is None or origin in {"http://" + a for a in allowed}


def _safe_rel(p):
    """A dropped file's relative path: forward slashes, no '..', no drive, no absolute."""
    if not isinstance(p, str) or not p or len(p) > 400 or "\0" in p:
        return None
    p = p.replace("\\", "/")
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        return None
    parts = [x for x in p.split("/") if x]
    if any(x in (".", "..") for x in parts) or not parts:
        return None
    for x in parts:
        # Windows traps: device names (CON, NUL, COM1...), names ending in a dot or space
        # (Windows silently renames them), and ':' (alternate data streams).
        if ":" in x or x != x.rstrip(". ") or WINDOWS_RESERVED.match(x):
            return None
    return "/".join(parts)


WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$", re.I)


def save_drop(state, files):
    """Write dropped copies into a new scratch folder. Returns (drop_id, path_to_inspect)."""
    if not isinstance(files, list) or not files or len(files) > pack.MAX_FILES:
        raise ValueError("drop between 1 and 2000 files")
    drop_id = secrets.token_hex(8)
    root = Path(tempfile.mkdtemp(prefix=drop_id + "-", dir=home() / "drops")).resolve()
    total = 0
    rels = []
    for f in files:
        rel = _safe_rel(f.get("path") if isinstance(f, dict) else None)
        if rel is None:
            shutil.rmtree(root, ignore_errors=True)
            raise ValueError("a dropped file had an unsafe path")
        b64 = f.get("b64", "")
        if not isinstance(b64, str):
            shutil.rmtree(root, ignore_errors=True)
            raise ValueError("a dropped file had no readable content")
        try:
            data = base64.b64decode(b64, validate=True)
        except ValueError:
            shutil.rmtree(root, ignore_errors=True)
            raise ValueError("a dropped file had unreadable content")
        total += len(data)
        if total > pack.MAX_TOTAL:
            shutil.rmtree(root, ignore_errors=True)
            raise ValueError("too big: a plug is at most 50 MB")
        try:
            target = (root / rel).resolve()
            if root not in target.parents:
                raise ValueError("a dropped file tried to land outside its folder")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        except (OSError, ValueError) as e:
            shutil.rmtree(root, ignore_errors=True)   # never leave a half-written drop behind
            raise ValueError(str(e) if isinstance(e, ValueError) else "a dropped file name can't be used on this computer")
        rels.append(rel)
    if pack._case_clash(rels):
        shutil.rmtree(root, ignore_errors=True)
        raise ValueError("two dropped files have the same name apart from capitals; on Windows one would overwrite the other")
    # One file dropped -> inspect the file. A folder dropped -> inspect that folder.
    tops = {r.split("/")[0] for r in rels}
    if len(rels) == 1:
        inspect_at = root / rels[0]
    elif len(tops) == 1 and all("/" in r for r in rels):
        inspect_at = root / tops.pop()
    else:
        inspect_at = root
    with state.lock:
        state.drops[drop_id] = inspect_at
        while len(state.drops) > 200:          # remember only the most recent drops
            state.drops.pop(next(iter(state.drops)))
    return drop_id, inspect_at


def hand_off(state, data):
    """Keep a VERIFIED plug for the desktop host to collect once. Returns the one-time id."""
    pack.verify(data)                          # never hand over anything that doesn't pass
    hid = secrets.token_hex(16)
    with state.lock:
        state.handoffs[hid] = data
        while len(state.handoffs) > 20:
            state.handoffs.pop(next(iter(state.handoffs)))
    return hid


def version():
    try:
        return (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "0.0.0"


def _ver(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3])


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect may only go to another public https address, never http, this computer or a home network."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        import ipaddress
        import socket
        from urllib.parse import urlparse
        u = urlparse(newurl)
        if u.scheme != "https" or not u.hostname:
            raise urllib.error.URLError("redirect refused (not https)")
        try:
            for info in socket.getaddrinfo(u.hostname, 443):
                ip = ipaddress.ip_address(info[4][0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified or ip.is_multicast:
                    raise urllib.error.URLError("redirect refused (local address)")
        except socket.gaierror:
            raise urllib.error.URLError("redirect refused (unknown host)")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_SAFE_OPENER = urllib.request.build_opener(_HttpsOnlyRedirects)


DEFAULT_UPDATE = "https://api.github.com/repos/WORKZONE-DEV/workzone-plug/releases/latest"


def update_check():
    """When YOU press "check now": ask this project's GitHub releases (or the address in
    WORKZONE_HOME/update.json) what the newest version is. It only ever tells you; it never
    downloads or installs anything."""
    cfg = home() / "update.json"
    cur = version()
    url = DEFAULT_UPDATE
    if cfg.exists():
        try:
            url = json.loads(cfg.read_text(encoding="utf-8")).get("url", "")
        except (OSError, ValueError):
            return {"current": cur, "configured": False, "error": "update.json isn't readable"}
    if not isinstance(url, str) or not url.startswith("https://"):
        return {"current": cur, "configured": False, "error": "update.json needs an https:// address"}
    try:
        with _SAFE_OPENER.open(urllib.request.Request(url, headers={"User-Agent": "WorkZone"}), timeout=6) as r:
            info = json.loads(r.read(65536))
        latest = str(info.get("version") or info.get("tag_name") or "").lstrip("v")   # our format, or GitHub's
        if not re.fullmatch(r"\d+\.\d+\.\d+", latest):
            raise ValueError("no version number in the answer")
        return {"current": cur, "configured": True, "latest": latest, "newer": _ver(latest) > _ver(cur),
                "notes": str(info.get("notes") or info.get("body") or "")[:500],
                "page": f"https://github.com/{catalog.REPO}/releases/latest"}
    except Exception as e:  # noqa: BLE001 - a failed check is just "couldn't check", never a crash
        return {"current": cur, "configured": True, "error": f"couldn't check ({type(e).__name__})"}


DEVICE_KEYS = re.compile(r"^[a-z0-9][a-z0-9 ._():-]{0,60}$")


def devices_file():
    return home() / "devices.json"


def load_devices():
    """Your devices list (WORKZONE_HOME/devices.json). Each power is a switch you control."""
    f = devices_file()
    if not f.exists():
        return []
    try:
        raw = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for d in raw.get("devices", []) if isinstance(raw, dict) else []:
        if not isinstance(d, dict) or not isinstance(d.get("name"), str) or not isinstance(d.get("powers", {}), dict):
            continue
        powers = {k: bool(v) for k, v in (d.get("powers") or {}).items() if isinstance(k, str) and DEVICE_KEYS.match(k)}
        out.append({"name": d["name"][:60], "kind": str(d.get("kind", "device"))[:30],
                    "driver": str(d.get("driver", ""))[:40], "powers": powers,
                    **{k: str(d[k])[:60] for k in ("address", "maker", "model") if isinstance(d.get(k), str)}})
    return out


def set_device_power(name, power, on, address=None):
    """Flip ONE switch in devices.json, leaving everything else in the file exactly as it was."""
    f = devices_file()
    try:
        raw = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError("devices.json isn't readable")
    for d in raw.get("devices", []) if isinstance(raw, dict) else []:
        if not isinstance(d, dict) or not isinstance(d.get("powers"), dict):
            continue
        same = d.get("address") == address if address else (d.get("name") == name and not d.get("address"))
        if same and isinstance(power, str) and DEVICE_KEYS.match(power) and power in d["powers"]:
            d["powers"][power] = bool(on)
            f.write_text(json.dumps(raw, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            return load_devices()
    raise ValueError("no such device or power")


def shelf():
    """Your registry shelf (WORKZONE_HOME/registry), for the Library. Empty if there isn't one."""
    try:
        newest = {}                                      # one tile per plug: its newest version
        for e in registry.load_index(registry.default_dir())["plugs"]:
            if e["id"] not in newest or registry._ver(e["version"]) > registry._ver(newest[e["id"]]["version"]):
                newest[e["id"]] = e
        return [{k: e[k] for k in ("file", "id", "name", "version", "kind")} for e in newest.values()]
    except (OSError, ValueError, KeyError, TypeError):
        return []


def settings_file():
    return home() / "settings.json"


def load_settings():
    try:
        s = json.loads(settings_file().read_text(encoding="utf-8"))
        return s if isinstance(s, dict) else {}
    except (OSError, ValueError):
        return {}


_answers = None
_ask_lock = threading.Lock()


def ask_in_terminal(what, wait=90):
    """Strict mode: ask the person at this terminal. No terminal, no answer or not "yes" = no."""
    global _answers
    import queue
    if sys.stdin is None or not sys.stdin.isatty():
        return False
    with _ask_lock:                                  # one question at a time
        if _answers is None:
            _answers = queue.Queue()
            threading.Thread(target=lambda: [_answers.put(line) for line in sys.stdin], daemon=True).start()
        while not _answers.empty():                  # ignore anything typed before the question
            _answers.get_nowait()
        print()
        print(f">>> Work Zone asks: {what}.")
        print("    Type yes and press Enter to allow (anything else = no): ", end="", flush=True)
        try:
            return _answers.get(timeout=wait).strip().lower() == "yes"
        except queue.Empty:
            print()
            print("    no answer, so: no.", flush=True)
            return False


def plug_summary(data):
    m, files = pack.verify(data)
    return {"b64": base64.b64encode(data).decode(), "id": m["id"], "name": m["name"], "version": m["version"],
            "kind": m["kind"], "author_key": m["author_key"], "permissions": m["permissions"],
            "files": {n: "sha256:" + pack._sha(b) for n, b in files.items()},
            "manifest": m, "fingerprint": pack._sha(data)[:16]}


def api(state, path, body):
    """Returns (status, dict). Every error is a plain-English message."""
    if path == "/api/confirm":
        action = body.get("action")
        if action not in RISKY:
            return 400, {"error": "that action doesn't need confirming"}
        code = body.get("code", "")
        code = code if isinstance(code, str) and re.fullmatch(r"[A-Z0-9]{4}", code) else ""
        try:
            return 200, {"pass": state.confirm(action, code)}
        except PermissionError as e:
            return 403, {"error": str(e)}
    if path == "/api/strict":
        on = body.get("on") is True
        settings = load_settings()
        settings["strict"] = on
        settings_file().parent.mkdir(parents=True, exist_ok=True)
        settings_file().write_text(json.dumps(settings), encoding="utf-8")
        state.strict = on
        print(f"[{time.strftime('%H:%M:%S')}] strict mode {'ON' if on else 'OFF'}", flush=True)
        return 200, {"strict": on}
    if path == "/api/status":
        kp = key_path()
        return 200, {"has_key": kp.exists(), "strict": state.strict,
                     "public_key": keys.public_key_str(keys.load_seed(kp)) if kp.exists() else None,
                     "examples": sorted(p.name for p in (ROOT / "examples").iterdir() if (p / "plug.json").exists()),
                     "ai_tools": mcp_bridge.offered(), "registry": shelf(), "version": version()}
    if path == "/api/key/new":
        try:
            seed = keys.new_key(key_path())
        except FileExistsError:
            return 409, {"error": "you already have a key; it was left exactly as it is"}
        return 200, {"public_key": keys.public_key_str(seed)}
    if path == "/api/fit":
        drop_id, where = save_drop(state, body.get("files"))
        info = fit.inspect(where)
        info["path"] = where.name   # don't show scratch paths
        return 200, {"drop_id": drop_id, "info": info, "verdict": fit.verdict(info["findings"]), "text": fit.render(info)}
    if path in ("/api/build", "/api/build-example"):
        if not key_path().exists():
            return 400, {"error": "make your key first (menu > Your key); plugs are signed with it", "need_key": True}
        seed = keys.load_seed(key_path())
        if path == "/api/build-example":
            name = body.get("name")
            src = ROOT / "examples" / str(name)
            if not re.fullmatch(r"[a-z0-9-]+", str(name)) or not (src / "plug.json").exists():
                return 404, {"error": "no such example"}
            return 200, plug_summary(pack.build(src, seed))
        drop_id = body.get("drop_id")
        if not isinstance(drop_id, str):
            return 400, {"error": "drop_id must be text"}
        with state.lock:
            where = state.drops.get(drop_id)
        if where is None:
            return 404, {"error": "that drop has expired; drop it again"}
        info = fit.inspect(where)
        if (where / "plug.json").exists():
            out = where                                    # already a plug source
        else:
            out = Path(tempfile.mkdtemp(prefix="port-", dir=home() / "drops")) / "plug"
            fit.port(where, out, info)                     # raises if it doesn't fit
        return 200, plug_summary(pack.build(out, seed, inline=True))
    if path == "/api/ai":
        # Only tools in YOUR mcp.json. The socket has already checked the plug declared it.
        tool, args = body.get("tool"), body.get("args", {})
        if not isinstance(tool, str):
            return 400, {"error": "tool must be text"}
        return 200, {"result": mcp_bridge.call(tool, args)}
    if path == "/api/update-check":
        return 200, update_check()
    if path == "/api/devices":
        import devices                                   # add plain "how to switch it off" steps from device profiles
        profiles, devs = devices.load_profiles(), load_devices()
        for d in devs:
            pr = devices.profile_for(d, profiles)
            if pr:
                d["profile"] = {"brand": pr["brand"], "model": pr["model"], "tested_by": str(pr.get("tested_by", ""))[:60],
                                "how": {k: v["how"][:300] for k, v in pr["powers"].items()}}
        return 200, {"devices": devs}
    if path == "/api/devices/scan":
        import devices                                   # only when YOU press "scan my network"
        added = devices.merge(devices_file(), devices.discover())
        return 200, {"devices": load_devices(), "added": added}
    if path == "/api/devices/set":
        return 200, {"devices": set_device_power(body.get("name"), body.get("power"), body.get("on"), body.get("address"))}
    if path == "/api/catalog":
        try:
            state.catalog = catalog.load(not_older_than=version())
        except (OSError, ValueError) as e:
            return 502, {"error": f"couldn't open the official catalog ({e})"}
        have = {}
        for e in shelf():
            have[e["id"]] = e["version"]
        return 200, {"tag": state.catalog["tag"], "categories": catalog.CATEGORIES,
                     "plugs": [dict(e, installed=have.get(e["id"])) for e in state.catalog["plugs"]]}
    if path == "/api/catalog-get":
        pid = body.get("id")
        if not isinstance(pid, str):
            return 400, {"error": "id must be text"}
        if not state.catalog:
            return 400, {"error": "open the catalog first"}
        try:
            data, _ = catalog.get(state.catalog, pid)      # fingerprint + signature + official key, or refused
        except OSError as e:
            return 502, {"error": f"couldn't download it ({type(e).__name__})"}
        with tempfile.TemporaryDirectory() as d:          # onto your shelf, so it stays in your Library
            f = Path(d) / "official.plug"
            f.write_bytes(data)
            registry.add(f)
        return 200, dict(plug_summary(data), official=True)
    if path == "/api/registry-get":
        f = body.get("file")
        if not isinstance(f, str):
            return 400, {"error": "file must be text"}
        return 200, plug_summary(registry.get(f, verify=False))   # only listed files; plug_summary does the full check
    if path == "/api/handoff":
        hid = body.get("id")
        with state.lock:
            data = state.handoffs.pop(hid, None) if isinstance(hid, str) else None   # collected once, then forgotten
        if data is None:
            return 404, {"error": "that plug was already opened (or never handed over); run it again"}
        return 200, {"b64": base64.b64encode(data).decode()}
    if path == "/api/verify":
        try:
            return 200, {"ok": True, **plug_summary(base64.b64decode(body.get("b64", ""), validate=True))}
        except ValueError as e:
            return 200, {"ok": False, "reason": str(e)}
    return 404, {"error": "unknown request"}


def make_handler(state):
    class H(BaseHTTPRequestHandler):
        server_version = "WorkZone/0"
        timeout = 30          # a caller that stalls mid-request is cut off, not waited on forever

        def log_message(self, *a):
            pass

        def _send(self, status, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(data)

        def _guard(self):
            if not state.origin_ok(self.headers.get("Host"), self.headers.get("Origin")):
                self._send(403, {"error": "only this computer's Work Zone page may talk to the helper"})
                return False
            return True

        def do_GET(self):
            if not self._guard():
                return
            path = self.path.split("?")[0]
            if path in ("/", ""):
                path = "/ui/index.html"
            rel = _safe_rel(path.lstrip("/"))
            if rel is None or rel.split("/")[0] not in STATIC:
                return self._send(404, {"error": "not found"})
            f = (ROOT / rel).resolve()
            if ROOT.resolve() not in f.parents or not f.is_file():
                return self._send(404, {"error": "not found"})
            data = f.read_bytes()
            if rel in TOKEN_PAGES:       # hand our own pages the token; no other page gets it
                data = data.replace(b"__WORKZONE_TOKEN__", state.token.encode())
            self._send(200, data, TYPES.get(f.suffix.lower(), "application/octet-stream"))

        def do_POST(self):
            # Read the (size-limited) request first, THEN answer. Refusing before reading it
            # made Windows drop the connection, so a refusal could arrive as a broken line.
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = -1
            if n < 0 or n > MAX_BODY:
                self.close_connection = True
                return self._send(413, {"error": "too big"})
            raw = self.rfile.read(n) if n else b""
            if not self._guard():
                return
            if not secrets.compare_digest(self.headers.get("X-WorkZone-Token", ""), state.token):
                return self._send(403, {"error": "missing or wrong token"})
            try:
                body = json.loads(raw or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("expected a JSON object")
                path = self.path.split("?")[0]
                turning_on = path == "/api/strict" and body.get("on") is True   # making things safer needs no pass
                if path in RISKY and not turning_on and not state.use_pass(body.pop("pass", None), path):
                    status, out = 403, {"error": "this needs you to confirm it first (press and hold the button)", "need_confirm": True}
                else:
                    status, out = api(state, path, body)
            except (ValueError, FileExistsError) as e:
                status, out = 400, {"error": str(e)}
            except Exception as e:  # noqa: BLE001 - fail closed with a message, never a crash page
                status, out = 500, {"error": f"something went wrong ({type(e).__name__})"}
            self._send(status, out)
    return H


def serve(port=8770, clear_drops=True):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), None)
    state = State(httpd.server_address[1], clear_drops)
    httpd.RequestHandlerClass = make_handler(state)
    return httpd, state


def main(argv):
    port = int(argv[0]) if argv else 8770
    httpd, state = serve(port)
    print(f"Work Zone is running (this computer only): http://127.0.0.1:{state.port}/")
    print("Close this window or press Ctrl+C to stop it.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main(sys.argv[1:])
