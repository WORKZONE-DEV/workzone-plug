"""Plug packer and verifier (Phase 2).

pack:   a plug folder (plug.json + app/) -> one signed NAME.plug file (a zip).
verify: a .plug file -> OK, or the first reason it must not run.

Usage:
  python tools/pack.py pack   SRC_DIR KEYFILE OUT.plug [--inline] [--force]
  python tools/pack.py verify FILE.plug

What is inside a .plug (in this order):
  plug.json   the manifest, with author_key and build.source_hash filled in
  build.json  every app file and its sha256, plus the source hash
  app/...     the app files
  signature   Ed25519 signature (hex) over plug.json + build.json

Why that is enough: build.json lists the hash of every app file, and the
signature covers build.json. Change one byte anywhere and something no
longer matches.

Reproducible: same folder + same key = byte-identical file. Zip dates are
fixed, file order is sorted, and Ed25519 signatures are deterministic.

Verify is FAIL CLOSED: anything
missing, extra, unreadable or unexpected means "do not run". There is no
override flag in verify, on purpose.
"""
import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keys  # noqa: E402
import validate  # noqa: E402

FORMAT = "plug-v0"
FIXED_DATE = (1980, 1, 1, 0, 0, 0)
MAX_TOTAL = 50 * 1024 * 1024      # 50 MB unpacked, stops zip bombs
MAX_FILES = 2000
RECIPE = "tools/pack.py plug-v0"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _canon(obj):
    """One exact byte form for a JSON object, so hashes and signatures are stable."""
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def signed_message(manifest_bytes, build_bytes):
    """What the signature covers. The format tag stops a signature being reused elsewhere."""
    return FORMAT.encode() + b"\n" + hashlib.sha256(manifest_bytes).digest() + hashlib.sha256(build_bytes).digest()


def source_hash(files):
    """files: {path: bytes}. One hash over every path + content."""
    h = hashlib.sha256()
    for p in sorted(files):
        h.update(p.encode("utf-8") + b"\0" + _sha(files[p]).encode() + b"\n")
    return "sha256:" + h.hexdigest()


SAFE_NAME = re.compile(r"[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*")   # same rule as socket/plug-socket.js


def _safe_name(name):
    """A zip entry name we accept: plain ASCII, relative, forward slashes, no '.' or '..'.
    ASCII only, so there are no unicode look-alikes or normalisation collisions (red-team #3)."""
    if not isinstance(name, str) or not SAFE_NAME.fullmatch(name):
        return False
    return all(p not in (".", "..") for p in name.split("/"))


def _case_clash(names):
    """Two names that differ only by upper/lower case overwrite each other on Windows/macOS (red-team #2)."""
    seen = set()
    for n in names:
        k = n.casefold()
        if k in seen:
            return n
        seen.add(k)
    return None


# ---------------------------------------------------------------- inline mode
_SCRIPT = re.compile(r'<script\b([^>]*?)\bsrc\s*=\s*"([^"]+)"([^>]*)>\s*</script>', re.I)
_STYLE = re.compile(r'<link\b[^>]*?\brel\s*=\s*"stylesheet"[^>]*?\bhref\s*=\s*"([^"]+)"[^>]*>|'
                    r'<link\b[^>]*?\bhref\s*=\s*"([^"]+)"[^>]*?\brel\s*=\s*"stylesheet"[^>]*>', re.I)
# After inlining, NOTHING may still point outside the plug, however it is quoted (red-team #1).
# Any src/href/action/url()/@import whose value starts with a scheme (except data:) or // is refused.
_LEFTOVER = re.compile(
    r"""(?:\b(?:src|href|action|formaction|poster|srcset|background)\s*=\s*["']?\s*|url\(\s*["']?\s*|@import\s+["']?\s*)"""
    r"""(?!data:)((?:[a-z][a-z0-9+.-]*:|//|\\\\)[^"'\s>)]*)""", re.I)


def inline_html(html, read):
    """Fold local <script src="..."> and <link rel="stylesheet"> into the page.
    Deny by default: any reference to anything outside the plug that is left over is refused.
    (Runtime is covered too: the socket's CSP blocks network loads whatever the HTML says.)"""
    def local(ref):
        if re.match(r"^[a-z][a-z0-9+.-]*:|^//", ref, re.I):
            raise ValueError(f"inline: remote resource {ref!r} is not allowed (deny by default)")
        return read(ref)

    def script(m):
        body = local(m.group(2)).decode("utf-8").replace("</script", "<\\/script")
        return f"<script{m.group(1)}{m.group(3)}>{body}</script>"

    def style(m):
        body = local(m.group(1) or m.group(2)).decode("utf-8").replace("</style", "<\\/style")
        return f"<style>{body}</style>"

    out = _STYLE.sub(style, _SCRIPT.sub(script, html))
    left = _LEFTOVER.search(out)
    if left:
        raise ValueError(f"inline: outside reference {left.group(1)[:80]!r} is not allowed (deny by default)")
    return out


# ---------------------------------------------------------------- pack
def collect(src):
    """Read plug.json + every file under app/. Refuses symlinks and anything outside app/."""
    src = Path(src)
    manifest = json.loads((src / "plug.json").read_text(encoding="utf-8"))
    app = src / "app"
    real_app = app.resolve()
    files = {}
    for f in sorted(app.rglob("*")):
        if f.is_symlink():
            raise ValueError(f"{f}: symlinks are not allowed in a plug")
        # Windows junctions are not symlinks to Python 3.11, but they still point elsewhere.
        # Anything whose real location is outside app/ is refused (red-team).
        if real_app not in f.resolve().parents:
            raise ValueError(f"{f}: really lives outside app/ (a shortcut or junction), not allowed in a plug")
        if f.is_file():
            rel = f.relative_to(app).as_posix()
            if not _safe_name(rel):
                raise ValueError(f"{rel}: unsafe file name")
            files[rel] = f.read_bytes()
    clash = _case_clash(files)
    if clash:
        raise ValueError(f"{clash}: another file has the same name apart from upper/lower case")
    return manifest, files


def build(src, seed, inline=False):
    """Return the .plug bytes for folder src, signed with seed."""
    manifest, files = collect(src)
    entry = manifest.get("entry")
    if entry not in files:
        raise ValueError(f"entry {entry!r} is not a file in app/")
    if inline:
        if not entry.endswith(".html"):
            raise ValueError("--inline needs an .html entry")
        base = PurePosixPath(entry).parent
        folded = set()

        def read(ref):
            p = str(base / ref) if str(base) != "." else ref
            if not _safe_name(p) or p not in files:
                raise ValueError(f"inline: {ref!r} not found in app/")
            folded.add(p)
            return files[p]
        page = inline_html(files[entry].decode("utf-8"), read).encode("utf-8")
        # Scripts and styles now live inside the page. Everything else (pictures, sounds,
        # WebAssembly, data files) stays in the plug: the socket folds those in when it runs.
        files = {n: b for n, b in files.items() if n not in folded}
        files[entry] = page

    manifest = dict(manifest)
    manifest["author_key"] = keys.public_key_str(seed)
    manifest["build"] = {"source_hash": source_hash(files), "recipe": RECIPE}
    errors = validate.validate(manifest)
    if errors:
        raise ValueError("manifest is not valid:\n  - " + "\n  - ".join(errors))

    build_info = {"format": FORMAT, "source_hash": manifest["build"]["source_hash"],
                  "files": {p: "sha256:" + _sha(b) for p, b in sorted(files.items())}}
    m_bytes, b_bytes = _canon(manifest), _canon(build_info)
    sig = keys.sign(seed, signed_message(m_bytes, b_bytes)).hex().encode() + b"\n"

    return _zip(m_bytes, b_bytes, files, sig)


def _zip(m_bytes, b_bytes, files, sig):
    """The one and only byte layout of a plug. verify() rebuilds with this and compares."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        def put(name, data):
            info = zipfile.ZipInfo(name, FIXED_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            info.create_system = 3
            z.writestr(info, data, compresslevel=9)
        put("plug.json", m_bytes)
        put("build.json", b_bytes)
        for p in sorted(files):
            put("app/" + p, files[p])
        put("signature", sig)
    return out.getvalue()


def refuse_if_different(out_path, new_bytes, force=False):
    """Rule: never silently replace a different existing file."""
    out_path = Path(out_path)
    if out_path.exists() and out_path.read_bytes() != new_bytes and not force:
        raise SystemExit(f"REFUSING TO WRITE {out_path}: a different plug is already there. "
                         "Bump the version or pass --force if you really mean to replace it.")


# ---------------------------------------------------------------- verify
def verify(data):
    """Return (manifest, files) if the plug is good. Raise ValueError with a plain reason if not.

    Fail closed: ANY unexpected error while reading (corrupt zip, bad CRC,
    decompression error, wrong types) becomes a rejection, never a crash that
    a caller might catch and carry on from.
    """
    try:
        return _verify(data)
    except ValueError:
        raise
    except Exception as e:  # noqa: BLE001 - deliberate: unknown problem = reject
        raise ValueError(f"unreadable or corrupt plug ({type(e).__name__})")


def _verify(data):
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ValueError("not a plug (not a readable zip)")
    infos = z.infolist()
    names = [i.filename for i in infos]
    if len(names) != len(set(names)):
        raise ValueError("duplicate entries in the zip (a classic trick to show one file and run another)")
    if len(infos) > MAX_FILES + 3:
        raise ValueError("too many files")
    if sum(i.file_size for i in infos) > MAX_TOTAL:
        raise ValueError("too big when unpacked")
    for n in names:
        if not _safe_name(n):
            raise ValueError(f"unsafe path in zip: {n!r}")
    if _case_clash(names):
        raise ValueError("two files differ only by upper/lower case")
    for required in ("plug.json", "build.json", "signature"):
        if required not in names:
            raise ValueError(f"missing {required}")

    def read(name):
        with z.open(name) as f:
            b = f.read(MAX_TOTAL + 1)
        if len(b) > MAX_TOTAL:
            raise ValueError("too big when unpacked")
        return b

    m_bytes, b_bytes = read("plug.json"), read("build.json")
    try:
        manifest = json.loads(m_bytes.decode("utf-8"))
        build_info = json.loads(b_bytes.decode("utf-8"))
        sig = bytes.fromhex(read("signature").decode("ascii").strip())
    except (ValueError, UnicodeDecodeError):
        raise ValueError("plug.json, build.json or signature is unreadable")
    if not isinstance(manifest, dict) or not isinstance(build_info, dict):
        raise ValueError("plug.json and build.json must be JSON objects")
    # One exact text form (same rule as the JS socket): kills duplicate keys, BOMs, odd
    # whitespace and number spellings, so both checkers always see the same thing.
    if _canon(manifest) != m_bytes or _canon(build_info) != b_bytes:
        raise ValueError("plug.json or build.json is not in canonical form")
    if not re.fullmatch(rb"[0-9a-f]{128}\n", read("signature")):
        raise ValueError("signature is not in canonical form")

    # Layer 1, the LOCK: every file listed, every hash matches, nothing extra, nothing missing.
    # (Cheap checks run first; nothing is trusted until ALL layers pass.)
    listed = build_info.get("files")
    if build_info.get("format") != FORMAT or not isinstance(listed, dict):
        raise ValueError("build.json is not plug-v0")
    app_names = {n[4:] for n in names if n.startswith("app/")}
    others = set(names) - {"plug.json", "build.json", "signature"} - {"app/" + a for a in app_names}
    if others:
        raise ValueError(f"unexpected entries: {sorted(others)}")
    if app_names != set(listed):
        raise ValueError(f"files do not match build.json (extra: {sorted(app_names - set(listed))}, "
                         f"missing: {sorted(set(listed) - app_names)})")
    files = {}
    for p in sorted(app_names):
        b = read("app/" + p)
        if "sha256:" + _sha(b) != listed[p]:
            raise ValueError(f"app/{p} was changed (hash mismatch)")
        files[p] = b
    if source_hash(files) != build_info.get("source_hash") or \
            build_info.get("source_hash") != (manifest.get("build") or {}).get("source_hash"):
        raise ValueError("source hash mismatch")
    # Layer 2, the KEY: the author's signature over plug.json + build.json (which holds the lock).
    if not keys.verify(manifest.get("author_key"), signed_message(m_bytes, b_bytes), sig):
        raise ValueError("signature does not match (changed after signing, or signed by someone else)")
    errors = validate.validate(manifest)
    if errors:
        raise ValueError("manifest invalid: " + "; ".join(errors))
    if manifest["entry"] not in files:
        raise ValueError("entry file missing")
    # Layer 3, the MOULD: packing is reproducible, so re-pack what we just checked and demand
    # the exact same bytes. This catches changes to zip bookkeeping (dates, attributes, extra
    # fields, comments) that no hash above covers. A plug has exactly one valid byte form.
    # The signature is re-written in its one form (lowercase hex + newline), so an upper-case
    # copy of a valid signature is a different file and is refused (red-team #4).
    if _zip(m_bytes, b_bytes, files, sig.hex().encode() + b"\n") != data:
        raise ValueError("file is not in canonical form (zip was altered or re-packed)")
    return manifest, files


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    flags = {a for a in argv if a.startswith("--")}
    if len(args) == 4 and args[0] == "pack":
        data = build(args[1], keys.load_seed(args[2]), inline="--inline" in flags)
        refuse_if_different(args[3], data, force="--force" in flags)
        Path(args[3]).write_bytes(data)
        print(f"packed {args[3]}  ({len(data)} bytes, sha256 {_sha(data)[:16]}...)")
        return 0
    if len(args) == 2 and args[0] == "verify":
        try:
            manifest, files = verify(Path(args[1]).read_bytes())
        except ValueError as e:
            print(f"REJECTED {args[1]}: {e}")
            return 1
        print(f"OK {manifest['id']} {manifest['version']} by {manifest['author_key'][:20]}... ({len(files)} file(s))")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
