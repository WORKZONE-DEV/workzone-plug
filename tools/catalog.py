"""Official plug catalog: plugs signed by the Work Zone official key, pulled in one click.

Every pull is checked three ways before anything runs:
  1. the file's fingerprint (sha256) matches the catalog entry
  2. it passes every check of the verifier (lock, key, mould) and its signature is valid
  3. it was signed by the official Work Zone key built into this program
So a changed catalog or a changed download can't slip in a plug nobody official signed.
Downloads only come from this project's GitHub releases (https, fixed hosts, size-limited).

  python tools/catalog.py build OUT_DIR KEY_FILE TAG   sign the official plugs + write catalog.json (the release build)
  python tools/catalog.py verify DIR                   check a built catalog folder with the same rules
"""
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keys  # noqa: E402
import pack  # noqa: E402

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
OFFICIAL_KEY = "ed25519:795ba792ff5ea4c073e6928f39e67507def3518e00935b0b97ba4c9a79cda0be"
REPO = "WORKZONE-DEV/workzone-plug"
CATALOG_URL = f"https://github.com/{REPO}/releases/latest/download/catalog.json"
HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
MAX_CATALOG = 256 * 1024
MAX_PLUG = 64 * 1024 * 1024
FILE_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,80}\.plug$")
TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
POWERS = {"network", "storage", "events", "identity", "ai"}
CATEGORIES = ["Everyday", "Games", "Music", "Media", "Creative", "Info", "Developer", "Starter"]


class _OnlyOurHosts(urllib.request.HTTPRedirectHandler):
    """Downloads may only be redirected to GitHub's own https download hosts."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed(newurl):
            raise urllib.error.URLError("redirect refused (not a GitHub download address)")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def allowed(url):
    u = urlparse(url)
    return u.scheme == "https" and u.hostname in HOSTS and not u.username and not u.password and u.port in (None, 443)


_OPENER = urllib.request.build_opener(_OnlyOurHosts)


def fetch(url, limit):
    """GET from GitHub's download hosts only, refusing anything bigger than `limit` bytes."""
    if not allowed(url):
        raise ValueError("only this project's GitHub downloads are allowed")
    with _OPENER.open(urllib.request.Request(url, headers={"User-Agent": "WorkZone"}), timeout=20) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError("the download is bigger than allowed")
    return data


def check_catalog(cat):
    """A catalog file -> list of plain problems (empty = good)."""
    p = []
    if not isinstance(cat, dict) or cat.get("catalog") != "0":
        return ["not a Work Zone catalog"]
    if not isinstance(cat.get("tag"), str) or not TAG_RE.match(cat["tag"]):
        p.append("the catalog has no proper release tag")
    plugs = cat.get("plugs")
    if not isinstance(plugs, list) or not plugs:
        return p + ["the catalog lists no plugs"]
    seen = set()
    for e in plugs:
        if not isinstance(e, dict):
            p.append("an entry isn't an object")
            continue
        for k in ("id", "name", "version", "category", "description", "file", "sha256"):
            if not isinstance(e.get(k), str):
                p.append(f"an entry is missing {k}")
        if p:
            continue
        if not FILE_RE.match(e["file"]):
            p.append(f"{e['id']}: odd file name")
        if not SHA_RE.match(e["sha256"]):
            p.append(f"{e['id']}: odd fingerprint")
        if e["category"] not in CATEGORIES:
            p.append(f"{e['id']}: unknown category")
        if not isinstance(e.get("size"), int) or not 0 < e["size"] <= MAX_PLUG:
            p.append(f"{e['id']}: odd size")
        pw = e.get("powers")
        if not isinstance(pw, list) or not all(isinstance(x, str) and x in POWERS for x in pw):
            p.append(f"{e['id']}: odd powers list")
        if e["id"] in seen:
            p.append(f"{e['id']}: listed twice")
        seen.add(e["id"])
    return p


def _ver(v):
    return tuple(int(x) for x in v.lstrip("v").split("."))


def load(url=CATALOG_URL, not_older_than=None):
    """Download and check the catalog list. A catalog older than this program is refused, so an old
    catalog can't be used to hand out old versions again."""
    cat = json.loads(fetch(url, MAX_CATALOG))
    problems = check_catalog(cat)
    if problems:
        raise ValueError("the catalog didn't pass its check: " + problems[0])
    if not_older_than and _ver(cat["tag"]) < _ver(not_older_than):
        raise ValueError(f"the catalog ({cat['tag']}) is older than this Work Zone ({not_older_than}); refused")
    return cat


def plug_url(cat, entry):
    return f"https://github.com/{REPO}/releases/download/{cat['tag']}/{entry['file']}"


def verify_official(data, entry):
    """All three checks. Returns the verified label, or raises ValueError with a plain reason."""
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("the download's fingerprint doesn't match the catalog (refused)")
    m, _ = pack.verify(data)
    if m["author_key"] != OFFICIAL_KEY:
        raise ValueError("it wasn't signed by the official Work Zone key (refused)")
    if m["id"] != entry["id"] or m["version"] != entry["version"]:
        raise ValueError("the plug inside isn't the one the catalog promised (refused)")
    return m


def get(cat, plug_id):
    """Download one official plug from the catalog and verify it. Returns (bytes, label)."""
    entry = next((e for e in cat["plugs"] if e["id"] == plug_id), None)
    if entry is None:
        raise ValueError("that plug isn't in the official catalog")
    data = fetch(plug_url(cat, entry), min(entry["size"], MAX_PLUG))
    return data, verify_official(data, entry)


def official_list():
    """The official plugs and their categories, in order (examples/catalog.json)."""
    return json.loads((ROOT / "examples" / "catalog.json").read_text(encoding="utf-8"))["plugs"]


def build(out, key_file, tag):
    """Sign every official plug with the official key and write catalog.json next to them."""
    if not TAG_RE.match(tag):
        raise ValueError("tag must look like v1.17.0")
    seed = keys.load_seed(Path(key_file))
    if keys.public_key_str(seed) != OFFICIAL_KEY:
        raise ValueError("that isn't the official Work Zone key")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    entries = []
    for item in official_list():
        data = pack.build(ROOT / "examples" / item["folder"], seed)
        m, _ = pack.verify(data)
        name = f"{m['id']}-{m['version']}.plug"
        (out / name).write_bytes(data)
        powers = sorted(k for k, v in m["permissions"].items() if k != "ui" and v not in (None, "none", [], ""))
        entries.append({"id": m["id"], "name": m["name"], "version": m["version"], "category": item["category"],
                        "description": m.get("description", "")[:300], "powers": powers, "file": name,
                        "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    cat = {"catalog": "0", "tag": tag, "official_key": OFFICIAL_KEY, "plugs": entries}
    problems = check_catalog(cat)
    if problems:
        raise ValueError(problems[0])
    (out / "catalog.json").write_text(json.dumps(cat, indent=1), encoding="utf-8")
    return cat


def verify_dir(d):
    """Re-check a built catalog folder with exactly the rules a download gets."""
    d = Path(d)
    cat = json.loads((d / "catalog.json").read_text(encoding="utf-8"))
    problems = check_catalog(cat)
    for e in cat.get("plugs", []) if not problems else []:
        try:
            verify_official((d / e["file"]).read_bytes(), e)
        except (OSError, ValueError) as err:
            problems.append(f"{e['id']}: {err}")
    return cat, problems


def main(argv):
    if len(argv) == 4 and argv[0] == "build":
        cat = build(argv[1], argv[2], argv[3])
        print(f"signed {len(cat['plugs'])} official plugs for {cat['tag']}")
        return 0
    if len(argv) == 2 and argv[0] == "verify":
        cat, problems = verify_dir(argv[1])
        for p in problems:
            print("PROBLEM:", p)
        print(f"{len(cat.get('plugs', []))} plugs:", "OK" if not problems else "FAILED")
        return 0 if not problems else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
