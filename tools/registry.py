"""Registry (Phase 9): a shelf of signed plugs that anyone can host and anyone can check.

  python tools/registry.py add   FILE.plug [REG_DIR]   check a plug and put it on the shelf
  python tools/registry.py list  [REG_DIR]             what's on the shelf
  python tools/registry.py check [REG_DIR]             re-check every plug against the index

A registry is just a folder (so it can be a USB stick, a shared drive or a git repo):

  REG_DIR/
    index.json        name, id, version, maker, powers and fingerprint of every plug
    plugs/<id>-<version>.plug

The default REG_DIR is WORKZONE_HOME/registry (your own shelf; the dashboard shows it
in the Library). The rules are the socket's rules, applied before anything goes on the shelf:
  - every plug must pass every check (lock, key, mould, label)
  - a name belongs to its first maker; nobody else can publish under it
  - versions only go forward; the same version can't be replaced with different bytes
  - the index is only a list: every plug is checked again when it is used, so a tampered
    index can't make a bad plug run. "check" also spots a swapped or missing file.
Standard library only; nothing goes online.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pack  # noqa: E402

INDEX = "index.json"


def default_dir():
    return Path(os.environ.get("WORKZONE_HOME", Path.home() / ".workzone")) / "registry"


def _ver(v):
    return tuple(int(x) for x in v.split("."))


def load_index(reg):
    f = Path(reg) / INDEX
    if not f.exists():
        return {"registry": "0", "plugs": []}
    idx = json.loads(f.read_text(encoding="utf-8"))
    if not isinstance(idx, dict) or not isinstance(idx.get("plugs"), list):
        raise ValueError("index.json is not a registry index")
    return idx


def _write_index(reg, idx):
    idx["plugs"].sort(key=lambda e: (e["id"], _ver(e["version"])))
    (Path(reg) / INDEX).write_text(json.dumps(idx, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def entry_for(data, file_name):
    m, files = pack.verify(data)
    return {"file": file_name, "id": m["id"], "name": m["name"], "version": m["version"], "kind": m["kind"],
            "description": m.get("description", ""), "author_key": m["author_key"],
            "permissions": m["permissions"], "built_on": m.get("built_on", []),
            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def add(plug_file, reg=None):
    """Check a plug and put it on the shelf. Returns its index entry. Raises ValueError with a plain reason."""
    reg = Path(reg or default_dir())
    data = Path(plug_file).read_bytes()
    idx = load_index(reg)
    e = entry_for(data, "")                        # every check, before anything is written
    e["file"] = f"plugs/{e['id']}-{e['version']}.plug"
    same_id = [x for x in idx["plugs"] if x["id"] == e["id"]]
    for x in same_id:
        if x["author_key"] != e["author_key"]:
            raise ValueError(f"the name {e['id']} already belongs to another maker on this shelf")
        if x["version"] == e["version"]:
            if x["sha256"] == e["sha256"]:
                return x                            # already on the shelf, exactly as it is
            raise ValueError(f"version {e['version']} of {e['id']} is already on the shelf with different bytes; "
                             "give your change a new version number")
    if same_id and _ver(e["version"]) < max(_ver(x["version"]) for x in same_id):
        raise ValueError(f"version {e['version']} is older than one already on the shelf (versions only go forward)")
    target = reg / e["file"]
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.read_bytes() != data:
        raise ValueError(f"{e['file']} already exists with different bytes (left untouched)")
    target.write_bytes(data)
    idx["plugs"].append(e)
    _write_index(reg, idx)
    return e


def check(reg=None):
    """Re-check every plug on the shelf. Returns a list of plain problems (empty = all good)."""
    reg = Path(reg or default_dir())
    problems = []
    for e in load_index(reg)["plugs"]:
        f = (reg / e.get("file", "")).resolve()
        if reg.resolve() not in f.parents:
            problems.append(f"{e.get('file')}: points outside the registry folder")
            continue
        if not f.is_file():
            problems.append(f"{e['file']}: missing")
            continue
        data = f.read_bytes()
        if hashlib.sha256(data).hexdigest() != e.get("sha256"):
            problems.append(f"{e['file']}: its bytes don't match the index (swapped or changed)")
            continue
        try:
            real = entry_for(data, e["file"])
        except ValueError as err:
            problems.append(f"{e['file']}: fails the checks ({err})")
            continue
        for k in ("id", "version", "author_key"):
            if real[k] != e.get(k):
                problems.append(f"{e['file']}: the index says {k}={e.get(k)!r} but the plug says {real[k]!r}")
    return problems


def get(file_name, reg=None, verify=True):
    """The bytes of one plug on the shelf, re-checked. Only files listed in the index.
    verify=False skips the full check ONLY for callers that check it straight after (the helper does)."""
    reg = Path(reg or default_dir())
    for e in load_index(reg)["plugs"]:
        if e["file"] == file_name:
            f = reg / e["file"]
            if f.is_symlink() or reg.resolve() not in f.resolve().parents:
                raise ValueError("that plug is outside the registry folder")
            data = f.read_bytes()
            if hashlib.sha256(data).hexdigest() != e["sha256"]:
                raise ValueError("that plug's bytes don't match the registry index")
            if verify:
                pack.verify(data)
            return data
    raise ValueError("no such plug on the shelf")


def main(argv):
    if not argv or argv[0] in ("-h", "--help") or argv[0] not in ("add", "list", "check"):
        print(__doc__)
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "add":
            if not rest:
                print(__doc__)
                return 2
            e = add(rest[0], rest[1] if len(rest) > 1 else None)
            print(f"On the shelf: {e['name']} {e['version']}  ({e['id']}, fingerprint {e['sha256'][:12]})")
            return 0
        reg = rest[0] if rest else None
        if cmd == "list":
            plugs = load_index(reg or default_dir())["plugs"]
            if not plugs:
                print("The shelf is empty. Add one with: registry.py add FILE.plug")
            for e in plugs:
                print(f"  {e['name'][:26]:26}  {e['id']:30}  {e['version']:8}  {e['sha256'][:12]}")
            return 0
        problems = check(reg)
        for p in problems:
            print("  NO   " + p)
        print("All plugs on the shelf pass." if not problems else f"{len(problems)} problem(s).")
        return 0 if not problems else 1
    except (OSError, ValueError) as e:
        print(f"Not done: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
