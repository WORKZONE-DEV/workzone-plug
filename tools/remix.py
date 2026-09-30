"""Build your own brick on top of someone else's.

  python tools/remix.py ORIGINAL.plug NEW_DIR [new.id]

1. Verifies ORIGINAL.plug (a tampered or unsigned plug can't be built on).
2. Copies its app files into a NEW source folder.
3. Writes a plug.json for YOUR brick with built_on = the original's family line plus the
   original itself (id, version, maker's key, exact file fingerprint). Credit travels
   with the file forever; follow built_on back and you reach the original bricks.
4. You change what you like, then pack it with YOUR key.

Nothing is fetched, and the original is only read. Standard library only.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pack  # noqa: E402
import validate  # noqa: E402

MAX_LINE = 32   # how many ancestors a brick may list (keeps files small and honest)


def remix(plug_bytes, out_dir, new_id=None):
    out = Path(out_dir)
    if out.exists():
        raise FileExistsError(f"{out} already exists; pick a new folder")
    manifest, files = pack.verify(plug_bytes)          # raises ValueError if it can't be trusted
    line = list(manifest.get("built_on") or [])
    line.append({"id": manifest["id"], "version": manifest["version"], "author_key": manifest["author_key"],
                 "fingerprint": "sha256:" + hashlib.sha256(plug_bytes).hexdigest()})
    if len(line) > MAX_LINE:
        line = line[-MAX_LINE:]
    mine = {k: v for k, v in manifest.items() if k not in ("build", "built_on")}
    mine["id"] = new_id or (manifest["id"] + "-remix" if not manifest["id"].endswith("-remix") else manifest["id"] + "2")
    mine["version"] = "0.1.0"
    mine["name"] = (manifest["name"] + " (remix)")[:60]
    mine["author_key"] = "ed25519:" + "0" * 64       # filled in with YOUR key when you pack
    mine["built_on"] = line
    errors = validate.validate(mine)
    if errors:
        raise ValueError("the new plug.json would not be valid: " + "; ".join(errors))
    for name, data in files.items():
        target = out / "app" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (out / "plug.json").write_text(json.dumps(mine, indent=2) + "\n", encoding="utf-8")
    return out, mine


def main(argv):
    if len(argv) not in (2, 3):
        print(__doc__)
        return 2
    new_id = argv[2] if len(argv) == 3 else None
    if new_id is not None and not re.fullmatch(r"[a-z0-9]+(\.[a-z0-9-]+)+", new_id):
        print("the new id must look like zone.work.my-brick")
        return 2
    try:
        out, m = remix(Path(argv[0]).read_bytes(), argv[1], new_id)
    except (ValueError, FileExistsError, OSError) as e:
        print(f"Not remixed: {e}")
        return 1
    print(f"Made {out}: {m['id']}, built on {len(m['built_on'])} brick(s), the original is {m['built_on'][0]['id']}")
    print(f"Next: change what you like, then python tools/pack.py pack {out} YOUR.key {out.name}.plug --inline")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
