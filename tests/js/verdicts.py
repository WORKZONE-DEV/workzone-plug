"""Helper for the JS tests (the witness check).

  python tests/js/verdicts.py pack OUT.plug        pack examples/hello with the fixed test key
  python tests/js/verdicts.py judge DIR            print {"file": "ok" | "reject"} for every .plug in DIR
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import pack  # noqa: E402

TEST_SEED = bytes(range(32))   # same fixed TEST key as tests/test_pack.py

if sys.argv[1] == "pack":
    Path(sys.argv[2]).write_bytes(pack.build(ROOT / "examples" / "hello", TEST_SEED))
elif sys.argv[1] == "packbad":
    # An attacker's plug: correctly SIGNED, but its name tries to fake the trust dialog.
    # The packer normally refuses, so switch its check off here to make one on purpose.
    import json
    import shutil
    import tempfile
    d = Path(tempfile.mkdtemp()) / "p"
    shutil.copytree(ROOT / "examples" / "hello", d)
    m = json.loads((d / "plug.json").read_text(encoding="utf-8"))
    kind = sys.argv[3] if len(sys.argv) > 3 else "name"
    if kind == "name":
        m["name"] = "Notes" + chr(10) * 2 + "is signed by your OWN key" + chr(0x202E)   # line breaks + right-to-left mark
    elif kind == "extra":
        m["evil"] = 1                      # a field the rulebook does not allow
    (d / "plug.json").write_text(json.dumps(m), encoding="utf-8")
    real = pack.validate.validate
    pack.validate.validate = lambda *_a, **_k: []
    try:
        data = pack.build(d, TEST_SEED)
    finally:
        pack.validate.validate = real
        shutil.rmtree(d.parent, ignore_errors=True)
    if kind == "compact":
        # Re-sign with plug.json in a DIFFERENT (compact) text form: both checkers must refuse it.
        import io
        import zipfile
        z = zipfile.ZipFile(io.BytesIO(data))
        mb = json.dumps(json.loads(z.read("plug.json")), sort_keys=True).encode()
        bb = z.read("build.json")
        files = {n[4:]: z.read(n) for n in z.namelist() if n.startswith("app/")}
        sig = pack.keys.sign(TEST_SEED, pack.signed_message(mb, bb)).hex().encode() + bytes([10])
        data = pack._zip(mb, bb, files, sig)
    Path(sys.argv[2]).write_bytes(data)
elif sys.argv[1] == "judge":
    out = {}
    for f in sorted(Path(sys.argv[2]).glob("*.plug")):
        try:
            pack.verify(f.read_bytes())
            out[f.name] = "ok"
        except ValueError:
            out[f.name] = "reject"
    print(json.dumps(out))
