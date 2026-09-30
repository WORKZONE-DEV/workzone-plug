"""Phase 9 registry: only checked plugs go on the shelf, names stay with their maker,
versions only go forward, and a swapped file is caught."""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import pack  # noqa: E402
import registry  # noqa: E402

ME, OTHER = bytes(range(32)), bytes(range(1, 33))


def build(tmp, version="0.1.0", seed=ME, name="hello"):
    src = Path(tmp) / f"src-{name}-{version}-{seed[0]}"
    shutil.copytree(ROOT / "examples" / name, src, dirs_exist_ok=True)
    m = json.loads((src / "plug.json").read_text())
    m["version"] = version
    (src / "plug.json").write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    out = Path(tmp) / f"{name}-{version}-{seed[0]}.plug"
    out.write_bytes(pack.build(src, seed))
    return out


class Registry(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.tmp = self.t.name
        self.reg = Path(self.tmp) / "reg"

    def tearDown(self):
        self.t.cleanup()

    def test_add_list_check_get(self):
        e = registry.add(build(self.tmp), self.reg)
        self.assertEqual(e["id"], "zone.work.hello")
        self.assertTrue((self.reg / e["file"]).is_file())
        self.assertEqual(registry.check(self.reg), [])
        self.assertEqual(registry.get(e["file"], self.reg)[:2], b"PK")
        self.assertEqual(registry.add(build(self.tmp), self.reg)["file"], e["file"], "adding the same plug again is harmless")

    def test_broken_plug_never_goes_on_the_shelf(self):
        p = build(self.tmp)
        data = bytearray(p.read_bytes())
        data[len(data) // 2] ^= 1
        p.write_bytes(bytes(data))
        with self.assertRaises(ValueError):
            registry.add(p, self.reg)
        self.assertFalse((self.reg / "index.json").exists(), "nothing written")

    def test_name_stays_with_its_maker(self):
        registry.add(build(self.tmp, seed=ME), self.reg)
        with self.assertRaises(ValueError) as c:
            registry.add(build(self.tmp, "0.2.0", seed=OTHER), self.reg)
        self.assertIn("another maker", str(c.exception))

    def test_versions_only_go_forward(self):
        registry.add(build(self.tmp, "0.2.0"), self.reg)
        with self.assertRaises(ValueError):
            registry.add(build(self.tmp, "0.1.0"), self.reg)
        registry.add(build(self.tmp, "0.3.0"), self.reg)
        self.assertEqual([e["version"] for e in registry.load_index(self.reg)["plugs"]], ["0.2.0", "0.3.0"])

    def test_same_version_different_bytes_is_refused(self):
        registry.add(build(self.tmp), self.reg)
        other = build(self.tmp, name="ticker")                      # different plug, but give it hello's name+version
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "s"
            shutil.copytree(ROOT / "examples" / "hello", src)
            (src / "app" / "index.html").write_text("<p>changed</p>")
            changed = Path(d) / "c.plug"
            changed.write_bytes(pack.build(src, ME))
            with self.assertRaises(ValueError) as c:
                registry.add(changed, self.reg)
        self.assertIn("new version number", str(c.exception))
        self.assertTrue(other.exists())

    def test_swapped_file_and_lying_index_are_caught(self):
        e = registry.add(build(self.tmp), self.reg)
        registry.add(build(self.tmp, name="ticker"), self.reg)
        idx = registry.load_index(self.reg)
        # swap: put ticker's bytes where hello should be
        (self.reg / e["file"]).write_bytes((self.reg / idx["plugs"][1]["file"]).read_bytes())
        self.assertTrue(any("don't match" in p for p in registry.check(self.reg)))
        with self.assertRaises(ValueError):
            registry.get(e["file"], self.reg)
        # an index entry pointing outside the folder
        idx["plugs"].append(dict(idx["plugs"][0], file="../../outside.plug"))
        (self.reg / "index.json").write_text(json.dumps(idx))
        self.assertTrue(any("outside" in p for p in registry.check(self.reg)))
        with self.assertRaises(ValueError) as c:
            registry.get("../../outside.plug", self.reg)
        self.assertIn("outside", str(c.exception))

    def test_get_only_serves_listed_files(self):
        registry.add(build(self.tmp), self.reg)
        with self.assertRaises(ValueError):
            registry.get("index.json", self.reg)


if __name__ == "__main__":
    unittest.main()
