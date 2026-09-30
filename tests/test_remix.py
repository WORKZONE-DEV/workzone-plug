"""Remix tests: build on a brick, credit travels, the family line reaches the original."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import pack  # noqa: E402
import remix  # noqa: E402
import validate  # noqa: E402

A, B, C = bytes(range(32)), bytes(range(1, 33)), bytes(range(2, 34))   # three different TEST makers


class Remix(unittest.TestCase):
    def test_three_generations_keep_the_whole_family_line(self):
        with tempfile.TemporaryDirectory() as d:
            og = pack.build(ROOT / "examples" / "hello", A)                       # maker A: the OG brick
            src2, m2 = remix.remix(og, Path(d) / "gen2")
            gen2 = pack.build(src2, B)                                            # maker B builds on it
            src3, m3 = remix.remix(gen2, Path(d) / "gen3", "zone.work.hello-third")
            gen3 = pack.build(src3, C)                                            # maker C builds on B's
            final, _ = pack.verify(gen3)
            line = final["built_on"]
            self.assertEqual([x["id"] for x in line], ["zone.work.hello", "zone.work.hello-remix"])
            self.assertEqual(line[0]["author_key"], pack.keys.public_key_str(A), "the OG maker is credited")
            self.assertEqual(line[1]["author_key"], pack.keys.public_key_str(B))
            self.assertEqual(line[0]["fingerprint"], "sha256:" + hashlib.sha256(og).hexdigest(), "exact file")
            self.assertEqual(final["author_key"], pack.keys.public_key_str(C), "and the new maker signs their own brick")

    def test_credit_cannot_be_quietly_removed(self):
        """Changing built_on after signing breaks the signature."""
        with tempfile.TemporaryDirectory() as d:
            src, _ = remix.remix(pack.build(ROOT / "examples" / "hello", A), Path(d) / "r")
            signed = pack.build(src, B)
            import io, zipfile
            z = zipfile.ZipFile(io.BytesIO(signed))
            m = json.loads(z.read("plug.json")); m["built_on"] = []
            files = {n[4:]: z.read(n) for n in z.namelist() if n.startswith("app/")}
            forged = pack._zip(pack._canon(m), z.read("build.json"), files, z.read("signature"))
            with self.assertRaises(ValueError):
                pack.verify(forged)

    def test_cannot_build_on_a_tampered_plug(self):
        with tempfile.TemporaryDirectory() as d:
            bad = bytearray(pack.build(ROOT / "examples" / "hello", A)); bad[60] ^= 1
            with self.assertRaises(ValueError):
                remix.remix(bytes(bad), Path(d) / "r")
            self.assertFalse((Path(d) / "r").exists(), "nothing written")

    def test_never_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "taken").mkdir()
            with self.assertRaises(FileExistsError):
                remix.remix(pack.build(ROOT / "examples" / "hello", A), Path(d) / "taken")

    def test_bad_built_on_entries_are_refused_by_the_rulebook(self):
        m = json.loads((ROOT / "examples" / "hello" / "plug.json").read_text())
        for bad in [[{"id": "x"}], [{"id": "a.b", "version": "1", "author_key": "k", "fingerprint": "f"}], "nope",
                    [{"id": "a.b", "version": "1.0.0", "author_key": "ed25519:" + "0" * 64, "fingerprint": "sha256:" + "0" * 64, "extra": 1}]]:
            with self.subTest(bad):
                m2 = dict(m, built_on=bad)
                self.assertTrue(validate.validate(m2))


if __name__ == "__main__":
    unittest.main()
