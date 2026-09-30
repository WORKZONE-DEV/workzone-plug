"""Phase 3 tests: RFC 8032 vectors, round trip, and every way a signature can be wrong."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import ed25519  # noqa: E402
import keys  # noqa: E402

# RFC 8032 section 7.1, tests 1 and 3: (secret, public, message, signature)
RFC = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]
# Optional drift check against a local original: set PLUG_ED25519_SOURCE to its path.
SOURCE = Path(os.environ.get("PLUG_ED25519_SOURCE", str(ROOT / "_missing_")))


class RfcVectors(unittest.TestCase):
    def test_vectors(self):
        for sk, pk, msg, sig in RFC:
            sk, pk, msg, sig = (bytes.fromhex(x) for x in (sk, pk, msg, sig))
            self.assertEqual(ed25519.ed25519_public_key(sk), pk)
            self.assertEqual(ed25519.ed25519_sign(msg, sk, pk), sig)
            self.assertTrue(ed25519.ed25519_verify(sig, msg, pk))


class Verify(unittest.TestCase):
    sk, pk, msg, sig = (bytes.fromhex(x) for x in RFC[1])

    def test_each_wrong_thing_fails(self):
        s = bytearray(self.sig)
        other_pk = bytes.fromhex(RFC[0][1])
        bad = {
            "wrong message": (self.sig, b"\xaf\x83", self.pk),
            "wrong key": (self.sig, self.msg, other_pk),
            "flipped R bit": (bytes([s[0] ^ 1]) + self.sig[1:], self.msg, self.pk),
            "flipped S bit": (self.sig[:40] + bytes([s[40] ^ 1]) + self.sig[41:], self.msg, self.pk),
            # S + l is the same number mod l: a "malleable" copy. Must be refused.
            "S not reduced": (self.sig[:32] + (int.from_bytes(self.sig[32:], "little") + ed25519._l).to_bytes(32, "little"),
                              self.msg, self.pk),
            "short signature": (self.sig[:63], self.msg, self.pk),
            "short key": (self.sig, self.msg, self.pk[:31]),
            "non-canonical key y>=q": (self.sig, self.msg, (ed25519._q + 1).to_bytes(32, "little")),
            "not bytes": ("nope", self.msg, self.pk),
        }
        for name, (sig, msg, pk) in bad.items():
            with self.subTest(name):
                self.assertFalse(ed25519.ed25519_verify(sig, msg, pk))


class KeyFiles(unittest.TestCase):
    def test_round_trip_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "k" / "me.key"
            seed = keys.new_key(p)
            self.assertEqual(keys.load_seed(p), seed)
            pub = keys.public_key_str(seed)
            sig = keys.sign(seed, b"hi")
            self.assertTrue(keys.verify(pub, b"hi", sig))
            self.assertFalse(keys.verify(pub, b"ho", sig))
            with self.assertRaises(FileExistsError):
                keys.new_key(p)
            self.assertEqual(keys.load_seed(p), seed, "a refused overwrite must leave the key untouched")

    def test_key_folder_follows_workzone_home(self):
        """Every tool uses the same home: keys must not land in the real ~/.workzone during tests."""
        import importlib
        old = os.environ.get("WORKZONE_HOME")
        with tempfile.TemporaryDirectory() as d:
            os.environ["WORKZONE_HOME"] = d
            try:
                k = importlib.reload(keys)
                self.assertEqual(k.KEY_DIR, Path(d) / "keys")
            finally:
                if old is None:
                    os.environ.pop("WORKZONE_HOME", None)
                else:
                    os.environ["WORKZONE_HOME"] = old
                importlib.reload(keys)

    def test_bad_public_key_strings_fail_closed(self):
        seed = bytes(32)
        sig = keys.sign(seed, b"x")
        good = keys.public_key_str(seed)
        for bad in [good.upper(), good[8:], "rsa:" + good[8:], good + "0", None, 5]:
            with self.subTest(bad):
                self.assertFalse(keys.verify(bad, b"x", sig))


@unittest.skipUnless(SOURCE.exists(), "no local original configured (optional)")
class NoDrift(unittest.TestCase):
    """The reference block must stay byte-identical to the local original, if one is configured."""
    def test_vendored_block_matches_source(self):
        src = SOURCE.read_text(encoding="utf-8")
        a = src.index("_b = 256")
        b = src.index("# ====", src.index("def ed25519_sign"))
        mine = (ROOT / "tools" / "ed25519.py").read_text(encoding="utf-8")
        start = mine.index("# ---- RFC 8032 REFERENCE START ----\n") + len("# ---- RFC 8032 REFERENCE START ----\n")
        vend = mine[start:mine.index("# ---- RFC 8032 REFERENCE END ----")]
        self.assertEqual(vend.rstrip(), src[a:b].replace("\r\n", "\n").rstrip())


if __name__ == "__main__":
    unittest.main()
