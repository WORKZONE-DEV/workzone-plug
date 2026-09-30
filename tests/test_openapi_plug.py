"""Web API adapter tests: the generated plug can reach exactly one https host, nothing else."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import openapi_plug as o  # noqa: E402
import pack  # noqa: E402

GOOD = {"openapi": "3.0.3", "info": {"title": "Weather API"},
        "servers": [{"url": "https://api.example.com/v1"}],
        "paths": {"/today": {"get": {"summary": "today's weather"}},
                  "/city/{name}": {"get": {}},
                  "/admin": {"delete": {}}}}


def spec(**changes):
    s = json.loads(json.dumps(GOOD))
    s.update(changes)
    return s


class Generate(unittest.TestCase):
    def test_good_spec_makes_a_valid_locked_down_plug(self):
        m, page = o.from_spec(GOOD)
        self.assertEqual(m["permissions"], {"network": ["api.example.com"], "ui": "panel"})
        self.assertIn('"/today"', page)
        self.assertIn('"/city/{name}"', page)
        self.assertNotIn("/admin", page, "only GET operations are offered")

    def test_every_bad_spec_is_refused_with_a_reason(self):
        bad = {
            "not openapi": {"swagger": "2.0"},
            "no server": spec(servers=[]),
            "http": spec(servers=[{"url": "http://api.example.com"}]),
            "port": spec(servers=[{"url": "https://api.example.com:8443"}]),
            "login": spec(servers=[{"url": "https://u:p@api.example.com"}]),
            "raw ip": spec(servers=[{"url": "https://10.0.0.1"}]),
            "no GETs": spec(paths={"/x": {"post": {}}}),
        }
        for name, s in bad.items():
            with self.subTest(name):
                with self.assertRaises(ValueError):
                    o.from_spec(s)

    def test_hostile_text_in_the_spec_cannot_break_out_of_the_script(self):
        s = spec(paths={"/x": {"get": {"summary": "</script><script>alert(1)</script>"}}},
                 info={"title": "<img src=x onerror=alert(1)>"})
        m, page = o.from_spec(s)
        self.assertEqual(page.lower().count("</script>"), 1, "only the real closing tag")
        self.assertNotIn("<img", page)

    def test_make_writes_a_packable_folder_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d) / "api.json"
            sp.write_text(json.dumps(GOOD))
            out, m = o.make(sp, Path(d) / "weather")
            data = pack.build(out, bytes(range(32)))
            got, files = pack.verify(data)
            self.assertEqual(got["permissions"]["network"], ["api.example.com"])
            with self.assertRaises(FileExistsError):
                o.make(sp, Path(d) / "weather")


if __name__ == "__main__":
    unittest.main()
