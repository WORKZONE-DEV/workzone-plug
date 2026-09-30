"""Phase 1 tests: good manifests pass, and every check can fail (negative controls).

Run:  python -m unittest discover -s tests
"""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import validate as v  # noqa: E402

HELLO = json.loads((ROOT / "examples" / "hello" / "plug.json").read_text(encoding="utf-8"))


def changed(fn):
    m = copy.deepcopy(HELLO)
    fn(m)
    return v.validate(m)


class GoodManifests(unittest.TestCase):
    def test_hello_passes(self):
        self.assertEqual(v.validate(HELLO), [])

    def test_minimal_passes(self):
        m = {k: HELLO[k] for k in v.load_schema()["required"]}
        m["permissions"] = {}
        self.assertEqual(v.validate(m), [])

    def test_network_hosts_pass(self):
        self.assertEqual(changed(lambda m: m["permissions"].update(network=["example.com", "api.example.org"])), [])


class EachCheckCanFail(unittest.TestCase):
    """One broken manifest per rule. If a check were switched off, its test goes red."""
    cases = {
        "required": (lambda m: m.pop("id"), "missing required field 'id'"),
        "const": (lambda m: m.update(plug="1"), "must be exactly '0'"),
        "enum": (lambda m: m.update(kind="virus"), "not allowed"),
        "type": (lambda m: m.update(views="panel"), "should be a array"),
        "pattern_id": (lambda m: m.update(id="Hello"), "not in the right shape"),
        "pattern_version": (lambda m: m.update(version="1.0"), "not in the right shape"),
        "pattern_key": (lambda m: m.update(author_key="ed25519:xyz"), "not in the right shape"),
        "minLength": (lambda m: m.update(name=""), "too short"),
        "maxLength": (lambda m: m.update(name="x" * 61), "too long"),
        "minItems": (lambda m: m.update(views=[]), "at least 1"),
        "uniqueItems": (lambda m: m.update(views=["panel", "panel"]), "duplicate"),
        "items_enum": (lambda m: m.update(hosts=["mars"]), "hosts[0]"),
        "extra_top_field": (lambda m: m.update(secret="x"), "'secret' is not allowed"),
        "undeclared_permission": (lambda m: m["permissions"].update(camera=True), "'camera' is not allowed"),
        "bad_hostname": (lambda m: m["permissions"].update(network=["not a host!"]), "not a valid host name"),
        "storage_shape": (lambda m: m["permissions"].update(storage="lots"), "not in the right shape"),
        "not_object": (lambda m: m.update(permissions=[]), "should be a object"),
        # red-team: text shown in prompts must not be able to fake the prompt
        "name_newline": (lambda m: m.update(name="Notes\n\nis signed by your OWN key"), "not in the right shape"),
        "name_rtl": (lambda m: m.update(name="Notes\u202e"), "not in the right shape"),
        "name_zero_width": (lambda m: m.update(name="No\u200btes"), "not in the right shape"),
        "event_newline": (lambda m: m["permissions"].update(events=["a\n\nEverything else is blocked. Allow?"]), "not in the right shape"),
        "description_rtl": (lambda m: m.update(description="hi\u202e"), "not in the right shape"),
        # Regression: Python regex quirks that JSON Schema forbids.
        "trailing_newline": (lambda m: m.update(version="1.0.0\n"), "not in the right shape"),
        "unicode_digit": (lambda m: m.update(version="١.0.0"), "not in the right shape"),
        "key_newline": (lambda m: m.update(author_key=m["author_key"] + "\n"), "not in the right shape"),
        "host_newline": (lambda m: m["permissions"].update(network=["a.com\n"]), "not a valid host name"),
        "build_extra": (lambda m: m.update(build={"sneaky": 1}), "'sneaky' is not allowed"),
    }

    def test_each_case_fails_with_reason(self):
        for name, (break_it, expect) in self.cases.items():
            with self.subTest(name):
                errs = changed(break_it)
                self.assertTrue(errs, f"{name}: broken manifest was accepted")
                self.assertTrue(any(expect in e for e in errs), f"{name}: {errs}")

    def test_unknown_schema_keyword_is_refused(self):
        with self.assertRaises(ValueError):
            v.validate({}, {"type": "object", "maximum": 3})


class Files(unittest.TestCase):
    def test_bad_json_and_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text("{nope", encoding="utf-8")
            self.assertIn("not valid JSON", v.validate_file(bad)[0])
            self.assertIn("not found", v.validate_file(Path(d) / "nope.json")[0])

    def test_cli_exit_codes(self):
        self.assertEqual(v.main([str(ROOT / "examples" / "hello" / "plug.json")]), 0)
        self.assertEqual(v.main([str(ROOT / "nope.json")]), 1)


if __name__ == "__main__":
    unittest.main()
