"""Plug manifest validator (Phase 1).

Checks a plug.json against socket/plug.schema.json using only the Python
standard library. The schema file stays the single source of truth: this
script reads it and applies the handful of JSON Schema rules it uses.

Usage:  python tools/validate.py path/to/plug.json [...]
Exit 0 = every file passed, 1 = at least one failed.
"""
import json
import re
import sys
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "socket" / "plug.schema.json"
HOSTNAME = re.compile(r"^(?=.{1,253}\Z)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.I)
TYPES = {"object": dict, "array": list, "string": str}
# Keywords this validator understands. An unknown one in the schema is an
# error, so a new rule can never be silently skipped.
KNOWN = {"$schema", "$id", "title", "description", "default", "type", "required",
         "additionalProperties", "properties", "const", "enum", "pattern",
         "minLength", "maxLength", "items", "minItems", "uniqueItems", "format"}


def load_schema(path=SCHEMA_PATH):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _pattern_ok(pattern, value):
    # JSON Schema patterns follow JavaScript rules. Python differs in two ways
    # that would let bad values through: \d matches non-ASCII digits (fixed by
    # re.ASCII) and $ also matches before a final newline (checked by hand).
    if pattern.endswith("$") and value.endswith("\n"):
        return False
    return re.search(pattern, value, re.ASCII) is not None


def _check(value, rule, where, errors):
    unknown = set(rule) - KNOWN
    if unknown:
        raise ValueError(f"schema uses unsupported keyword(s) at {where}: {sorted(unknown)}")
    if "const" in rule and value != rule["const"]:
        errors.append(f"{where}: must be exactly {rule['const']!r}, got {value!r}")
        return
    if "enum" in rule and value not in rule["enum"]:
        errors.append(f"{where}: {value!r} is not allowed; pick one of {rule['enum']}")
        return
    t = rule.get("type")
    if t and not isinstance(value, TYPES[t]):
        errors.append(f"{where}: should be a {t}, got {type(value).__name__}")
        return
    if isinstance(value, str):
        if "minLength" in rule and len(value) < rule["minLength"]:
            errors.append(f"{where}: too short (min {rule['minLength']} characters)")
        if "maxLength" in rule and len(value) > rule["maxLength"]:
            errors.append(f"{where}: too long (max {rule['maxLength']} characters)")
        if "pattern" in rule and not _pattern_ok(rule["pattern"], value):
            errors.append(f"{where}: {value!r} is not in the right shape (pattern {rule['pattern']})")
        if rule.get("format") == "hostname" and not (HOSTNAME.match(value) and not value.endswith("\n")):
            errors.append(f"{where}: {value!r} is not a valid host name")
    if isinstance(value, list):
        if "minItems" in rule and len(value) < rule["minItems"]:
            errors.append(f"{where}: needs at least {rule['minItems']} item(s)")
        if rule.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            errors.append(f"{where}: has duplicate items")
        for i, item in enumerate(value):
            _check(item, rule.get("items", {}), f"{where}[{i}]", errors)
    if isinstance(value, dict):
        props = rule.get("properties", {})
        for key in rule.get("required", []):
            if key not in value:
                errors.append(f"{where}: missing required field '{key}'")
        for key, v in value.items():
            if key in props:
                _check(v, props[key], f"{where}.{key}", errors)
            elif rule.get("additionalProperties") is False:
                errors.append(f"{where}: '{key}' is not allowed here (deny by default: only listed fields exist)")


def validate(manifest, schema=None):
    """Return a list of plain-English problems. Empty list = valid."""
    errors = []
    _check(manifest, schema or load_schema(), "plug.json", errors)
    return errors


def validate_file(path, schema=None):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [f"{path}: file not found"]
    except json.JSONDecodeError as e:
        return [f"{path}: not valid JSON ({e.msg}, line {e.lineno})"]
    return validate(data, schema)


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    schema, bad = load_schema(), 0
    for p in argv:
        errs = validate_file(p, schema)
        if errs:
            bad += 1
            print(f"FAIL {p}")
            for e in errs:
                print(f"  - {e}")
        else:
            print(f"OK   {p}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
