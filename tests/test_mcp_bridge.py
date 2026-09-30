"""AI tools adapter tests: only tools in YOUR list run, and a broken tool is a clean error."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import mcp_bridge as mb  # noqa: E402

FAKE = str(ROOT / "tests" / "fixtures" / "fake_mcp_server.py")


def cfg_file(d, cfg):
    p = Path(d) / "mcp.json"
    p.write_text(json.dumps(cfg))
    return p


GOOD = {"servers": {"fake": {"command": [sys.executable, FAKE]}},
        "tools": {"echo": {"server": "fake", "tool": "echo"},
                  "shout": {"server": "fake", "tool": "shout"},
                  "boom": {"server": "fake", "tool": "boom"}}}


class Bridge(unittest.TestCase):
    def test_listed_tool_runs_over_mcp(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = mb.load_config(cfg_file(d, GOOD))
            self.assertEqual(mb.offered(cfg), ["boom", "echo", "shout"])
            r = mb.call("shout", {"text": "hi"}, cfg)
            self.assertEqual(r["content"][0]["text"], "HI")
            r = mb.call("echo", {"a": 1}, cfg)
            self.assertEqual(json.loads(r["content"][0]["text"]), {"a": 1})

    def test_tool_not_in_your_list_never_runs(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = mb.load_config(cfg_file(d, GOOD))
            with self.assertRaises(ValueError) as cm:
                mb.call("delete_everything", {}, cfg)
            self.assertIn("not in your AI tools list", str(cm.exception))

    def test_broken_tool_and_bad_args_are_clean_errors(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = mb.load_config(cfg_file(d, GOOD))
            with self.assertRaises(ValueError) as cm:
                mb.call("boom", {}, cfg)
            self.assertIn("it broke", str(cm.exception))
            with self.assertRaises(ValueError):
                mb.call("echo", [1, 2], cfg)

    def test_missing_or_broken_config_offers_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(mb.offered(mb.load_config(Path(d) / "none.json")), [])
            bad = Path(d) / "bad.json"; bad.write_text("{not json")
            self.assertEqual(mb.offered(mb.load_config(bad)), [])

    def test_badly_formed_entries_are_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = {"servers": {"fake": {"command": [sys.executable, FAKE]}, "shell": {"command": "rm -rf /"}},
                   "tools": {"ok": {"server": "fake", "tool": "echo"},
                             "no server": {"server": "missing", "tool": "x"},
                             "string cmd": {"server": "shell", "tool": "x"},
                             "bad name!": {"server": "fake", "tool": "echo"}}}
            self.assertEqual(mb.offered(mb.load_config(cfg_file(d, cfg))), ["ok"])

    def test_stuck_tool_is_stopped_not_left_running(self):
        hang = str(ROOT / "tests" / "fixtures" / "hang_mcp_server.py")
        with tempfile.TemporaryDirectory() as d:
            cfg = mb.load_config(cfg_file(d, {"servers": {"h": {"command": [sys.executable, hang]}},
                                               "tools": {"slow": {"server": "h", "tool": "x"}}}))
            started = []
            real = mb._Rpc.__init__

            def spy(self, command):
                real(self, command)
                started.append(self.p)
            old_t = mb.TIMEOUT
            mb._Rpc.__init__, mb.TIMEOUT = spy, 1
            try:
                with self.assertRaises(ValueError) as cm:
                    mb.call("slow", {}, cfg)
            finally:
                mb._Rpc.__init__, mb.TIMEOUT = real, old_t
            self.assertIn("stopped", str(cm.exception))
            self.assertIsNotNone(started[0].poll(), "the stuck tool program was killed, not left running")

    def test_stopped_server_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = mb.load_config(cfg_file(d, {"servers": {"dead": {"command": [sys.executable, "-c", "pass"]}},
                                               "tools": {"t": {"server": "dead", "tool": "t"}}}))
            with self.assertRaises(ValueError):
                mb.call("t", {}, cfg)


if __name__ == "__main__":
    unittest.main()
