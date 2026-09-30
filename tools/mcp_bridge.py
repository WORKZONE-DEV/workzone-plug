"""AI tools adapter (Phase 8): lets plugs call AI tools YOU chose, through MCP.

MCP (Model Context Protocol) is the common way AI tools talk to apps. This bridge
starts a tool server you listed, asks it to run ONE tool, and returns the answer.

Your list lives on your computer only: WORKZONE_HOME/mcp.json (default ~/.workzone/mcp.json)

  {
    "servers": { "local-ai": { "command": ["python", "C:/tools/my_ai_server.py"] } },
    "tools":   { "summarise": { "server": "local-ai", "tool": "summarize" } }
  }

"tools" maps the name a plug declares (permissions.ai) to a server + that server's tool.
Three locks, all needed: the plug declared the tool, you approved the plug, and the tool
is in YOUR list. Nothing is offered by default. Standard library only.
"""
import json
import os
import re
import subprocess
import threading
from pathlib import Path

TIMEOUT = 30
MAX_ANSWER = 1024 * 1024
MAX_AT_ONCE = 2
_SLOTS = threading.BoundedSemaphore(MAX_AT_ONCE)
TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def config_path():
    return Path(os.environ.get("WORKZONE_HOME", Path.home() / ".workzone")) / "mcp.json"


def load_config(path=None):
    """Your list of AI tools. Missing or broken file = no tools (fail closed)."""
    p = Path(path) if path else config_path()
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"servers": {}, "tools": {}}
    servers = cfg.get("servers") if isinstance(cfg.get("servers"), dict) else {}
    tools = {}
    for name, t in (cfg.get("tools") or {}).items():
        if (isinstance(name, str) and TOOL_NAME.fullmatch(name) and isinstance(t, dict)
                and t.get("server") in servers and isinstance(t.get("tool"), str)
                and isinstance(servers[t["server"]].get("command"), list)
                and all(isinstance(c, str) for c in servers[t["server"]]["command"])):
            tools[name] = t
    return {"servers": servers, "tools": tools}


def offered(cfg=None):
    return sorted((cfg or load_config())["tools"])


class _Rpc:
    """Newline-delimited JSON-RPC over a child process's stdin/stdout (MCP 'stdio' transport)."""
    def __init__(self, command):
        self.p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
        self.next = 1

    def send(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            msg["id"] = self.next
            self.next += 1
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        if notify:
            return None
        while True:
            line = self.p.stdout.readline(MAX_ANSWER + 1)
            if not line:
                raise RuntimeError("the tool server stopped")
            if len(line) > MAX_ANSWER:
                raise RuntimeError("answer too big")
            try:
                reply = json.loads(line)
            except ValueError:
                continue            # not ours (servers may print other lines); keep reading
            if reply.get("id") == msg["id"]:
                if "error" in reply:
                    raise RuntimeError(str(reply["error"].get("message", "tool error"))[:200])
                return reply.get("result")

    def close(self):
        for f in (self.p.stdin, self.p.stdout):
            try:
                f.close()
            except OSError:
                pass
        try:
            self.p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()


def call(tool, args, cfg=None):
    """Run one tool from YOUR list. Returns the tool's result. Raises ValueError with a plain reason."""
    cfg = cfg or load_config()
    t = cfg["tools"].get(tool)
    if t is None:
        raise ValueError(f"'{tool}' is not in your AI tools list")
    if not isinstance(args, dict):
        raise ValueError("args must be an object")
    command = cfg["servers"][t["server"]]["command"]
    if not _SLOTS.acquire(timeout=TIMEOUT):
        raise ValueError("too many AI tools running at once; try again")
    box = {}
    try:
        rpc = _Rpc(command)                 # started HERE, so it can be killed from here too
    except OSError as e:
        _SLOTS.release()
        raise ValueError(f"'{tool}' could not start: {e}")

    def work():
        try:
            rpc.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "work-zone-plug", "version": "0"}})
            rpc.send("notifications/initialized", notify=True)
            box["result"] = rpc.send("tools/call", {"name": t["tool"], "arguments": args})
        except Exception as e:  # noqa: BLE001 - reported as a plain failure below
            box["error"] = str(e) or type(e).__name__
    th = threading.Thread(target=work, daemon=True)
    try:
        th.start()
        th.join(TIMEOUT)
        timed_out = th.is_alive()
    finally:
        if th.is_alive():
            rpc.p.kill()                    # a stuck tool is stopped, never left running
        rpc.close()
        th.join(5)
        _SLOTS.release()
    if timed_out:
        raise ValueError(f"'{tool}' took longer than {TIMEOUT} seconds and was stopped")
    if "error" in box:
        raise ValueError(f"'{tool}' failed: {box['error']}")
    return box.get("result")
