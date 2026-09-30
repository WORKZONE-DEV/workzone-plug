"""A tiny stand-in MCP tool server for tests: offers 'echo' and 'shout', and 'boom' that errors."""
import json
import sys

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if "id" not in msg:
        continue                                   # a notification: no answer
    if msg["method"] == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "0"}}
    elif msg["method"] == "tools/call":
        name, args = msg["params"]["name"], msg["params"].get("arguments", {})
        if name == "boom":
            print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -1, "message": "it broke"}}), flush=True)
            continue
        text = json.dumps(args) if name == "echo" else str(args.get("text", "")).upper()
        result = {"content": [{"type": "text", "text": text}]}
    else:
        result = {}
    print("some log line the client must ignore", flush=True)
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
