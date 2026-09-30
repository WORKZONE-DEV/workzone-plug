"""wz: the whole Work Zone from any terminal (PowerShell, a Linux or Mac terminal, a small floating window...).

  python tools/wz.py                     a simple menu (type a number)
  python tools/wz.py fit PATH            will it fit? (read-only)
  python tools/wz.py port PATH NEW_DIR   copy it into a new plug folder
  python tools/wz.py key                 make your key (once)
  python tools/wz.py pack DIR [OUT.plug] seal a plug folder with your key
  python tools/wz.py verify FILE.plug    check a plug (both layers of checks)
  python tools/wz.py remix FILE.plug NEW_DIR   build your own plug on top of another
  python tools/wz.py api SPEC.json NEW_DIR     make a plug from a web API description
  python tools/wz.py list [DIR]          show the plugs in a folder, with their fingerprints
  python tools/wz.py open                open the dashboard in your browser
  python tools/wz.py run FILE.plug [mini]  run one plug in its own app window
  python tools/wz.py shelf FILE.plug     put a checked plug on your registry shelf (shows in the Library)

Same rules as everywhere else: your originals are only read, nothing is overwritten,
nothing goes online. Standard library only.
"""
import hashlib
import os
import subprocess
import sys
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import desktop  # noqa: E402
import fit  # noqa: E402
import keys  # noqa: E402
import openapi_plug  # noqa: E402
import registry  # noqa: E402
import pack  # noqa: E402
import remix  # noqa: E402

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))   # the packed app unpacks here
MY_KEY = "workzone"          # the same key the dashboard makes and uses
BANNER = r"""
  +-----------------------------+
  |  W O R K   Z O N E   (wz)   |
  |  one signed file, any host  |
  +-----------------------------+"""


def key_file():
    return keys.KEY_DIR / f"{MY_KEY}.key"


def cmd_fit(path):
    info = fit.inspect(path)
    print(fit.render(info))
    return {fit.OK: 0, fit.WARN: 1, fit.STOP: 2}[fit.verdict(info["findings"])]


def cmd_port(path, out):
    return fit.main([path, "--port", out])


def cmd_key():
    kf = key_file()
    if kf.exists():
        print(f"You already have a key (left exactly as it is): {keys.public_key_str(keys.load_seed(kf))}")
        return 0
    seed = keys.new_key(kf)
    print(f"Your key is ready: {keys.public_key_str(seed)}")
    print(f"It lives at {kf} and never leaves this computer. Keep it private.")
    return 0


def cmd_pack(folder, out=None):
    kf = key_file()
    if not kf.exists():
        print("Make your key first:  wz key")
        return 1
    out = Path(out) if out else Path(Path(folder).resolve().name + ".plug")
    try:
        data = pack.build(folder, keys.load_seed(kf), inline=True)
        pack.refuse_if_different(out, data)
    except (ValueError, SystemExit) as e:
        print(f"Not packed: {e}")
        return 1
    out.write_bytes(data)
    print(f"Sealed {out}  (fingerprint {hashlib.sha256(data).hexdigest()[:16]})")
    return 0


def cmd_verify(file):
    return pack.main(["verify", file])


def cmd_remix(file, out):
    return remix.main([file, out])


def cmd_api(spec, out):
    return openapi_plug.main([spec, out])


def cmd_list(folder="."):
    found = sorted(Path(folder).glob("*.plug"))
    if not found:
        print(f"No .plug files in {Path(folder).resolve()}")
        return 0
    for f in found:
        data = f.read_bytes()
        try:
            m, _ = pack.verify(data)
            print(f"  OK   {m['name'][:28]:28}  {m['id']:32}  {m['version']:8}  {hashlib.sha256(data).hexdigest()[:12]}")
        except ValueError as e:
            print(f"  NO   {f.name[:28]:28}  {str(e)[:60]}")
    return 0


def cmd_open():
    print("Starting the dashboard (this computer only). Close the window or press Ctrl+C to stop it.")
    webbrowser.open("http://127.0.0.1:8770/")
    return subprocess.call([sys.executable, str(ROOT / "tools" / "workzone.py")])


def cmd_shelf(file):
    return registry.main(["add", file])


def cmd_run(file, size="normal"):
    return desktop.main([file, size])


COMMANDS = {
    "fit": (cmd_fit, 1, "Will it fit? (read-only)", ["path to a file or folder"]),
    "port": (cmd_port, 2, "Copy something into a new plug folder", ["path to a file or folder", "new folder name"]),
    "key": (cmd_key, 0, "Make your key (once)", []),
    "pack": (cmd_pack, 1, "Seal a plug folder with your key", ["plug folder"]),
    "verify": (cmd_verify, 1, "Check a .plug file", [".plug file"]),
    "remix": (cmd_remix, 2, "Build on top of another plug", [".plug file", "new folder name"]),
    "api": (cmd_api, 2, "Make a plug from a web API description", ["OpenAPI .json file", "new folder name"]),
    "list": (cmd_list, 0, "Show the plugs in a folder", []),
    "open": (cmd_open, 0, "Open the dashboard in your browser", []),
    "run": (cmd_run, 1, "Run one plug in its own app window", [".plug file"]),
    "shelf": (cmd_shelf, 1, "Put a plug on your registry shelf", [".plug file"]),
}


def menu(ask=input):
    print(BANNER)
    names = list(COMMANDS)
    while True:
        print()
        for i, n in enumerate(names, 1):
            print(f"  {i}. {n:7} {COMMANDS[n][2]}")
        print("  0. quit")
        choice = ask("\n  > ").strip().lower()
        if choice in ("0", "q", "quit", "exit", ""):
            return 0
        name = names[int(choice) - 1] if choice.isdigit() and 0 < int(choice) <= len(names) else choice
        if name not in COMMANDS:
            print("  Type a number from the list.")
            continue
        fn, _, _, questions = COMMANDS[name]
        answers = [ask(f"  {q}: ").strip().strip('"') for q in questions]
        if any(not a for a in answers):
            print("  Cancelled (nothing was changed).")
            continue
        print()
        fn(*answers)


def main(argv):
    if not argv:
        return menu()
    name, args = argv[0].lower(), argv[1:]
    if name in ("-h", "--help", "help") or name not in COMMANDS:
        print(__doc__)
        return 0 if name in ("-h", "--help", "help") else 2
    fn, need, _, _ = COMMANDS[name]
    if len(args) < need:
        print(__doc__)
        return 2
    return fn(*args[:need + 1]) if name in ("pack", "list", "run") else fn(*args[:need])


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print()
        sys.exit(130)
    except EOFError:
        sys.exit(0)
