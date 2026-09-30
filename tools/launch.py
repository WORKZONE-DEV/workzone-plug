"""One-click start: runs the Work Zone helper on this computer and opens it in your browser.

This is what the downloadable app runs (built in the cloud by .github/workflows/release.yml).
Keep its window open while you use Work Zone: strict mode asks you to type "yes" there.

  python tools/launch.py            start and open the browser
  python tools/launch.py --check    self-check with our own tools, then exit (the build runs this)
"""
import os
import sys
import tempfile
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keys  # noqa: E402
import pack  # noqa: E402
import validate  # noqa: E402
import workzone  # noqa: E402


BS = chr(92)
LOGO = [
    " _       ______  ____  __ __    _____   ____  _   __ ______",
    "| |     / / __ " + BS + "/ __ " + BS + "/ //_/   /__  /  / __ " + BS + "/ | / // ____/",
    "| | /| / / / / / /_/ / ,<        / /  / / / /  |/ // __/",
    "| |/ |/ / /_/ / _, _/ /| |      / /__/ /_/ / /|  // /___",
    "|__/|__/" + BS + "____/_/ |_/_/ |_|     /____/" + BS + "____/_/ |_//_____/",
]
PINK, BLUE, GREEN, GREY, OFF = "\033[38;5;205m", "\033[38;5;111m", "\033[38;5;114m", "\033[38;5;245m", "\033[0m"


def console():
    """Window title, and colours in the Windows console. Returns True when we may animate."""
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleTitleW("Work Zone")
            h, mode = k.GetStdHandle(-11), ctypes.c_uint()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 4)      # let the console understand colours
        except (AttributeError, OSError):
            pass
    return sys.stdout.isatty()


def say(text=""):
    print(text, flush=True)


def header(live):
    """The logo as two halves (every other column) that slide in, then click together."""
    width = max(len(r) for r in LOGO)
    rows = [r.ljust(width) for r in LOGO]
    if not live:
        for r in rows:
            say("  " + r)
        return
    say()
    steps = [7, 5, 3, 2, 1, 1, 0]
    for n, d in enumerate(steps):
        for r in rows:
            line = [" "] * (width + 16)
            for x, c in enumerate(r):
                if c != " ":
                    odd = x % 2 == 1
                    line[x + 8 + (d if odd else -d)] = (BLUE if odd else PINK) + c + OFF
            if d == 0:
                line = [PINK + c + OFF if c.strip() else c for c in " " * 8 + r + " " * 8]
            say("[2K" + "".join(line).rstrip())      # clear the old line, then draw
        time.sleep(0.09 if d else 0)
        if n < len(steps) - 1:
            sys.stdout.write("\033[%dA" % len(rows))
    say(" " * 10 + GREEN + "fits. sealed. one piece." + OFF)
    say()


def step(n, total, label, live):
    sys.stdout.write(f"  {GREY if live else ''}[{n}/{total}]{OFF if live else ''} {label:<28}")
    sys.stdout.flush()


def done(extra="", live=True):
    say((GREEN + "ok" + OFF if live else "ok") + (f"  {extra}" if extra else ""))


def splash_close():
    try:
        import pyi_splash                    # only exists inside the packed app
        pyi_splash.close()
    except ImportError:
        pass


def check():
    """Proves this copy works: every example label is valid, a key can be made, a plug can be
    packed, signed and verified, a changed byte is refused, and the dashboard page is served."""
    problems = []
    examples = sorted(p for p in (workzone.ROOT / "examples").iterdir() if (p / "plug.json").exists())
    for ex in examples:
        errs = validate.validate_file(ex / "plug.json")
        if errs:
            problems.append(f"{ex.name}: {errs[0]}")
    with tempfile.TemporaryDirectory() as d:
        seed = keys.new_key(Path(d) / "check.key")
        data = pack.build(workzone.ROOT / "examples" / "hello", seed)
        m, _ = pack.verify(data)
        bad = bytearray(data)
        bad[len(bad) // 2] ^= 1
        try:
            pack.verify(bytes(bad))
            problems.append("a changed plug was not refused")
        except ValueError:
            pass
    httpd, state = workzone.serve(0, clear_drops=False)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        page = urllib.request.urlopen(f"http://127.0.0.1:{state.port}/", timeout=10).read()
        if state.token.encode() not in page or b"Work Zone" not in page:
            problems.append("the dashboard page was not served properly")
    finally:
        httpd.shutdown()
        httpd.server_close()
    print(f"examples checked: {len(examples)}; signed + verified: {m['id']}; tamper refused; dashboard served")
    for p in problems:
        print("PROBLEM:", p)
    print("self-check:", "OK" if not problems and len(examples) >= 12 else "FAILED")
    return 0 if not problems and len(examples) >= 12 else 1


def main(argv):
    if "--check" in argv:
        splash_close()
        return check()
    live = console()
    splash_close()
    header(live)
    step(1, 4, "unpacking", live)
    done("", live)
    examples = sorted(p for p in (workzone.ROOT / "examples").iterdir() if (p / "plug.json").exists())
    step(2, 4, f"checking {len(examples)} plugs", live)
    bad = []
    for i, ex in enumerate(examples, 1):
        if validate.validate_file(ex / "plug.json"):
            bad.append(ex.name)
        if live:
            bar = "#" * i + "-" * (len(examples) - i)
            sys.stdout.write(f"[{bar}] {i}/{len(examples)}" + "\b" * (len(bar) + 4 + len(str(i)) + len(str(len(examples)))))
            sys.stdout.flush()
            time.sleep(0.03)
    if live:
        sys.stdout.write(" " * (len(examples) + 10) + "\b" * (len(examples) + 10))
    done("" if not bad else "skipped: " + ", ".join(bad), live)
    step(3, 4, "starting the safety helper", live)
    try:
        httpd, state = workzone.serve(8770)
    except OSError:
        httpd, state = workzone.serve(0)            # 8770 is busy: use any free port
    url = f"http://127.0.0.1:{state.port}/"
    done(f"{url}  (this computer only)", live)
    step(4, 4, "opening your browser", live)
    threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    done("", live)
    say()
    say(f"  strict mode: {'ON' if state.strict else 'off'}" + ("  (risky actions ask you here first: type yes)" if state.strict else ""))
    say("  Keep this window open while you use Work Zone. Close it to stop.")
    say()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
