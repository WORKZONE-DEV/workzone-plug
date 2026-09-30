"""One-click start: runs the Work Zone helper on this computer and opens it in your browser.

This is what the downloadable app runs (built in the cloud by .github/workflows/release.yml).
Keep its window open while you use Work Zone: strict mode asks you to type "yes" there.

  python tools/launch.py            start and open the browser
  python tools/launch.py --check    self-check with our own tools, then exit (the build runs this)
"""
import sys
import tempfile
import threading
import urllib.request
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keys  # noqa: E402
import pack  # noqa: E402
import validate  # noqa: E402
import workzone  # noqa: E402


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
        return check()
    try:
        httpd, state = workzone.serve(8770)
    except OSError:
        httpd, state = workzone.serve(0)            # 8770 is busy: use any free port
    url = f"http://127.0.0.1:{state.port}/"
    print(f"Work Zone is running (this computer only): {url}")
    print("Keep this window open while you use it. Close it to stop Work Zone.")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
