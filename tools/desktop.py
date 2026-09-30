"""Desktop host (Phase 8.1): run one plug in its own clean app window.

  python tools/desktop.py FILE.plug          a normal window
  python tools/desktop.py FILE.plug mini     a small side window (430 x 680)

What happens:
  1. the plug is checked here first (every layer); a plug that fails never gets a window
  2. a private helper starts on this computer only (127.0.0.1, a random port, its own token)
  3. an app window opens (Edge or Chrome with no address bar; your normal browser if neither is found)
  4. the window collects the plug ONCE, asks you, then runs it in the same locked box as every host
  5. close the window (or press Ctrl+C here) and everything stops

The window uses its own browser profile under WORKZONE_HOME, so it never sees your normal
browsing, cookies or logins. Standard library only.
"""
import os
import shutil
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pack  # noqa: E402
import workzone  # noqa: E402

SIZES = {"normal": (1100, 760), "mini": (430, 680)}
WINDOWS_BROWSERS = [
    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
    r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
]
OTHER_BROWSERS = ["microsoft-edge", "google-chrome", "chromium", "chromium-browser", "brave-browser"]


def find_app_browser():
    """A browser that can open a chromeless app window, or None."""
    if os.name == "nt":
        for p in WINDOWS_BROWSERS:
            p = os.path.expandvars(p)
            if os.path.isfile(p):
                return p
    mac = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if os.path.isfile(mac):
        return mac
    for name in OTHER_BROWSERS:
        found = shutil.which(name)
        if found:
            return found
    return None


def app_command(browser, url, size="normal"):
    w, h = SIZES.get(size, SIZES["normal"])
    profile = workzone.home() / "desktop-profile"     # its own profile: never your cookies or logins
    return [browser, f"--app={url}", f"--window-size={w},{h}", f"--user-data-dir={profile}",
            "--no-first-run", "--no-default-browser-check"]


def run(plug_file, size="normal", open_window=True):
    """Check the plug, start a private helper, open the window. Returns (manifest, httpd, url, process)."""
    data = Path(plug_file).read_bytes()
    m, _ = pack.verify(data)                          # raises with a plain reason if it doesn't pass
    httpd, state = workzone.serve(0, clear_drops=False)   # a dashboard may be open too: leave its drops alone
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    hid = workzone.hand_off(state, data)
    url = f"http://127.0.0.1:{state.port}/ui/desktop.html#h={hid}"
    proc = None
    if open_window:
        browser = find_app_browser()
        if browser:
            proc = subprocess.Popen(app_command(browser, url, size))
        else:
            webbrowser.open(url)
    return m, httpd, url, proc


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    size = "mini" if len(argv) > 1 and argv[1].lower() == "mini" else "normal"
    try:
        m, httpd, url, proc = run(argv[0], size)
    except (OSError, ValueError) as e:
        print(f"Not opened: {e}")
        return 1
    print(f"{m['name']} {m['version']} passed every check. Opening its window (this computer only).")
    print("Close the window, or press Ctrl+C here, to stop.")
    try:
        if proc:
            proc.wait()
        else:
            threading.Event().wait()                  # plain browser tab: stop with Ctrl+C
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
    print("Stopped. Nothing left running.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
