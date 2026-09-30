# Work Zone Plug

<p align="center"><img src="docs/logo.svg" alt="WORK ZONE: two halves that don't fit, then click together and seal" width="684"></p>

**One signed file = one app that snaps into any host.** Deny by default. Holds no user data.

A **plug** is one `.plug` file: a small app, a label saying what it may touch, and its maker's
signature. The **socket** checks the file, asks you, and runs it in a locked box.
It can only use what it declared. Change one byte and it won't run.

## Start

1. Install Python 3.10 or newer.
2. Double-click `start-workzone.bat` (Windows), or run:

```bash
python tools/workzone.py
```

3. The dashboard opens at http://127.0.0.1:8770. Click **hello** in the Library.

## Folders

| Folder | What is in it |
|---|---|
| `ui/` | Every screen: the dashboard, the page that opens a `.plug` file, and the "what is this" page |
| `socket/` | The safety engine: checks the file, locks the app in a box, watches it, and the rules every plug label must follow |
| `tools/` | The commands: make a key, pack, check, fit, run |
| `examples/` | 12 ready plugs, including Doom, a media player and live space data |
| `tests/` | Proof it works |
| `docs/` | How to make your own plug |
| `devices/` | How devices work, and device profiles (an example TV) |

## Commands

```bash
python tools/wz.py                 # a simple menu with everything
python tools/wz.py fit my-site     # will this folder work as a plug?
```

Making your own plug: [docs/DEVELOPERS.md](docs/DEVELOPERS.md).

## Tests

```bash
python -m unittest discover -s tests
node --test --test-concurrency=1 "tests/js/*.test.mjs"
```

Every check has a test that proves it can say no. Every single byte of a plug is flipped in turn,
and every flip is rejected.

## Safety

Risky actions (making a key, sealing code, going online, network scans, device switches) never
happen on a click. You press and hold, and in strict mode (on by default) you also type `yes` in the
Work Zone terminal window, so nothing driving your browser, an AI helper included, can do them alone.

Security problems: please report privately, see [SECURITY.md](SECURITY.md).

## Licence

MIT: free to use, change and share. See [LICENSE](LICENSE).
