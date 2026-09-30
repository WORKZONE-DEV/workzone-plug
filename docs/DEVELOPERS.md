# Making plugs: the developer guide

Everything you need to build a plug, seal it, test it and share it. No accounts, no servers:
Python 3 and a browser.

## 1. Five-minute plug

```
my-plug/
  plug.json        the label
  app/
    index.html     the app (any web page)
```

`plug.json`:

```json
{
  "plug": "0",
  "id": "com.yourname.hello",
  "name": "My first plug",
  "version": "0.1.0",
  "kind": "widget",
  "entry": "index.html",
  "views": ["panel"],
  "permissions": {},
  "author_key": "ed25519:0000000000000000000000000000000000000000000000000000000000000000",
  "description": "Says hello."
}
```

`author_key` is filled in with your real key when you seal it, so leave the zeros.

```
python tools/wz.py key                    make your key (once; it never leaves your computer)
python tools/wz.py fit my-plug            will it fit? plain-English reasons and fixes
python tools/wz.py pack my-plug           seal it -> my-plug.plug
python tools/wz.py verify my-plug.plug    check it the way every socket will
python tools/wz.py run my-plug.plug       run it in its own window
```

Or skip the terminal: drop the folder onto the dashboard (`start-workzone.bat`, or
`python tools/workzone.py`) and it does the same steps with buttons.

## 2. The label (`plug.json`)

| Field | What it is |
|---|---|
| `plug` | Label format. Always `"0"` for now. |
| `id` | Reverse-domain name, lowercase: `com.yourname.thing`. It stays yours: nobody else can publish under it. |
| `name` | Up to 60 characters. No hidden or control characters. |
| `version` | `major.minor.patch`. Versions only move forward. |
| `kind` | `panel`, `game`, `world`, `island`, `skin`, `tool`, `widget`, `service`, `terminal` or `feed`. Picks the icon. |
| `entry` | The start file inside `app/`, usually `index.html`. |
| `views` | Any of `panel`, `2d`, `3d`, `ascii`, `headless`. |
| `hosts` | Optional: `web`, `hud`, `world`, `desktop`, `any` (default). |
| `permissions` | Everything it may use. Left out = blocked. See below. |
| `description` | Optional, up to 280 characters. |
| `built_on` | Filled in by `wz remix`: the plugs this one was built on (credit travels with the file). |

The full rules are in [socket/plug.schema.json](../socket/plug.schema.json). Both checkers (Python and
JavaScript) use exactly that file.

## 3. Powers (`permissions`)

Ask for as little as you can. The person sees every power as a tick box and can untick any of them,
so your plug should keep working (more quietly) without them.

| Power | Example | What it allows |
|---|---|---|
| `network` | `["api.example.com"]` | Requests to exactly those https hosts, through the gateway. Never local or home-network addresses. |
| `storage` | `"64KB"` | A private key/value store of that size. |
| `events` | `["clock.tick"]` | Send and receive those named events. Plugs only hear each other when the person links them. |
| `identity` | `"public-key"` | The person's public key. Never a name, email or anything personal. |
| `ai` | `["notes.search"]` | Those AI tools, only if the person has them set up and switched on. |
| `ui` | `"panel"` | How it wants to be shown. |

## 4. Talking to the socket

A plug runs in a sealed frame with no network and no access to the page around it. Its only way out
is `postMessage` to the socket, and every message is checked against the label, answered and logged.

```js
// tell the socket you're ready
parent.postMessage({ topic: 'plug.ready' }, '*');

// ask for something and get an answer back: add an id
function ask(msg) {
  return new Promise(function (resolve) {
    var id = Math.random().toString(36).slice(2);
    addEventListener('message', function on(e) {
      if (e.data && e.data.topic === 'reply' && e.data.id === id) { removeEventListener('message', on); resolve(e.data); }
    });
    parent.postMessage(Object.assign({ id: id }, msg), '*');
  });
}

ask({ topic: 'storage.set', key: 'score', value: 12 });
ask({ topic: 'storage.get', key: 'score' }).then(function (r) { /* r.ok, r.reply = 12 */ });
ask({ topic: 'net.fetch', url: 'https://api.example.com/data', method: 'GET' });
ask({ topic: 'ai.call', tool: 'notes.search', args: { q: 'plugs' } });
parent.postMessage({ topic: 'event.publish', name: 'clock.tick', data: 1 }, '*');

// events from linked plugs arrive like this
addEventListener('message', function (e) {
  if (e.data && e.data.topic === 'event' && e.data.name === 'clock.tick') { /* ... */ }
});
```

A refused request comes back with `ok: false` and a plain `reason`. Keep asking for things you never
declared and the watchdog pulls the plug (20 refusals, a message flood, or trying to navigate away).
Asking for a power the person unticked is fine: it's refused quietly and never counts against you.

## 5. More than one file

Put scripts, styles, pictures and sounds in `app/` and link them normally
(`<script src="app.js">`, `<link rel="stylesheet" href="style.css">`, `<img src="img/a.svg">`).
When the plug runs, the socket folds them into the page from the sealed file. Data files
(`.wasm`, `.json`, `.txt`, `.csv`) are read with `plugFile('name')` (bytes) or `plugText('name')`.
See `examples/gallery` and `examples/wasm-add`.

## 6. Sharing: the registry shelf

A registry is a folder anyone can host (a USB stick, a shared drive, a git repo):

```
python tools/registry.py add my-plug.plug [REG_DIR]    checked, then put on the shelf
python tools/registry.py list [REG_DIR]
python tools/registry.py check [REG_DIR]               re-check every plug against the index
```

`wz shelf my-plug.plug` puts it on your own shelf (`WORKZONE_HOME/registry`), which shows in the
dashboard's Library. The shelf follows the socket's rules: every plug passes every check, a name stays
with its first maker, versions only go forward, and the same version can't be swapped for different
bytes. The index is only a list; every plug is checked again when it's used.

## 7. Update reminder

The dashboard reminds you about once a month to check for a newer, safer version (switch it off in the
menu under "Show only what you use"). To let it ask for the newest version number itself, create
`WORKZONE_HOME/update.json`:

```json
{ "url": "https://example.com/workzone/latest.json" }
```

That address should answer `{"version": "1.11.0", "notes": "what changed"}`. Work Zone only ever *tells*
you; it never downloads or installs anything.

## 8. Before you share

- `wz fit` shows no `[no]` items and `wz verify` passes.
- It works with every power unticked (or says politely what it needs).
- Bump the version for every change you share.
- Security problems: see [SECURITY.md](../SECURITY.md). Everything else: GitHub issues.
