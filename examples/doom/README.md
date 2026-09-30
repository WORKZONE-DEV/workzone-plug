# Doom (Freedoom) plug

The classic Doom engine running inside a plug with **zero powers**: no internet, no storage, no access to
anything outside its box. It shows the Plug can take a big, real program written in C and seal it.

| Part | What it is | Licence |
|---|---|---|
| `app/doom.js` | the **doomgeneric** engine compiled to WebAssembly (one file) | GPL-2.0, see `app/DOOMGENERIC-LICENSE.txt` |
| `app/freedoom1.wad` | **Freedoom Phase 1**, free levels, pictures and sounds | BSD-3-Clause, see `app/FREEDOOM-COPYING.txt` |
| `app/index.html`, `build/doomgeneric_plug.c` | the small glue that connects the engine to the plug | GPL-2.0 (because it links the engine) |

This folder is licensed as above; the rest of the project stays MIT. The original Doom game files are
**not** included. If you own Doom, you can replace `freedoom1.wad` with your own `DOOM.WAD` (and change
the name in `app/index.html`), then seal it again with `wz pack`.

## How it was built

1. `.github/workflows/build-doom.yml` compiles the engine in the cloud (GitHub Actions), so nobody needs a
   compiler on their own computer.
2. `wz fit examples/doom` then `wz pack`, `wz verify`, `wz shelf` and `wz run doom.plug`.

Controls: arrows move, Ctrl fire, Space use/open, Enter select, Esc menu, 1-7 weapons. On phones, on-screen buttons appear.
