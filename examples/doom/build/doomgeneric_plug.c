// Doom inside a plug: the "platform" file that connects the doomgeneric engine (GPL) to the plug's page.
// Built to WebAssembly in the cloud by .github/workflows/build-doom.yml. It has no network, no files and
// no storage: the game data is handed to it from the sealed plug, pictures go to a canvas, keys come in.
#include <emscripten.h>
#include <stdint.h>
#include "doomgeneric.h"
#include "doomkeys.h"

#define QUEUE 64
static unsigned short keys[QUEUE];
static unsigned int kread = 0, kwrite = 0;

// Called from the page for every key press/release (already translated to Doom's key codes).
EMSCRIPTEN_KEEPALIVE void plug_key(int pressed, int code) {
  keys[kwrite++ % QUEUE] = (unsigned short)(((pressed ? 1 : 0) << 8) | (code & 0xff));
}

// Hand each finished frame to the page, which paints it on a canvas.
EM_JS(void, js_draw, (uint32_t *buf, int w, int h), {
  if (Module.onFrame) Module.onFrame(HEAPU32.subarray(buf >> 2, (buf >> 2) + w * h), w, h);
});
EM_JS(void, js_title, (const char *t), {
  if (Module.onTitle) Module.onTitle(UTF8ToString(t));
});

void DG_Init(void) {}
void DG_DrawFrame(void) { js_draw(DG_ScreenBuffer, DOOMGENERIC_RESX, DOOMGENERIC_RESY); }
void DG_SleepMs(uint32_t ms) { (void)ms; }            // the browser's frame loop does the waiting
uint32_t DG_GetTicksMs(void) { return (uint32_t)emscripten_get_now(); }
int DG_GetKey(int *pressed, unsigned char *key) {
  if (kread == kwrite) return 0;
  unsigned short k = keys[kread++ % QUEUE];
  *pressed = k >> 8;
  *key = (unsigned char)(k & 0xff);
  return 1;
}
void DG_SetWindowTitle(const char *title) { js_title(title); }

int main(int argc, char **argv) {
  doomgeneric_Create(argc, argv);
  emscripten_set_main_loop(doomgeneric_Tick, 0, 1);  // one game tick per screen refresh
  return 0;
}
