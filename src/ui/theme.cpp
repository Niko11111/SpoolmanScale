#include "ui/theme.h"

#include <string.h>

#include "services/prefs_store.h"

// NVS key of the chosen palette. A uchar: UiThemeId.
#define THEME_PREF_KEY  "ui_theme"

// Every colour starts out dark, so anything that runs before uiThemeBegin()
// still draws in the palette the scale has always had.
#define UI_COLOUR(name, dark, light) uint32_t UI_COL_##name = dark;
#include "ui/theme_palette.h"
#undef UI_COLOUR

// Per channel. Dark lightens a tile by 16 and 24, light darkens it as much.
#define SHADE_PRESSED_STEP  16
#define SHADE_BORDER_STEP   24
int UI_SHADE_PRESSED = SHADE_PRESSED_STEP;
int UI_SHADE_BORDER  = SHADE_BORDER_STEP;

static UiThemeId s_active = UI_THEME_DARK;

static const char* const PALETTE_NAMES[] = {
#define UI_COLOUR(name, dark, light) #name,
#include "ui/theme_palette.h"
#undef UI_COLOUR
};

static const uint32_t PALETTE_DARK[] = {
#define UI_COLOUR(name, dark, light) dark,
#include "ui/theme_palette.h"
#undef UI_COLOUR
};

static const uint32_t PALETTE_LIGHT[] = {
#define UI_COLOUR(name, dark, light) light,
#include "ui/theme_palette.h"
#undef UI_COLOUR
};

static const char* const THEME_KEYS[UI_THEME_COUNT] = { "dark", "light" };

uint32_t uiShade(uint32_t colour, int step) {
  uint32_t out = 0;
  for (int shift = 0; shift <= 16; shift += 8) {
    int c = (int)((colour >> shift) & 0xFF) + step;
    if (c < 0) c = 0;
    if (c > 0xFF) c = 0xFF;
    out |= (uint32_t)c << shift;
  }
  return out;
}

static void applyPalette(UiThemeId id) {
  const bool light = (id == UI_THEME_LIGHT);
#define UI_COLOUR(name, dark, light_value) UI_COL_##name = light ? light_value : dark;
#include "ui/theme_palette.h"
#undef UI_COLOUR
  UI_SHADE_PRESSED = light ? -SHADE_PRESSED_STEP : SHADE_PRESSED_STEP;
  UI_SHADE_BORDER  = light ? -SHADE_BORDER_STEP  : SHADE_BORDER_STEP;
  s_active = id;
}

void uiThemeBegin() {
  uint8_t stored = prefsGetUChar(THEME_PREF_KEY, UI_THEME_DARK);
  if (stored >= UI_THEME_COUNT) stored = UI_THEME_DARK;
  applyPalette((UiThemeId)stored);

  // LVGL builds its default theme when the display driver registers, from
  // lv_conf.h. Re-initialised here with the palette's two colours; the mode
  // stays LV_THEME_DEFAULT_DARK for both palettes, because every surface this
  // code draws sets its own colour and only the leftovers come from LVGL.
  lv_disp_t *disp = lv_disp_get_default();
  if (!disp) return;
  lv_theme_t *th = lv_theme_default_init(disp, lv_color_hex(UI_COL_LV_PRIMARY),
                                         lv_color_hex(UI_COL_LV_SECONDARY),
                                         LV_THEME_DEFAULT_DARK, LV_FONT_DEFAULT);
  lv_disp_set_theme(disp, th);
}

UiThemeId uiThemeActive() { return s_active; }

UiThemeId uiThemeStored() {
  uint8_t stored = prefsGetUChar(THEME_PREF_KEY, UI_THEME_DARK);
  return stored < UI_THEME_COUNT ? (UiThemeId)stored : UI_THEME_DARK;
}

bool uiThemeStore(UiThemeId id) {
  if (id >= UI_THEME_COUNT) return false;
  return prefsPutUChar(THEME_PREF_KEY, (uint8_t)id);
}

const char* uiThemeKey(UiThemeId id) {
  return id < UI_THEME_COUNT ? THEME_KEYS[id] : THEME_KEYS[UI_THEME_DARK];
}

bool uiThemeFromKey(const char* key, UiThemeId* out) {
  if (!key || !out) return false;
  for (uint8_t i = 0; i < UI_THEME_COUNT; i++) {
    if (strcmp(key, THEME_KEYS[i]) == 0) { *out = (UiThemeId)i; return true; }
  }
  return false;
}

size_t uiPaletteCount() { return sizeof(PALETTE_DARK) / sizeof(PALETTE_DARK[0]); }

const char* uiPaletteName(size_t i) {
  return i < uiPaletteCount() ? PALETTE_NAMES[i] : "";
}

uint32_t uiPaletteValue(UiThemeId id, size_t i) {
  if (i >= uiPaletteCount()) return 0;
  return id == UI_THEME_LIGHT ? PALETTE_LIGHT[i] : PALETTE_DARK[i];
}
