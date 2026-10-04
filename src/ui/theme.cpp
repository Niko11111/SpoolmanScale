#include "ui/theme.h"

#include <string.h>

#include "services/prefs_store.h"

// NVS key of the chosen palette. A uchar: UiThemeId.
#define THEME_PREF_KEY  "ui_theme"
#define WEB_OS_PREF_KEY "ui_web_os"     // bool

// Every colour starts out dark, so anything that runs before uiThemeBegin()
// still draws in the palette the scale has always had.
#define UI_COLOUR(name, dark, light, sm_dark, sm_light, fm_dark, fm_light) uint32_t UI_COL_##name = dark;
#include "ui/theme_palette.h"
#undef UI_COLOUR

// Per channel. A dark palette lightens a tile by 16 and 24, a light one
// darkens it as much.
#define SHADE_PRESSED_STEP  16
#define SHADE_BORDER_STEP   24
int UI_SHADE_PRESSED = SHADE_PRESSED_STEP;
int UI_SHADE_BORDER  = SHADE_BORDER_STEP;

static UiThemeId s_active = UI_THEME_DARK;

static const char* const PALETTE_NAMES[] = {
#define UI_COLOUR(name, dark, light, sm_dark, sm_light, fm_dark, fm_light) #name,
#include "ui/theme_palette.h"
#undef UI_COLOUR
};

#define PALETTE_SIZE (sizeof(PALETTE_NAMES) / sizeof(PALETTE_NAMES[0]))

// Where each colour lands, in table order: one loop fills them all instead of
// one assignment per colour and palette.
static uint32_t* const PALETTE_VARS[PALETTE_SIZE] = {
#define UI_COLOUR(name, dark, light, sm_dark, sm_light, fm_dark, fm_light) &UI_COL_##name,
#include "ui/theme_palette.h"
#undef UI_COLOUR
};

static const uint32_t PALETTES[UI_THEME_COUNT][PALETTE_SIZE] = {
  {
#define UI_COLOUR(name, dark, light, sm_dark, sm_light, fm_dark, fm_light) dark,
#include "ui/theme_palette.h"
#undef UI_COLOUR
  },
  {
#define UI_COLOUR(name, dark, light, sm_dark, sm_light, fm_dark, fm_light) light,
#include "ui/theme_palette.h"
#undef UI_COLOUR
  },
  {
#define UI_COLOUR(name, dark, light, sm_dark, sm_light, fm_dark, fm_light) sm_dark,
#include "ui/theme_palette.h"
#undef UI_COLOUR
  },
  {
#define UI_COLOUR(name, dark, light, sm_dark, sm_light, fm_dark, fm_light) sm_light,
#include "ui/theme_palette.h"
#undef UI_COLOUR
  },
  {
#define UI_COLOUR(name, dark, light, sm_dark, sm_light, fm_dark, fm_light) fm_dark,
#include "ui/theme_palette.h"
#undef UI_COLOUR
  },
  {
#define UI_COLOUR(name, dark, light, sm_dark, sm_light, fm_dark, fm_light) fm_light,
#include "ui/theme_palette.h"
#undef UI_COLOUR
  },
};

struct ThemeInfo {
  const char *key;   // what the web interface speaks
  bool dark;         // which way a tile's shade goes
};

static const ThemeInfo THEMES[UI_THEME_COUNT] = {
  { "dark",           true  },
  { "light",          false },
  { "spoolman_dark",  true  },
  { "spoolman_light", false },
  { "filaman_dark",   true  },
  { "filaman_light",  false },
};

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
  for (size_t i = 0; i < PALETTE_SIZE; i++) *PALETTE_VARS[i] = PALETTES[id][i];
  const int dir = THEMES[id].dark ? 1 : -1;
  UI_SHADE_PRESSED = dir * SHADE_PRESSED_STEP;
  UI_SHADE_BORDER  = dir * SHADE_BORDER_STEP;
  s_active = id;
}

void uiThemeBegin() {
  // After backendLoadSettings(): following the backend needs its mode.
  const UiThemeCustom own = uiThemeCustomStored();
  applyPalette(uiThemeResolve(uiThemeStored(), own.follow));
  uiThemeApplyCustom(own);

  // LVGL builds its default theme when the display driver registers, from
  // lv_conf.h. Re-initialised here with the palette's two colours; the mode
  // stays LV_THEME_DEFAULT_DARK for every palette, because every surface this
  // code draws sets its own colour and only the leftovers come from LVGL.
  lv_disp_t *disp = lv_disp_get_default();
  if (!disp) return;
  lv_theme_t *th = lv_theme_default_init(disp, lv_color_hex(UI_COL_LV_PRIMARY),
                                         lv_color_hex(UI_COL_LV_SECONDARY),
                                         LV_THEME_DEFAULT_DARK, LV_FONT_DEFAULT);
  lv_disp_set_theme(disp, th);
}

UiThemeId uiThemeActive() { return s_active; }

bool uiThemeIsDark() { return THEMES[s_active].dark; }

UiThemeId uiThemeStored() {
  uint8_t stored = prefsGetUChar(THEME_PREF_KEY, UI_THEME_DARK);
  return stored < UI_THEME_COUNT ? (UiThemeId)stored : UI_THEME_DARK;
}

bool uiThemeStore(UiThemeId id) {
  if (id >= UI_THEME_COUNT) return false;
  return prefsPutUChar(THEME_PREF_KEY, (uint8_t)id);
}

const char* uiThemeKey(UiThemeId id) {
  return THEMES[id < UI_THEME_COUNT ? id : UI_THEME_DARK].key;
}

UiThemeId uiThemeInFamily(UiThemeId id, bool dark) {
  const uint8_t first = (uint8_t)(id < UI_THEME_COUNT ? id : UI_THEME_DARK) & ~1u;
  return (UiThemeId)(dark ? first : first + 1);
}

bool uiWebFollowsSystem() { return prefsGetBool(WEB_OS_PREF_KEY, false); }

bool uiWebFollowsSystemStore(bool on) { return prefsPutBool(WEB_OS_PREF_KEY, on); }

bool uiThemeFromKey(const char* key, UiThemeId* out) {
  if (!key || !out) return false;
  for (uint8_t i = 0; i < UI_THEME_COUNT; i++) {
    if (strcmp(key, THEMES[i].key) == 0) { *out = (UiThemeId)i; return true; }
  }
  return false;
}

size_t uiPaletteCount() { return PALETTE_SIZE; }

const char* uiPaletteName(size_t i) {
  return i < PALETTE_SIZE ? PALETTE_NAMES[i] : "";
}

uint32_t uiPaletteValue(UiThemeId id, size_t i) {
  if (i >= PALETTE_SIZE || id >= UI_THEME_COUNT) return 0;
  return PALETTES[id][i];
}
