#include "theme.h"

#include <Arduino.h>
#include <string.h>

#include "app/app_state.h"
#include "ui_common.h"
#include "services/prefs_store.h"

// Positional, in ThemeColor order. Kept positional rather than using
// designated initialisers because the Arduino ESP32 core builds as gnu++11,
// where those are a GCC extension rather than standard.
uint32_t g_theme[] = {
  0x0a1020, 0x0a1828, 0x1a3060, 0x1a2840, 0x1a2030,
  0x0a1e30, 0x1a3050, 0x28d49a, 0xc8d8f0, 0xe8f0ff,
  0x4a6fa0, 0x2a4060, 0xf0b838, 0x3a2c10, 0x5a4420, 0xe03030,
  0x4a7800, 0x00b8d4,
  0x40c080, 0x2a5030,
  0x1a3020, 0xff8080, 0x3a1010, 0x602020, 0x000000, 0x000000,
};

volatile bool theme_dirty_pending = false;

// ---------------------------------------------------------------- metadata

static const char *TOKEN_ID[] = {
  "bg", "surface", "surface2", "surface3", "surfaced",
  "tile", "border", "accent", "text", "textbright",
  "textmuted", "textdim", "warning", "warnbg", "warnpress", "alert",
  "link", "copy",
  "oktext", "okbg",
  "okbg2", "dangertext", "dangerbg", "dangerpress", "popupbg", "onaccent",
};

static const char *TOKEN_LABEL[] = {
  "Page background", "Header / bar", "Buttons, sliders", "Alt surface",
  "Recessed surface", "Settings tile", "Borders / pressed", "Accent",
  "Body text", "Bright text", "Subtitles", "Hints",
  "Warning", "Warning fill", "Warning pressed", "Alert badge",
  "Link button edge", "Copy button edge",
  "Success text", "Success fill", "OK fill",
  "Danger text", "Danger fill", "Danger pressed", "Popup backdrop", "Text on accent",
};

const char* themeTokenId(int i) {
  if (i < 0 || i >= TH_COUNT || !TOKEN_ID[i]) return "";
  return TOKEN_ID[i];
}
const char* themeTokenLabel(int i) {
  if (i < 0 || i >= TH_COUNT || !TOKEN_LABEL[i]) return "";
  return TOKEN_LABEL[i];
}

// ----------------------------------------------------------------- presets

static const uint32_t PRESETS[][TH_COUNT] = {
  // Default: the original palette, unchanged.
  { 0x0a1020, 0x0a1828, 0x1a3060, 0x1a2840, 0x1a2030,
    0x0a1e30, 0x1a3050, 0x28d49a, 0xc8d8f0, 0xe8f0ff,
    0x4a6fa0, 0x2a4060, 0xf0b838, 0x3a2c10, 0x5a4420, 0xe03030,
    0x4a7800, 0x00b8d4,
    0x40c080, 0x2a5030, 0x1a3020, 0xff8080, 0x3a1010, 0x602020, 0x000000, 0x000000 },

  // Contrast: same character, lifted off the floor. The stock palette sits
  // very close to black, which is what makes the panel read as dim even at
  // full backlight; this raises the dark end and separates the text tiers.
  { 0x121a2c, 0x1a2740, 0x2c4c86, 0x24344f, 0x1e2839,
    0x152a42, 0x2f4c78, 0x3ee9ae, 0xe4eefc, 0xffffff,
    0x8aa8cc, 0x6684ab, 0xffc84d, 0x4a3a18, 0x6e5628, 0xff5a5a,
    0x6aa800, 0x22d0ec,
    0x69f2a9, 0x2f6b42, 0x244a2e, 0xff9a9a, 0x5a1c1c, 0x7d2a2a, 0x000000, 0x000000 },

  // Light: pale surfaces, dark text. The one that actually competes with a
  // light-themed firmware for perceived brightness.
  { 0xeef2f7, 0xe0e7f0, 0xc9d8ec, 0xd6dfeb, 0xdde4ee,
    0xe6edf5, 0xb4c6dc, 0x0c7454, 0x1b2b3f, 0x0b1622,
    0x4d6480, 0x5c7086, 0x8c5f08, 0xf7e6c4, 0xecd6a8, 0xc02626,
    0x4a6a10, 0x0e7f92,
    0x186f3f, 0xbfe5cd, 0xcdebd8, 0xa32020, 0xf3d0d0, 0xe0b0b0, 0xdfe6ef, 0xffffff },

  // Amber: warm and low blue, for a scale sitting next to a printer at night.
  { 0x140d06, 0x1e1409, 0x3a2810, 0x2a1d0c, 0x241a0b,
    0x1f1509, 0x4a3418, 0xffab40, 0xf0d8b0, 0xfff0d8,
    0xa8845a, 0x96754c, 0xffd070, 0x4a3410, 0x6a4c18, 0xff6a40,
    0x7a6410, 0xb07828,
    0xc0d060, 0x3a4018, 0x2e3212, 0xff9060, 0x40180a, 0x602a12, 0x000000, 0x000000 },
};

static const char *PRESET_NAME[] = {
  "Default", "Contrast", "Light", "Amber",
};

// Adding a ThemeColor means touching six places. These turn "forgot one" into a
// build error instead of a null pointer or a black swatch at runtime.
//
// NOTE: a PRESETS *row* that is short still zero-fills silently -- C++ gives us
// no way to check the inner dimension. If you add a token, add a colour to all
// THEME_PRESET_COUNT rows by hand, or the new token renders black on every
// preset but Default.
static_assert(sizeof(g_theme) / sizeof(g_theme[0]) == TH_COUNT,
              "g_theme needs one entry per ThemeColor");
static_assert(sizeof(TOKEN_ID) / sizeof(TOKEN_ID[0]) == TH_COUNT,
              "TOKEN_ID needs one id per ThemeColor (used as the web form field name)");
static_assert(sizeof(TOKEN_LABEL) / sizeof(TOKEN_LABEL[0]) == TH_COUNT,
              "TOKEN_LABEL needs one label per ThemeColor");
static_assert(sizeof(PRESETS) / sizeof(PRESETS[0]) == THEME_PRESET_COUNT,
              "PRESETS needs one row per preset");
static_assert(sizeof(PRESET_NAME) / sizeof(PRESET_NAME[0]) == THEME_PRESET_COUNT,
              "PRESET_NAME needs one name per preset");

const char* themePresetName(int i) {
  if (i < 0 || i >= THEME_PRESET_COUNT || !PRESET_NAME[i]) return "";
  return PRESET_NAME[i];
}

// Set by anything that changes the live palette, never at boot: themeLoad()
// reads the stored values straight into g_theme without coming through here,
// so a device that starts on a saved theme does not ask to restart for it.
static bool s_restart_pending = false;

bool themeRestartPending() { return s_restart_pending; }

void themeApplyPreset(int i) {
  s_restart_pending = true;
  if (i < 0 || i >= THEME_PRESET_COUNT) return;
  memcpy(g_theme, PRESETS[i], sizeof(g_theme));
}

int themeCurrentPreset() {
  for (int p = 0; p < THEME_PRESET_COUNT; p++) {
    if (memcmp(g_theme, PRESETS[p], sizeof(g_theme)) == 0) return p;
  }
  return -1;   // custom
}

void themeResetToDefault() {
  themeApplyPreset(0);
}

// ------------------------------------------------------------- persistence

// Keyed by name, not index. Stored as th%02d, inserting a token anywhere but
// the end silently re-pointed every key after it, so an upgrade loaded the old
// value of a different colour into the new slot and scrambled the palette.
// With names, tokens can be added or reordered freely.
static void tokenKey(int i, char *buf, size_t n) {
  snprintf(buf, n, "th_%s", themeTokenId(i));
}

// Second slot, holding the last palette that was not one of the presets.
static void customKey(int i, char *buf, size_t n) {
  snprintf(buf, n, "cu_%s", themeTokenId(i));
}

bool themeHasCustom() {
  // 0xFFFFFFFF is the sentinel: a stored colour is masked to 24 bits, so it can
  // never legitimately read back as that. If any key returns something else,
  // the slot has been written.
  char key[20];
  for (int i = 0; i < TH_COUNT; i++) {
    customKey(i, key, sizeof(key));
    if (prefsGetUInt(key, 0xFFFFFFFFu) != 0xFFFFFFFFu) return true;
  }
  return false;
}

void themeApplyCustom() {
  s_restart_pending = true;
  if (!themeHasCustom()) return;
  char key[20];
  for (int i = 0; i < TH_COUNT; i++) {
    customKey(i, key, sizeof(key));
    g_theme[i] = prefsGetUInt(key, g_theme[i]) & 0xFFFFFFu;
  }
}

static void saveCustom() {
  char key[20];
  for (int i = 0; i < TH_COUNT; i++) {
    customKey(i, key, sizeof(key));
    prefsPutUInt(key, g_theme[i] & 0xFFFFFFu);
  }
}

void themeLoad() {
  char key[20];
  for (int i = 0; i < TH_COUNT; i++) {
    tokenKey(i, key, sizeof(key));
    // Default is whatever the compiled-in palette already holds, so a device
    // that has never saved a theme keeps the stock look.
    g_theme[i] = prefsGetUInt(key, g_theme[i]) & 0xFFFFFFu;
  }
}

void themeSave() {
  char key[20];
  for (int i = 0; i < TH_COUNT; i++) {
    tokenKey(i, key, sizeof(key));
    prefsPutUInt(key, g_theme[i] & 0xFFFFFFu);
  }
  // Anything that is not a preset is the user's own scheme, so keep a copy the
  // preset buttons cannot overwrite.
  if (themeCurrentPreset() < 0) saveCustom();
}

// ------------------------------------------------------------------ apply

static void dropScreen(lv_obj_t **s) {
  if (*s) { lv_obj_del(*s); *s = nullptr; }
}

void themeInvalidateScreens() {
  // Only the cached overlay screens, all of which are rebuilt by their own
  // build*Screen() on next open. Deliberately does not navigate: the caller
  // knows whether the user is sitting on the theme screen (which repaints
  // itself) or somewhere that needs sending back to the main screen.
  //
  // The main screen is not touched. It is built once at boot by buildUI() and
  // spool_flow.cpp holds 16 static pointers to children of the active screen
  // with no complete public teardown, so cleaning it would free objects that
  // module still references. It picks up the palette on restart instead.
  overlayDropAll();
  // Screens that build their own container rather than calling
  // buildOverlayScreen(&slot), so the registry does not know about them.
  dropScreen(&scr_factor);
  dropScreen(&scr_bag);
  dropScreen(&scr_extra_fields);
  dropScreen(&scr_cal_reminder);
  dropScreen(&scr_spoolman);
  dropScreen(&scr_spoolman_fail);
}
