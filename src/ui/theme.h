#pragma once

#include <lvgl.h>
#include <stdint.h>

// Runtime palette.
//
// Every entry is initialised to exactly the literal it replaced, so introducing
// this table changed no pixel. It only moved the colours out of compile-time
// constants and into something that can be changed at runtime.
//
// Names describe the role a colour plays rather than the colour itself, so an
// alternative palette can reuse them without the names becoming lies. Only the
// 20 most-used colours live here (824 of the 988 lv_color_hex call sites). The
// long tail is 72 one-off accents used three times or fewer; folding those in
// means either 72 more tokens or quietly changing colours.
enum ThemeColor : uint8_t {
  TH_BG,              // page background
  TH_SURFACE,         // header bar, back/close button face
  TH_SURFACE_2,       // raised buttons, sliders, list rows
  TH_SURFACE_3,       // alternate raised surface
  TH_SURFACE_DARK,    // recessed surface
  TH_TILE_BG,         // settings tile face
  TH_BORDER,          // tile borders and pressed state
  TH_ACCENT,          // primary accent: titles, icons, active states
  TH_TEXT,            // primary body text
  TH_TEXT_BRIGHT,     // emphasised text
  TH_TEXT_MUTED,      // subtitles
  TH_TEXT_DIM,        // hints, least emphasis
  TH_WARNING,         // amber status line
  TH_WARNING_BG,      // amber panel fill
  TH_WARNING_PRESSED, // amber panel, pressed
  TH_ALERT,           // strong red badge
  TH_LINK_ACCENT,     // Link button edge, olive by default
  TH_COPY_ACCENT,     // Copy button edge, teal by default
  TH_SUCCESS_TEXT,
  TH_SUCCESS_BG,
  TH_OK_BG,
  TH_DANGER_TEXT,
  TH_DANGER_BG,
  TH_DANGER_PRESSED,
  TH_POPUP_BG,        // full-screen popup and modal backdrop
  TH_ON_ACCENT,       // text drawn on top of the accent fill
  TH_COUNT
};

extern uint32_t g_theme[TH_COUNT];

// Shorthand used at the call sites in place of lv_color_hex(0x......).
static inline lv_color_t tc(ThemeColor c) { return lv_color_hex(g_theme[c]); }

// ---------------------------------------------------------------- metadata
// Short stable ids used as form field names by the web editor, and human
// labels for both the web editor and the on-device theme screen.
const char* themeTokenId(int i);
const char* themeTokenLabel(int i);

#define THEME_PRESET_COUNT 4
const char* themePresetName(int i);
void themeApplyPreset(int i);
// -1 when the live palette matches no preset, which is what a custom scheme is.
int themeCurrentPreset();

// A palette edited in the web UI matches no preset, so without somewhere to
// keep it, tapping a preset on the device would destroy it with no way back.
// themeSave() copies the live palette into this second slot whenever it is not
// a preset, and the device offers it as a fifth choice.
bool themeHasCustom();
void themeApplyCustom();

// ------------------------------------------------------------- persistence
// Stored as one NVS key per token (th00..th19) plus "ui_gain"; the prefs
// wrapper has no putBytes, and 21 keys is well inside the NVS budget.
void themeLoad();
void themeSave();
void themeResetToDefault();

// ------------------------------------------------------------------ apply
// Colours are baked into LVGL styles when a screen is built, so a palette
// change only shows on screens built afterwards. Drops the cached overlay
// screens so they rebuild on next open. The main screen is built once at boot
// by buildUI() and is deliberately NOT rebuilt here: spool_flow.cpp keeps 16
// static pointers to children of the active screen and exposes no complete
// teardown, so cleaning the active screen would free objects it still
// references. The main screen therefore picks the palette up on restart.
void themeInvalidateScreens();

// Set by the web editor so the theme screen can repaint itself while a colour
// is being dragged. Cleared once consumed by the UI loop.
extern volatile bool theme_dirty_pending;

// True once a palette has been applied in this session. The overlay screens
// rebuild themselves, but the main screen is built once at boot and only picks
// up a new palette on the way back up, so the theme screen offers a restart
// rather than leaving the user to notice the difference and guess why.
bool themeRestartPending();
