#include "theme.h"

// Positional, in ThemeColor order. Kept positional rather than using
// designated initialisers because the Arduino ESP32 core builds as gnu++11,
// where those are a GCC extension rather than standard.
//
// The values are the literals these colours already had, so the default look is
// unchanged apart from the small consolidation described in the commit.
uint32_t g_theme[] = {
  0x0a1020,   // TH_BG
  0x0a1828,   // TH_SURFACE
  0x1a3060,   // TH_SURFACE_2
  0x1a2840,   // TH_SURFACE_3
  0x1a2030,   // TH_SURFACE_DARK
  0x0a1e30,   // TH_TILE_BG
  0x1a3050,   // TH_BORDER
  0x28d49a,   // TH_ACCENT
  0xc8d8f0,   // TH_TEXT
  0xe8f0ff,   // TH_TEXT_BRIGHT
  0x4a6fa0,   // TH_TEXT_MUTED
  0x2a4060,   // TH_TEXT_DIM
  0xf0b838,   // TH_WARNING
  0x3a2c10,   // TH_WARNING_BG
  0x5a4420,   // TH_WARNING_PRESSED
  0xe03030,   // TH_ALERT
  0x4a7800,   // TH_LINK_ACCENT
  0x00b8d4,   // TH_COPY_ACCENT
  0x40c080,   // TH_SUCCESS_TEXT
  0x2a5030,   // TH_SUCCESS_BG
  0x1a3020,   // TH_OK_BG
  0xff8080,   // TH_DANGER_TEXT
  0x3a1010,   // TH_DANGER_BG
  0x602020,   // TH_DANGER_PRESSED
  0x000000,   // TH_POPUP_BG
  0x000000,   // TH_ON_ACCENT
};

// Declared without an explicit size above so the compiler deduces it, then
// checked here. Written as g_theme[TH_COUNT] a short initialiser would
// zero-fill silently and the missing colours would render black.
static_assert(sizeof(g_theme) / sizeof(g_theme[0]) == TH_COUNT,
              "g_theme needs one entry per ThemeColor");
