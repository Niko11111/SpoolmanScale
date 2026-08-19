#pragma once

#include <lvgl.h>
#include <stdint.h>

// Runtime palette.
//
// Names describe the role a colour plays rather than the colour itself, so an
// alternative palette can reuse them without the names becoming lies.
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
  TH_WARNING,         // amber status text
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
