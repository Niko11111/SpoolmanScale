#pragma once

#include <lvgl.h>
#include <stdint.h>

// ============================================================
//  THEME
//
//  The one table for what the panel looks like: colours, type
//  sizes, radii, the house measurements of a button. Every colour
//  in src/ui and src/app has a name; the ratchet counts one written
//  as a number (inline_color_hex, raw_color_hex). The colours
//  themselves stand in theme_palette.h, dark and light side by side.
//
//  Names say what a colour is for, not what it looks like:
//  UI_COL_CAPTION rather than "dim blue". A palette that swaps
//  the blue for grey changes one line and every caption follows.
//  Two names may share a value when their roles differ (INK_FAINT
//  and RULE): a palette can then set them apart. A name that
//  carries a widget (UI_COL_COPY_*) is a colour only that widget
//  uses.
//
//  UI_COL_<name> is a variable, filled at boot from the palette the
//  user chose (uiThemeBegin). Written in capitals so a call site
//  reads the same as when these were constants. Never read one in
//  #if, constexpr or a static initialiser: that would take the dark
//  value before the palette is chosen. A change of palette takes
//  effect with a restart, because LVGL copies a colour into the
//  object when the object is made.
// ============================================================

// ---- colours -------------------------------------------------
#define UI_COLOUR(name, dark, light) extern uint32_t UI_COL_##name;
#include "theme_palette.h"
#undef UI_COLOUR

#define UI_OPA_SCRIM           LV_OPA_70

// Steps added to a tile's own colour, per channel, for its pressed state and
// its border: lighter on a dark palette, darker on a light one.
extern int UI_SHADE_PRESSED;
extern int UI_SHADE_BORDER;
uint32_t uiShade(uint32_t colour, int step);

// ---- palettes ------------------------------------------------
enum UiThemeId : uint8_t {
  UI_THEME_DARK  = 0,
  UI_THEME_LIGHT = 1,
  UI_THEME_COUNT
};

// Reads the stored choice and fills every UI_COL_* from it, then hands LVGL's
// default theme its two colours. After loadPrefs() and the display driver,
// before the first screen is built.
void uiThemeBegin();
UiThemeId uiThemeActive();
UiThemeId uiThemeStored();
// Stores the choice for the next boot. The running palette stays.
bool uiThemeStore(UiThemeId id);
// "dark", "light": the id the web interface speaks.
const char* uiThemeKey(UiThemeId id);
bool uiThemeFromKey(const char* key, UiThemeId* out);

// The palette as a table, for the web preview.
size_t uiPaletteCount();
const char* uiPaletteName(size_t i);
uint32_t uiPaletteValue(UiThemeId id, size_t i);

// ---- content -------------------------------------------------
// Fixed colours next to data, not part of the look: a palette may
// leave them alone. Colours that come from a spool are never here.
#define UI_COL_ON_BRIGHT_FILL  0x000000   // a label on a light filament colour
#define UI_COL_ON_DARK_FILL    0xffffff   // a label on a dark one
#define UI_COL_QR_DARK         0x000000   // a QR code must stay black on white to scan
#define UI_COL_QR_LIGHT        0xffffff
#define UI_COL_SWATCH_NONE     0x333333   // a spool without a colour
#define UI_COL_SWATCH_GLASS    0xdce6f0   // a transparent filament

// ---- type ----------------------------------------------------
#define UI_FONT_CAPTION        (&lv_font_montserrat_ext_12)
#define UI_FONT_SMALL          (&lv_font_montserrat_ext_14)
#define UI_FONT_BODY           (&lv_font_montserrat_ext_16)
#define UI_FONT_TITLE          (&lv_font_montserrat_ext_18)
#define UI_FONT_HEADLINE       (&lv_font_montserrat_ext_20)
#define UI_FONT_ICON           (&lv_font_montserrat_ext_24)

// ---- shapes --------------------------------------------------
#define UI_RADIUS_BOX          12   // a popup's box, a settings tile
#define UI_RADIUS_ROW          10   // a settings row
#define UI_RADIUS_BTN          8
#define UI_RADIUS_INPUT        6
#define UI_TOUCH_MIN           44   // the smallest thing a finger is asked to hit
#define UI_POPUP_W             400  // a two button question
#define UI_POPUP_BTN_W         170
#define UI_POPUP_BTN_H         56

// ---- the card: question, waiting, result ---------------------
// One footprint for the three stages of something the user set off: the
// question, the card that stands while it runs, and the result. Measured off
// the tag write question (BOX_H and BTN_Y in tag_write_popup.cpp), so each
// stage appears exactly where the one before stood and only its contents
// change. The row of answers is where the waiting card's bar runs and where
// the result's OK button counts down.
#define UI_CARD_H              260
#define UI_CARD_ICON_Y          14
#define UI_CARD_TITLE_Y         52
#define UI_CARD_TEXT_Y          98
#define UI_CARD_TEXT_PAD        40   // what the text stays clear of, left and right together
#define UI_CARD_ROW_X           12   // the answer row's inset, left and right
#define UI_CARD_ROW_Y          186   // its top, UI_POPUP_BTN_H high
