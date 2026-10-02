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
//  themselves stand in theme_palette.h, one column per palette.
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
#define UI_COLOUR(name, dark, light, sm_dark, sm_light, fm_dark, fm_light) extern uint32_t UI_COL_##name;
#include "theme_palette.h"
#undef UI_COLOUR

#define UI_OPA_SCRIM           LV_OPA_70

// Steps added to a tile's own colour, per channel, for its pressed state and
// its border: lighter on a dark palette, darker on a light one.
extern int UI_SHADE_PRESSED;
extern int UI_SHADE_BORDER;
uint32_t uiShade(uint32_t colour, int step);

// ---- palettes ------------------------------------------------
// Stored in NVS by number: append, never reorder. The columns of
// theme_palette.h follow this order.
enum UiThemeId : uint8_t {
  UI_THEME_DARK           = 0,
  UI_THEME_LIGHT          = 1,
  UI_THEME_SPOOLMAN_DARK  = 2,
  UI_THEME_SPOOLMAN_LIGHT = 3,
  UI_THEME_FILAMAN_DARK   = 4,
  UI_THEME_FILAMAN_LIGHT  = 5,
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
// "dark", "light", "spoolman_dark", "spoolman_light", "filaman_dark",
// "filaman_light": the id the web interface speaks, and the data-theme of
// its pages.
const char* uiThemeKey(UiThemeId id);
bool uiThemeFromKey(const char* key, UiThemeId* out);

// The same family in the other lightness: palettes come in pairs, dark first.
UiThemeId uiThemeInFamily(UiThemeId id, bool dark);

// Whether the web pages take light or dark from the browser instead of from
// the scale. Theirs only: the panel keeps its palette, so this needs no
// restart and applies to the next page load.
bool uiWebFollowsSystem();
bool uiWebFollowsSystemStore(bool on);

// The palette as a table, for the web preview.
size_t uiPaletteCount();
const char* uiPaletteName(size_t i);
uint32_t uiPaletteValue(UiThemeId id, size_t i);

// ---- own colours ---------------------------------------------
// Laid over the chosen palette at boot (theme_custom.cpp). The accent
// replaces the house colour; the tone turns the hue of the ground, the
// surfaces, the lines and the grey text while every colour keeps its
// lightness, so no contrast changes. Strength scales their saturation.
#define UI_TONE_NONE          -1     // the palette's own hue
#define UI_TONE_STRENGTH_SAME 50     // the palette's own saturation
#define UI_TONE_STRENGTH_MAX  100
#define UI_RGB_MASK           0xFFFFFFu
// The label on an accent the user chose: whichever reads better on it.
#define UI_COL_ON_ACCENT_DARK  0x0b0f0d
#define UI_COL_ON_ACCENT_LIGHT 0xffffff
struct UiThemeCustom {
  bool     has_accent;
  uint32_t accent;        // 0xRRGGBB
  int16_t  tone;          // UI_TONE_NONE or a hue, 0..359
  uint8_t  strength;      // 0 grey .. UI_TONE_STRENGTH_SAME .. UI_TONE_STRENGTH_MAX
  bool     follow;        // the palette's family follows the backend
};
UiThemeCustom uiThemeCustomStored();
bool uiThemeCustomStore(const UiThemeCustom& c);
// The palette that runs for a stored choice: with follow on, the backend's
// family in the choice's lightness (BamBuddy has none and keeps the standard).
UiThemeId uiThemeResolve(UiThemeId chosen, bool follow);
// Over the palette that was just applied. Nothing to do for a default.
void uiThemeApplyCustom(const UiThemeCustom& c);
// What uiThemeApplyCustom() laid over the running palette at boot.
UiThemeCustom uiThemeCustomActive();

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
