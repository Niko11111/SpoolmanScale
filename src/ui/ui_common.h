#pragma once

#include <lvgl.h>

#include "services/spool_color.h"
#include "services/spool_start.h"
#include "services/text_util.h"
#include "theme.h"

void addBackButton(lv_obj_t *parent, lv_event_cb_t cb);
// The "?" circle in the header row, between the centred title and the close
// button - the one gap on a sub screen nothing else wants. Opens the info
// popup with the two strings.
lv_obj_t* addHeaderHelp(lv_obj_t *scr, int title_id, int text_id);
// Returns the button, for a screen that has more to close than showMainScreen()
// knows about.
lv_obj_t* addCloseButton(lv_obj_t *parent);
void buildSubHeader(lv_obj_t *parent, const char *title,
                    lv_event_cb_t back_cb, const char *back_hint = nullptr);
lv_obj_t* buildOverlayScreen();
// The resting look of a secondary button: "Later", an option not chosen.
// After the button's own border width, which it overrides. Dark fills it with
// LINE as it always has; on a light palette LINE is a mid tone that weighs
// more than the light green primary beside it, so the button takes the
// quiet row fill with the row's border.
void uiSecondaryFill(lv_obj_t *btn);

// A countdown drawn as a fill inside its button, `full_w` wide at the start.
// It is the share of the time left and hangs from the button's right edge, so
// its left edge travels with the reading direction as the time runs out. Set
// from the loop on every pass rather than run as an lv_anim: a blocking fetch
// would leave an animation running ahead of the time it shows. `drawn_w`
// remembers the last width, so a pass without a change draws nothing.
void uiCountdownFillSet(lv_obj_t *fill, lv_coord_t full_w, lv_coord_t *drawn_w,
                        uint32_t remaining_ms, uint32_t total_ms);

// Something lies over the main screen. Every overlay of this firmware covers
// the whole panel, and nothing of the main screen does, so the size says it
// without a list of screens that would fall behind the next one added.
bool uiMainScreenCovered();

// Frees a screen object that is about to be replaced and clears the pointer.
// Call at the top of every build*Screen() function: without it the previous
// object is orphaned in LVGL's memory and never reclaimed.
// Uses lv_obj_del_async(), so the object is destroyed at the end of the
// current lv_timer_handler() pass. That keeps it safe even when called from
// an event callback belonging to the screen itself.
// No-op when the pointer is already null, so callers that clean up on their
// own stay correct.
void releaseScreen(lv_obj_t **scr);

// One snapshot of LVGL's memory (hardware/lvgl_mem.h), tagged so a log can be
// read back per list. free= is what is left of the internal budget, the
// figure a list runs into, so the numbers that matter are the ones taken
// before the rows exist.
//
// What an exhausted pool did was long noted here as while(1) from
// LV_USE_ASSERT_MALLOC - a freeze, no reboot. That is wrong for the case that
// matters: lv_obj_class_create_obj() (lv_obj_class.c:47) returns NULL without
// asserting anything, and lv_obj_create() / lv_label_create() hand that
// straight to lv_obj_class_init_obj(), which writes to obj->layout_inv. So a
// list that outgrows the pool is a null dereference, which on the ESP32 is
// "PANIC (exception/abort)" and on the card is no explanation at all.
// Reproduced in the simulator, see lvPoolHasRoomForRow() below.
//
// Call it in pairs around a list build, "<name>/pre" and "<name>/post", with
// rows = 0 on the pre call. The cost of one row is then
//   (free of pre - free of post) / rows
// Silent unless sd_verbose is on, so it costs nothing in normal operation.
void logLvMem(const char* tag, int rows);

// Whether internal RAM can still take one more list row. Asked before a row is
// built rather than after each object in it: a row is five objects, and
// running out between the second and the third was the crash above. Since
// LVGL can fall back to PSRAM that crash is gone, but a list still stops
// here: rows in PSRAM scroll with a stutter, so a list is no longer than the
// old pool allowed.
//
// The reserve scales with the pointer width, so the same number covers the
// device and the 64 bit host the simulator runs on, where every object is
// about twice the size.
#define LV_ROW_RESERVE_BYTES  (3072u * (sizeof(void*) / 4u))
bool lvPoolHasRoomForRow();

// A list that lvPoolHasRoomForRow() cut short is often cut by a passing low,
// not by a full pool: a transfer's WiFi buffers hold some 25 kB of the
// internal heap for a second or two (07.11.2026). A screen notes the cut and
// builds the list again once there is room, a few times at most.
#define LV_CUT_RETRY_MS  700
#define LV_CUT_RETRIES   4
struct LvCutRetry {
  uint32_t cut_ms;   // lv_tick_get() when a list was cut, 0: none cut
  uint8_t  tries;    // lists built again since the last reset
};
// lvPoolHasRoomForRow(), noting a refusal in `r`.
bool lvRoomForRowNoted(LvCutRetry* r);
// True once for a noted cut at least LV_CUT_RETRY_MS old, when there is room
// for a row again and tries are left.
bool lvCutRetryDue(LvCutRetry* r);
// A list the user asked for: the tries start over.
void lvCutRetryReset(LvCutRetry* r);

// Neutral grey for a colour swatch with no usable colour behind it.
#define SWATCH_FALLBACK_COLOR UI_COL_SWATCH_NONE

// What a clear filament is drawn in when nothing names a tint for it: the
// glass white the filament databases use for "clear".
#define SWATCH_GLASS_COLOR    UI_COL_SWATCH_GLASS

// A filament that lets light through is drawn as a vertical fade, from its
// hue at the top into the screen ground at the bottom. It reads as glass, the
// hue stays recognisable at the top, and it cannot be mistaken for an opaque
// spool of a darker colour, which a plain half-transparent fill was. These
// say how much of the hue is left at the bottom, out of 255: a translucent
// filament keeps some, a clear one almost none.
#define SWATCH_FADE_TRANSLUCENT 110
#define SWATCH_FADE_CLEAR        40

// Paints a filament colour onto a swatch: flat when opaque, the fade above
// when it lets light through, SWATCH_FALLBACK_COLOR when nothing is known.
// Touches the background only, so a border the caller chose - the AMS tile's
// accent for the active bay - stays. Safe on an object that showed another
// spool before: a fade left over from it is removed.
void swatchPaint(lv_obj_t* obj, const SpoolColor& c);

// The same from a server's colour field, "#RRGGBB" or "RRGGBBAA". Both
// Spoolman and FilaMan hand out empty and truncated colour fields, which
// paint as SWATCH_FALLBACK_COLOR rather than as a random colour off the stack.
void swatchPaintHex(lv_obj_t* obj, const char* hex);

// The weight line of a create card (services/spool_start.h): the grams as
// they will be filed and, where the reading could not be taken as the
// spool's, why. `tare_inherited` turns a reading too heavy for the empty
// spool into the hint to check that inherited weight.
void spoolStartText(const SpoolStart& s, bool tare_inherited, char* out, size_t out_size);

// A label of one line, as wide as its text up to `max_w` and ending in dots
// beyond that. LVGL writes the dots on a label of fixed size only: one that
// sizes itself to its content under a max_width style is cut at the edge
// instead, and one with a fixed width but content height wraps to a second
// line. The caller sets the colour.
lv_obj_t* labelOneLine(lv_obj_t* parent, const char* text, const lv_font_t* font, int max_w);

// A key of the number pads (tare_entry.cpp, price_pad.cpp, spool_id_pad.cpp):
// a flat button with a soft outline, and its caption centred in it. One look
// for the three pads.
lv_obj_t* padButton(lv_obj_t* parent, int x, int y, int w, int h, uint32_t bg, uint32_t bg_pressed);

// A question's frame: the dimmed screen in *slot (an earlier one released
// first) and, centred on it, the box that is returned - w by h, the popup
// border and radius, no padding, so its children are placed in its content
// area. The weight popup and the questions behind it share it.
lv_obj_t* uiPopupBox(lv_obj_t** slot, int w, int h);
lv_obj_t* padLabel(lv_obj_t* btn, const char* text, uint32_t col, const lv_font_t* font);

// One of the line icons of icons.h, tinted ink, centred in a filled circle of
// the given diameter. The caller places the circle. Clicks pass through to the
// button it sits on.
lv_obj_t* uiIconDisc(lv_obj_t* parent, const lv_img_dsc_t* icon, int diameter,
                     uint32_t bg, uint32_t ink);

// The colour in the middle of a painted swatch as 0xRRGGBB, for choosing the
// colour of text drawn across it.
uint32_t swatchCenterRgb(const SpoolColor& c);

// utf8Cut(), isHexColorWord() and colorNameClean() moved to
// services/text_util.h, which the AMS parsers can reach too. Included
// above, so the screens that call them need no change.

// FilaMan's six spool statuses, as the caption to print and the colour to
// print it in. Shared rather than repeated: a status the server adds has to
// reach every card that shows one, and two copies of the same switch is how
// that stops being true. The id is a StringID, spelled int so this header
// does not have to pull in the whole string table.
int      filamanStatusStrId(int status_id);
uint32_t filamanStatusColor(int status_id);

// Two column info row: a muted label on the left, the value on the right.
// Used by the WiFi status screen and by the summary on the WiFi connecting
// screen, so both stay in step. Returns the value label so the caller can
// update it later.
//
// The value ellipsises instead of wrapping: a long SSID must not push the rows
// below it off their baselines.
#define INFO_ROW_LABEL_X  28
#define INFO_ROW_VALUE_X  172
#define INFO_ROW_VALUE_W  288   // 172 + 288 = 460, leaving a 20px margin

// out_label, when given, receives the label object so a caller can hide or
// restyle the whole row by name instead of hunting for it by child index.
lv_obj_t* addInfoRow(lv_obj_t* parent, int y, const char* label,
                     lv_obj_t** out_label = nullptr);

// Row in a settings list: icon, title, optional subtitle and an arrow on the
// right. Toggles replace that arrow with ON/OFF and pass toggle_active so the
// border and subtitle turn green. Shared by the scale menu and the FilaMan
// options, which is what moved it out of scale_menu.cpp.
// Pass out_help to get a small circled "?" on the right of the row; the
// button is handed back so the caller can attach showInfoPopup() to it. Left
// null the row is built exactly as before, which is why the scale menu needs
// no change.
lv_obj_t* makeListBtn(lv_obj_t* list, const char* ico_sym, const char* title,
                      const char* sub, bool toggle_active = false,
                      lv_obj_t** out_help = nullptr);

// A row of a one-of-several picker: the arrow makeListBtn() put last turns
// into a tick on the chosen entry and into nothing on the rest. The help
// button is built before the arrow, so a row with both still ends in the arrow.
void markListBtnChosen(lv_obj_t* btn, bool active);

// ---------------------------------------------------------------------------
//  Settings rows, built from services/settings_registry.h
// ---------------------------------------------------------------------------
struct SettingDesc;

// The list body every settings screen uses, once instead of seven times.
lv_obj_t* buildOptionList(lv_obj_t* parent);

// One row from its description: title, subtitle, help circle, ON/OFF and the
// click, all decided by the descriptor. Replaces ~27 lines of hand written
// LVGL per option, of which nine were the same arrow patch six files carried.
lv_obj_t* addSettingRow(lv_obj_t* list, const SettingDesc& s);

// Every row that belongs to the active backend and applies right now.
void addSettingRows(lv_obj_t* list);

// ---------------------------------------------------------------------------
//  Modal questions
// ---------------------------------------------------------------------------

// True while a popup is on screen waiting for the user to answer it.
//
// It exists because a blocking backend call and a question on screen cannot
// share the loop. lv_timer_handler() is what reads the touch panel, and it
// does not run while an HTTP request is in flight - a full inventory is six
// seconds on a library of 250 - so the question sits there taking no input
// and looks broken. Pumping LVGL from inside the request is not the way out:
// loading_overlay.cpp repaints with lv_refr_now() for exactly this reason and
// says why, dispatching events from there would re-enter the callback the
// request was started from.
//
// So the expensive lookup stands aside instead. The cheap server side tag
// search still runs, and spoolmanRecheckTick() keeps retrying it while an
// unknown tag lies on the pad, which is what makes standing aside free.
bool uiModalWaiting();

// How loudly a list row warns. A restart costs the user twenty seconds and
// takes nothing away; a factory reset erases every setting on the device.
// Painting both red would say they are the same kind of mistake to make.
enum ListTone { TONE_PLAIN, TONE_WARN, TONE_DANGER };
// Paints a makeListBtn() row amber or red: border, fill, icon and title.
void listBtnTone(lv_obj_t* btn, ListTone tone);

// Cancel, Close and Back: a reddish outline and icon in front of a neutral
// caption, so the way out is found without reading it. Quieter than the red
// fill of a real danger (unlink, factory reset), which has to warn more.
// Called on a finished button: takes its first label and its fill, so a
// countdown fill added afterwards keeps working.
void styleLeaveButton(lv_obj_t* btn, const char* icon = LV_SYMBOL_CLOSE);
