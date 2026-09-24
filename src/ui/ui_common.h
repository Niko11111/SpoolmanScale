#pragma once

#include <lvgl.h>

#include "services/spool_color.h"
#include "services/text_util.h"

void addBackButton(lv_obj_t *parent, lv_event_cb_t cb);
// The "?" circle in the header row, between the centred title and the close
// button - the one gap on a sub screen nothing else wants. Opens the info
// popup with the two strings.
lv_obj_t* addHeaderHelp(lv_obj_t *scr, int title_id, int text_id);
void addCloseButton(lv_obj_t *parent);
void buildSubHeader(lv_obj_t *parent, const char *title,
                    lv_event_cb_t back_cb, const char *back_hint = nullptr);
lv_obj_t* buildOverlayScreen();

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

// Neutral grey for a colour swatch with no usable colour behind it.
#define SWATCH_FALLBACK_COLOR 0x333333

// What a clear filament is drawn in when nothing names a tint for it: the
// glass white the filament databases use for "clear".
#define SWATCH_GLASS_COLOR    0xDCE6F0

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
