#pragma once

#include <lvgl.h>

void addBackButton(lv_obj_t *parent, lv_event_cb_t cb);
void addCloseButton(lv_obj_t *parent);
void buildSubHeader(lv_obj_t *parent, const char *title,
                    lv_event_cb_t back_cb, const char *back_hint = nullptr);
lv_obj_t* buildOverlayScreen();

// Frees a screen object that is about to be replaced and clears the pointer.
// Call at the top of every build*Screen() function: without it the previous
// object is orphaned in the LVGL pool (LV_MEM_SIZE) and never reclaimed.
// Uses lv_obj_del_async(), so the object is destroyed at the end of the
// current lv_timer_handler() pass. That keeps it safe even when called from
// an event callback belonging to the screen itself.
// No-op when the pointer is already null, so callers that clean up on their
// own stay correct.
void releaseScreen(lv_obj_t **scr);

// One snapshot of the LVGL pool, tagged so a log can be read back per list.
// LV_MEM_SIZE is a static pool in internal SRAM, PSRAM does not feed it, and
// LV_USE_ASSERT_MALLOC turns an exhausted pool into while(1): no reboot, no
// panic output, just a frozen screen and a warm board. The numbers that
// matter are therefore the ones taken before the rows exist.
//
// Call it in pairs around a list build, "<name>/pre" and "<name>/post", with
// rows = 0 on the pre call. The cost of one row is then
//   (free of pre - free of post) / rows
// Silent unless sd_verbose is on, so it costs nothing in normal operation.
void logLvMem(const char* tag, int rows);

// Neutral grey for a colour swatch with no usable colour behind it.
#define SWATCH_FALLBACK_COLOR 0x333333

// Parse "#RRGGBB" or "RRGGBB" into a swatch colour, falling back to
// SWATCH_FALLBACK_COLOR when the string is absent, too short or malformed.
// Both Spoolman and FilaMan hand out empty and truncated colour fields, and the
// call sites used to run sscanf without checking its result, which left r/g/b
// uninitialised and gave the swatch a random colour off the stack.
lv_color_t swatchColorFromHex(const char* hex);

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
