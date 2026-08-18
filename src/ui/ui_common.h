#pragma once

#include <lvgl.h>

void addBackButton(lv_obj_t *parent, lv_event_cb_t cb);
void addCloseButton(lv_obj_t *parent);
void buildSubHeader(lv_obj_t *parent, const char *title,
                    lv_event_cb_t back_cb, const char *back_hint = nullptr);
lv_obj_t* buildOverlayScreen();

// Preferred form: pass the pointer the screen is stored in and it registers
// itself, so it is hidden by hideAllOverlays() and dropped by
// themeInvalidateScreens() without the author having to remember either.
//
// Both were previously hand-maintained lists in two different files. Forgetting
// the first made the corner X look broken (the main screen appears underneath
// while the overlay stays on top); forgetting the second left the screen on the
// old palette forever. Neither failure points at the missing line.
lv_obj_t* buildOverlayScreen(lv_obj_t **slot);

// For screens that build their own container instead of calling the helper.
void overlayRegister(lv_obj_t **slot);

void overlayHideAll();   // hide every registered screen
void overlayDropAll();   // delete and null every registered screen

// Frees a screen object that is about to be replaced and clears the pointer.
// Call at the top of every build*Screen() function: without it the previous
// object is orphaned in the LVGL pool (LV_MEM_SIZE) and never reclaimed.
// Uses lv_obj_del_async(), so the object is destroyed at the end of the
// current lv_timer_handler() pass. That keeps it safe even when called from
// an event callback belonging to the screen itself.
// No-op when the pointer is already null, so callers that clean up on their
// own stay correct.
void releaseScreen(lv_obj_t **scr);

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
lv_obj_t* makeListBtn(lv_obj_t* list, const char* ico_sym, const char* title,
                      const char* sub, bool toggle_active = false);
