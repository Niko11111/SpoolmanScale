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
