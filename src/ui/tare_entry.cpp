#include "tare_entry.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstdlib>
#include <cstring>

#include "app/app_state.h"
#include "app_config.h"
#include "confirm_popup.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "theme.h"
#include "ui_common.h"

// Issue #40: a spool that is still in use has no empty reel to weigh, but its
// empty weight is often known - printed on the box, measured on a sister
// spool, or listed by the maker. The weight popup's empty spool button
// offers typing it in next to weighing it, and a typed number then takes the
// same way to the server as a weighed one.

static lv_obj_t *s_pad = nullptr;   // the keypad

static char      s_input[8]  = "";
static lv_obj_t *s_lbl_input = nullptr;
static lv_obj_t *s_lbl_info  = nullptr;
static lv_obj_t *s_btn_next  = nullptr;

// Longest input: "600.0", plus room for the one decimal digit being typed.
#define TARE_INPUT_MAX_CHARS  5

// Lifted, by the same measure the removal check in app_loop.cpp uses: more
// than half of what was on the pad when the entry opened has left it.
#define TARE_ENTRY_GONE_FRACTION 0.5f

// The spool the entry was opened for, and what the pad carried then. Typing
// takes long enough for the spool to be swapped meanwhile, and a number typed
// for one spool must not land on the next (issue #40 follow-up).
static int   s_spool_id = 0;
static float s_open_g   = 0.0f;

bool isTareEntryOpen() {
  return s_pad != nullptr;
}

void closeTareEntry() {
  releaseScreen(&s_pad);
  s_lbl_input = nullptr;
  s_lbl_info  = nullptr;
  s_btn_next  = nullptr;
}

// ---------------------------------------------------------------------------
//  The keypad
// ---------------------------------------------------------------------------

// Something is on the pad that can only be a spool. Below that the reading is
// noise or nothing, and the typed value is not compared against it.
static bool padHoldsSpool() {
  return scale_weight_g > NEW_SPOOL_TARE_MIN_G;
}

// The typed value, when it may be stored. The range is the one a derived tare
// has to pass (confirm_popup.cpp, newSpoolDerivesTare), and a spool on the pad
// has to outweigh its own empty reel.
static bool inputValue(float *out) {
  if (!s_input[0]) return false;
  const float v = atof(s_input);
  if (v < NEW_SPOOL_TARE_MIN_G || v > NEW_SPOOL_TARE_MAX_G) return false;
  if (padHoldsSpool() && v >= scale_weight_g) return false;
  if (out) *out = v;
  return true;
}

// Input line, the line under it and the look of the Next button, all from
// the current input. Called after every key.
static void refreshPad() {
  if (!s_lbl_input || !s_lbl_info || !s_btn_next) return;

  char buf[24];
  snprintf(buf, sizeof(buf), "%s g", s_input[0] ? s_input : "_");
  lv_label_set_text(s_lbl_input, buf);

  float v = 0.0f;
  const bool ok = inputValue(&v);
  char info[96];
  uint32_t info_col = UI_COL_CAPTION;
  if (ok && padHoldsSpool()) {
    // What a weighing would store once this tare is in - the number the
    // issue asked to see before anything is saved.
    snprintf(info, sizeof(info), T(STR_TARE_ENTER_REST), scale_weight_g, v, scale_weight_g - v);
    info_col = UI_COL_GOOD;
  } else if (s_input[0] && padHoldsSpool() && atof(s_input) >= scale_weight_g) {
    copyT(info, sizeof(info), STR_TARE_ENTER_OVER);
    info_col = UI_COL_WARN;
  } else {
    snprintf(info, sizeof(info), T(STR_TARE_ENTER_RANGE), NEW_SPOOL_TARE_MIN_G, NEW_SPOOL_TARE_MAX_G);
    if (s_input[0] && !ok) info_col = UI_COL_WARN;
  }
  lv_label_set_text(s_lbl_info, info);
  lv_obj_set_style_text_color(s_lbl_info, lv_color_hex(info_col), 0);

  // Ready is the confirm role as built; not ready is the one local look on top.
  lv_obj_t *next_lbl = lv_obj_get_child(s_btn_next, 0);
  if (ok) {
    lv_obj_remove_local_style_prop(s_btn_next, LV_STYLE_BG_COLOR, 0);
    lv_obj_remove_local_style_prop(s_btn_next, LV_STYLE_BORDER_WIDTH, 0);
    lv_obj_remove_local_style_prop(s_btn_next, LV_STYLE_BORDER_COLOR, 0);
    lv_obj_remove_local_style_prop(next_lbl, LV_STYLE_TEXT_COLOR, 0);
  } else {
    // The pad keys' outline, so the inert button still reads as a key.
    lv_obj_set_style_bg_color(s_btn_next, lv_color_hex(UI_COL_SURFACE), 0);
    lv_obj_set_style_border_width(s_btn_next, 1, 0);
    lv_obj_set_style_border_color(s_btn_next, lv_color_hex(UI_COL_LINE_SOFT), 0);
    lv_obj_set_style_text_color(next_lbl, lv_color_hex(UI_COL_CAPTION), 0);
  }
}

static void onKey(lv_event_t *e) {
  const char *ch = lv_label_get_text(lv_obj_get_child(lv_event_get_target(e), 0));
  const size_t len = strlen(s_input);
  const char *dot = strchr(s_input, '.');
  if (ch[0] == '.') {
    if (dot || len == 0) return;           // one point, and not in front
  } else if (dot && strlen(dot) > 1) {
    return;                                // one decimal is plenty for grams
  }
  if (len >= TARE_INPUT_MAX_CHARS) return;
  s_input[len] = ch[0];
  s_input[len + 1] = '\0';
  refreshPad();
}

static void showTarePad() {
  logSD("SHOW: TareEntryPad");
  releaseScreen(&s_pad);
  s_input[0] = '\0';

  lv_obj_t *scr = buildOverlayScreen();
  s_pad = scr;
  lv_obj_clear_flag(scr, LV_OBJ_FLAG_HIDDEN);

  lv_obj_t *title = lv_label_create(scr);
  lv_label_set_text(title, T(STR_TARE_ENTER_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(title, UI_FONT_SMALL, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

  // Keys on the left, the value above them; what the value means and the
  // two ways out on the right.
  const int KEY_W = 90, KEY_H = 48, GAP = 6, EDGE = 10;
  const int PAD_W = 3 * KEY_W + 2 * GAP;
  const int KEYS_Y = 100;
  const int COL_X = EDGE + PAD_W + EDGE;
  const int COL_W = 480 - COL_X - EDGE;

  lv_obj_t *box = lv_obj_create(scr);
  lv_obj_set_size(box, PAD_W, 52);
  lv_obj_set_pos(box, EDGE, 38);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_INPUT, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);
  s_lbl_input = lv_label_create(box);
  lv_obj_set_style_text_color(s_lbl_input, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(s_lbl_input, UI_FONT_ICON, 0);
  lv_obj_center(s_lbl_input);

  s_lbl_info = lv_label_create(scr);
  lv_label_set_long_mode(s_lbl_info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(s_lbl_info, COL_W);
  lv_obj_set_pos(s_lbl_info, COL_X, 38);
  lv_obj_set_style_text_font(s_lbl_info, UI_FONT_CAPTION, 0);

  static const char *const KEYS[12] = { "1","2","3","4","5","6","7","8","9",".","0","" };
  for (int i = 0; i < 12; i++) {
    const int x = EDGE + (i % 3) * (KEY_W + GAP);
    const int y = KEYS_Y + (i / 3) * (KEY_H + GAP);
    lv_obj_t *b = padButton(scr, x, y, KEY_W, KEY_H, UI_COL_SURFACE, UI_COL_LINE);
    if (KEYS[i][0]) {
      padLabel(b, KEYS[i], UI_COL_INK, UI_FONT_HEADLINE);
      lv_obj_add_event_cb(b, onKey, LV_EVENT_CLICKED, NULL);
    } else {
      padLabel(b, LV_SYMBOL_BACKSPACE, UI_COL_INK_2, UI_FONT_BODY);
      lv_obj_add_event_cb(b, [](lv_event_t *e) {
        const size_t len = strlen(s_input);
        if (len) s_input[len - 1] = '\0';
        refreshPad();
      }, LV_EVENT_CLICKED, NULL);
    }
  }

  // Next starts level with the second row of keys, so the hint above it has
  // room to breathe; Cancel keeps the bottom.
  const int KEYS_H = 4 * KEY_H + 3 * GAP;
  const int CANCEL_H = UI_TOUCH_MIN + 10;
  const int NEXT_Y = KEYS_Y + KEY_H + GAP;
  const int CANCEL_Y = KEYS_Y + KEYS_H - CANCEL_H;
  const int NEXT_H = CANCEL_Y - GAP - NEXT_Y;

  char next_buf[32];
  snprintf(next_buf, sizeof(next_buf), "%s  " LV_SYMBOL_RIGHT, T(STR_BTN_NEXT));
  s_btn_next = padButton(scr, COL_X, NEXT_Y, COL_W, NEXT_H, UI_COL_ROW, UI_COL_ROW_PRESS_FILL);
  padLabel(s_btn_next, next_buf, UI_COL_INK, UI_FONT_BODY);
  uiBtnRole(s_btn_next, BTN_CONFIRM);
  lv_obj_add_event_cb(s_btn_next, [](lv_event_t *e) {
    float v = 0.0f;
    if (!inputValue(&v)) return;          // the button is greyed, the press is ignored
    // tareEntryTick() closes the pad on a swap; this covers a swap that
    // landed in the same pass as the press.
    if (sm_id != s_spool_id) {
      logSDf("UI: tare %.1f g typed for spool %d, spool %d loaded now - dropped",
             v, s_spool_id, sm_id);
      closeTareEntry();
      return;
    }
    logSDf("UI: tare typed in, %.1f g", v);
    closeTareEntry();
    showSpoolWeightScope(v, false);
  }, LV_EVENT_CLICKED, NULL);

  // styleLeaveButton sets the fill and the label colour; padButton only needs
  // a neutral start.
  lv_obj_t *cancel = padButton(scr, COL_X, CANCEL_Y, COL_W, CANCEL_H,
                               UI_COL_ROW, UI_COL_ROW_PRESS_FILL);
  padLabel(cancel, T(STR_CANCEL), UI_COL_INK_2, UI_FONT_SMALL);
  styleLeaveButton(cancel);
  lv_obj_add_event_cb(cancel, [](lv_event_t *e) { closeTareEntry(); }, LV_EVENT_CLICKED, NULL);

  refreshPad();
}

// Opened from the weight popup's Options, which offer weighing the empty
// spool beside it; the choice that used to stand between the two is gone.
void showTareEntryPad() {
  closeTareEntry();
  s_spool_id = sm_id;
  s_open_g   = scale_weight_g;
  showTarePad();
}

void tareEntryTick() {
  if (!isTareEntryOpen()) return;
  const bool swapped = sm_id != s_spool_id;
  // Only where a spool was on the pad to begin with: the entry also serves a
  // spool that sits in the printer, and an empty pad has nothing to lose.
  const bool lifted = s_open_g > NEW_SPOOL_TARE_MIN_G &&
                      (s_open_g - scale_weight_g) > s_open_g * TARE_ENTRY_GONE_FRACTION;
  if (!swapped && !lifted) return;
  logSDf("UI: tare entry for spool %d closed unsaved, %s (%.0f g -> %.0f g)",
         s_spool_id, swapped ? "another spool loaded" : "spool lifted",
         s_open_g, scale_weight_g);
  // From the loop, not from a callback; releaseScreen() deletes on the next
  // timer pass either way.
  closeTareEntry();
}
