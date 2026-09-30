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
// therefore asks first how the number is to be had, and a typed number then
// takes the same way to the server as a weighed one.

static lv_obj_t *s_choice = nullptr;   // weigh or type
static lv_obj_t *s_pad    = nullptr;   // the keypad

static char      s_input[8]  = "";
static lv_obj_t *s_lbl_input = nullptr;
static lv_obj_t *s_lbl_info  = nullptr;
static lv_obj_t *s_btn_next  = nullptr;

// Longest input: "600.0", plus room for the one decimal digit being typed.
#define TARE_INPUT_MAX_CHARS  5

void closeTareEntry() {
  releaseScreen(&s_choice);
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

  lv_obj_set_style_bg_color(s_btn_next, lv_color_hex(ok ? UI_COL_OK_BG : UI_COL_SURFACE), 0);
  lv_obj_set_style_text_color(lv_obj_get_child(s_btn_next, 0),
                              lv_color_hex(ok ? UI_COL_OK_TEXT : UI_COL_CAPTION), 0);
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

static lv_obj_t *padButton(lv_obj_t *parent, int x, int y, int w, int h,
                           uint32_t bg, uint32_t bg_pressed) {
  lv_obj_t *b = lv_btn_create(parent);
  lv_obj_set_size(b, w, h);
  lv_obj_set_pos(b, x, y);
  lv_obj_set_style_bg_color(b, lv_color_hex(bg), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(bg_pressed), LV_STATE_PRESSED);
  lv_obj_set_style_radius(b, UI_RADIUS_INPUT, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_border_width(b, 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_LINE_SOFT), 0);
  return b;
}

static lv_obj_t *padLabel(lv_obj_t *btn, const char *text, uint32_t col, const lv_font_t *font) {
  lv_obj_t *l = lv_label_create(btn);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_color(l, lv_color_hex(col), 0);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_center(l);
  return l;
}

static void showTarePad() {
  logSD("SHOW: TareEntryPad");
  releaseScreen(&s_pad);
  s_input[0] = '\0';

  lv_obj_t *scr = lv_obj_create(lv_scr_act());
  s_pad = scr;
  lv_obj_set_size(scr, 480, 320);
  lv_obj_set_pos(scr, 0, 0);
  lv_obj_set_style_bg_color(scr, lv_color_hex(UI_COL_GROUND), 0);
  lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(scr, 0, 0);
  lv_obj_set_style_radius(scr, 0, 0);
  lv_obj_set_style_pad_all(scr, 0, 0);
  lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);

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

  const int KEYS_H = 4 * KEY_H + 3 * GAP;
  const int CANCEL_H = UI_TOUCH_MIN + 10;
  const int NEXT_H = KEYS_H - CANCEL_H - GAP;

  char next_buf[32];
  snprintf(next_buf, sizeof(next_buf), "%s  " LV_SYMBOL_RIGHT, T(STR_BTN_NEXT));
  s_btn_next = padButton(scr, COL_X, KEYS_Y, COL_W, NEXT_H, UI_COL_OK_BG, UI_COL_OK_BG_PRESSED);
  padLabel(s_btn_next, next_buf, UI_COL_OK_TEXT, UI_FONT_BODY);
  lv_obj_add_event_cb(s_btn_next, [](lv_event_t *e) {
    float v = 0.0f;
    if (!inputValue(&v)) return;          // the button is greyed, the press is ignored
    logSDf("UI: tare typed in, %.1f g", v);
    closeTareEntry();
    showSpoolWeightScope(v, false);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *cancel = padButton(scr, COL_X, KEYS_Y + NEXT_H + GAP, COL_W, CANCEL_H,
                               UI_COL_BAD_BG, UI_COL_BAD_BG_PRESSED);
  padLabel(cancel, T(STR_CANCEL), UI_COL_BAD_TEXT, UI_FONT_SMALL);
  lv_obj_add_event_cb(cancel, [](lv_event_t *e) { closeTareEntry(); }, LV_EVENT_CLICKED, NULL);

  refreshPad();
}

// ---------------------------------------------------------------------------
//  Weigh or type
// ---------------------------------------------------------------------------

static lv_obj_t *choiceButton(lv_obj_t *box, int y, int w, int h, const char *text) {
  lv_obj_t *b = lv_btn_create(box);
  lv_obj_set_size(b, w, h);
  lv_obj_set_pos(b, 12, y);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_CHIP), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_LINE), LV_STATE_PRESSED);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  padLabel(b, text, UI_COL_INK_2, UI_FONT_SMALL);
  return b;
}

void showTareChoice() {
  logSD("SHOW: TareChoice");
  closeTareEntry();

  lv_obj_t *scrim = lv_obj_create(lv_scr_act());
  s_choice = scrim;
  lv_obj_set_size(scrim, 480, 320);
  lv_obj_set_pos(scrim, 0, 0);
  lv_obj_set_style_bg_color(scrim, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(scrim, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(scrim, 0, 0);
  lv_obj_set_style_radius(scrim, 0, 0);
  lv_obj_set_style_pad_all(scrim, 0, 0);
  lv_obj_clear_flag(scrim, LV_OBJ_FLAG_SCROLLABLE);

  const int BOX_W = 440, BOX_H = 262, BTN_H = 70, GAP = 10;
  lv_obj_t *box = lv_obj_create(scrim);
  lv_obj_set_size(box, BOX_W, BOX_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);
  const int BTN_W = BOX_W - 2 * 12;

  lv_obj_t *title = lv_label_create(box);
  lv_label_set_text(title, T(STR_TARE_CHOICE_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(title, UI_FONT_TITLE, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 12);

  int y = 44;
  char weigh_buf[96];
  snprintf(weigh_buf, sizeof(weigh_buf), T(STR_TARE_CHOICE_WEIGH), scale_weight_g);
  lv_obj_t *weigh = choiceButton(box, y, BTN_W, BTN_H, weigh_buf);
  lv_obj_add_event_cb(weigh, [](lv_event_t *e) {
    // The reading at the moment of the press, as the old button took it.
    const float g = scale_weight_g;
    closeTareEntry();
    showSpoolWeightScope(g, true);
  }, LV_EVENT_CLICKED, NULL);
  y += BTN_H + GAP;

  char type_buf[96];
  snprintf(type_buf, sizeof(type_buf), LV_SYMBOL_KEYBOARD "  %s", T(STR_TARE_CHOICE_TYPE));
  lv_obj_t *type = choiceButton(box, y, BTN_W, BTN_H, type_buf);
  lv_obj_add_event_cb(type, [](lv_event_t *e) {
    releaseScreen(&s_choice);
    showTarePad();
  }, LV_EVENT_CLICKED, NULL);
  y += BTN_H + GAP;

  lv_obj_t *cancel = padButton(box, 12, y, BTN_W, UI_TOUCH_MIN,
                               UI_COL_BAD_BG, UI_COL_BAD_BG_PRESSED);
  lv_obj_set_style_radius(cancel, UI_RADIUS_BTN, 0);
  lv_obj_set_style_border_width(cancel, 0, 0);
  padLabel(cancel, T(STR_CANCEL), UI_COL_BAD_TEXT, UI_FONT_SMALL);
  lv_obj_add_event_cb(cancel, [](lv_event_t *e) { closeTareEntry(); }, LV_EVENT_CLICKED, NULL);
}
