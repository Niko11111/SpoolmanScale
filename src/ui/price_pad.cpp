#include "ui/price_pad.h"

#include <Arduino.h>
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui/theme.h"
#include "ui/ui_common.h"

// "9999.99": more than any spool costs, and what the input box shows whole.
#define PRICE_INPUT_MAX_CHARS  7
#define PRICE_DECIMALS         2

// The keypad's geometry, the tare pad's (tare_entry.cpp): keys on the left,
// the value above them, the two ways out on the right.
#define PP_KEY_W   90
#define PP_KEY_H   48
#define PP_GAP      6
#define PP_EDGE    10
#define PP_KEYS_Y 100
#define PP_PAD_W  (3 * PP_KEY_W + 2 * PP_GAP)
#define PP_COL_X  (PP_EDGE + PP_PAD_W + PP_EDGE)
#define PP_COL_W  (480 - PP_COL_X - PP_EDGE)

enum PriceAnswer : uint8_t { PA_NONE = 0, PA_OK, PA_CANCEL };

static lv_obj_t*   s_pad       = nullptr;
static lv_obj_t*   s_lbl_input = nullptr;
static char        s_input[PRICE_INPUT_MAX_CHARS + 1] = "";
static void      (*s_done)(float) = nullptr;
static PriceAnswer s_answer    = PA_NONE;

bool pricePadOpen() { return s_pad != nullptr; }

void closePricePad() {
  releaseScreen(&s_pad);
  s_lbl_input = nullptr;
  s_answer = PA_NONE;
}

static void refreshInput() {
  if (s_lbl_input) lv_label_set_text(s_lbl_input, s_input[0] ? s_input : "_");
}

static void onKey(lv_event_t* e) {
  const char* ch = lv_label_get_text(lv_obj_get_child(lv_event_get_target(e), 0));
  const size_t len = strlen(s_input);
  const char* dot = strchr(s_input, '.');
  if (ch[0] == '.' && (dot || len == 0)) return;                  // one point, not in front
  if (ch[0] != '.' && dot && strlen(dot) > PRICE_DECIMALS) return; // cents at most
  if (len >= PRICE_INPUT_MAX_CHARS) return;
  s_input[len] = ch[0];
  s_input[len + 1] = '\0';
  refreshInput();
}

static void onBackspace(lv_event_t*) {
  const size_t len = strlen(s_input);
  if (len) s_input[len - 1] = '\0';
  refreshInput();
}

static lv_obj_t* padButton(int x, int y, int w, int h, uint32_t bg, uint32_t bg_pressed) {
  lv_obj_t* b = lv_btn_create(s_pad);
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

static void padLabel(lv_obj_t* btn, const char* text, uint32_t col, const lv_font_t* font) {
  lv_obj_t* l = lv_label_create(btn);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_color(l, lv_color_hex(col), 0);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_center(l);
}

static void buildHead() {
  lv_obj_t* title = lv_label_create(s_pad);
  lv_label_set_text(title, T(STR_PRICE_PAD_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(title, UI_FONT_SMALL, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

  lv_obj_t* box = lv_obj_create(s_pad);
  lv_obj_set_size(box, PP_PAD_W, 52);
  lv_obj_set_pos(box, PP_EDGE, 38);
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

  lv_obj_t* info = lv_label_create(s_pad);
  lv_label_set_text(info, T(STR_PRICE_PAD_INFO));
  lv_label_set_long_mode(info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(info, PP_COL_W);
  lv_obj_set_pos(info, PP_COL_X, 38);
  lv_obj_set_style_text_color(info, lv_color_hex(UI_COL_CAPTION), 0);
  lv_obj_set_style_text_font(info, UI_FONT_CAPTION, 0);
}

static void buildKeys() {
  static const char* const KEYS[12] = { "1","2","3","4","5","6","7","8","9",".","0","" };
  for (int i = 0; i < 12; i++) {
    const int x = PP_EDGE + (i % 3) * (PP_KEY_W + PP_GAP);
    const int y = PP_KEYS_Y + (i / 3) * (PP_KEY_H + PP_GAP);
    lv_obj_t* b = padButton(x, y, PP_KEY_W, PP_KEY_H, UI_COL_SURFACE, UI_COL_LINE);
    if (KEYS[i][0]) {
      padLabel(b, KEYS[i], UI_COL_INK, UI_FONT_HEADLINE);
      lv_obj_add_event_cb(b, onKey, LV_EVENT_CLICKED, NULL);
    } else {
      padLabel(b, LV_SYMBOL_BACKSPACE, UI_COL_INK_2, UI_FONT_BODY);
      lv_obj_add_event_cb(b, onBackspace, LV_EVENT_CLICKED, NULL);
    }
  }
}

// OK and Cancel only park the answer: the pad is deleted from the loop, not
// from inside its own button's callback.
static void buildAnswers() {
  const int keys_h   = 4 * PP_KEY_H + 3 * PP_GAP;
  const int cancel_h = UI_TOUCH_MIN + 10;
  const int ok_h     = keys_h - cancel_h - PP_GAP;

  lv_obj_t* ok = padButton(PP_COL_X, PP_KEYS_Y, PP_COL_W, ok_h, UI_COL_OK_BG, UI_COL_OK_BG_PRESSED);
  padLabel(ok, T(STR_BTN_OK), UI_COL_OK_TEXT, UI_FONT_BODY);
  lv_obj_add_event_cb(ok, [](lv_event_t*) {
    if (s_pad) lv_obj_add_flag(s_pad, LV_OBJ_FLAG_HIDDEN);
    s_answer = PA_OK;
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t* no = padButton(PP_COL_X, PP_KEYS_Y + ok_h + PP_GAP, PP_COL_W, cancel_h,
                           UI_COL_BAD_BG, UI_COL_BAD_BG_PRESSED);
  padLabel(no, T(STR_CANCEL), UI_COL_BAD_TEXT, UI_FONT_SMALL);
  lv_obj_add_event_cb(no, [](lv_event_t*) {
    if (s_pad) lv_obj_add_flag(s_pad, LV_OBJ_FLAG_HIDDEN);
    s_answer = PA_CANCEL;
  }, LV_EVENT_CLICKED, NULL);
}

void showPricePad(float current, void (*done)(float price)) {
  logSD("SHOW: PricePad");
  closePricePad();
  s_done = done;
  // A value the box cannot show whole starts it empty rather than cut: a
  // cut one would go back to the server as a different price on OK.
  char shown[16];
  snprintf(shown, sizeof(shown), "%.2f", current);
  const bool fits = current > 0.0f && strlen(shown) <= PRICE_INPUT_MAX_CHARS;
  if (fits) snprintf(s_input, sizeof(s_input), "%s", shown);
  else      s_input[0] = '\0';

  s_pad = lv_obj_create(lv_scr_act());
  lv_obj_set_size(s_pad, 480, 320);
  lv_obj_set_pos(s_pad, 0, 0);
  lv_obj_set_style_bg_color(s_pad, lv_color_hex(UI_COL_GROUND), 0);
  lv_obj_set_style_bg_opa(s_pad, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(s_pad, 0, 0);
  lv_obj_set_style_radius(s_pad, 0, 0);
  lv_obj_set_style_pad_all(s_pad, 0, 0);
  lv_obj_clear_flag(s_pad, LV_OBJ_FLAG_SCROLLABLE);

  buildHead();
  buildKeys();
  buildAnswers();
  refreshInput();
}

void pricePadTick() {
  if (!s_pad || s_answer == PA_NONE) return;
  const bool ok = s_answer == PA_OK;
  const float price = ok && s_input[0] ? (float)atof(s_input) : 0.0f;
  void (*done)(float) = s_done;
  closePricePad();
  logSDf("UI: price pad %s, %.2f", ok ? "OK" : "cancelled", price);
  if (ok && done) done(price);
}
