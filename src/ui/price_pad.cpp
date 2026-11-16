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

// The keypad's geometry, the number pad's as the large popup (num_pad.cpp):
// keys on the left, the value above them, the two ways out on the right. The
// pad is a step under a card's Options, placed inside the box's 2 px border.
#define PP_INNER_W (UI_POPUP_LARGE_W - 4)
#define PP_INNER_H (UI_POPUP_LARGE_H - 4)
#define PP_KEY_W   90
#define PP_KEY_H   46
#define PP_GAP      6
#define PP_EDGE    10
#define PP_TITLE_Y  8
#define PP_FIELD_Y 32
#define PP_FIELD_H 44
#define PP_KEYS_H  (4 * PP_KEY_H + 3 * PP_GAP)
#define PP_KEYS_Y  (PP_INNER_H - PP_EDGE - PP_KEYS_H)
#define PP_PAD_W   (3 * PP_KEY_W + 2 * PP_GAP)
#define PP_COL_X   (PP_EDGE + PP_PAD_W + PP_EDGE)
#define PP_COL_W   (PP_INNER_W - PP_COL_X - PP_EDGE)

enum PriceAnswer : uint8_t { PA_NONE = 0, PA_OK, PA_CANCEL };

static lv_obj_t*   s_pad       = nullptr;   // the popup's scrim
static lv_obj_t*   s_box       = nullptr;   // where its parts go
static lv_obj_t*   s_lbl_input = nullptr;
static char        s_input[PRICE_INPUT_MAX_CHARS + 1] = "";
static void      (*s_done)(bool, float) = nullptr;
static PriceAnswer s_answer    = PA_NONE;

bool pricePadOpen() { return s_pad != nullptr; }

void closePricePad() {
  releaseScreen(&s_pad);
  s_box = nullptr;
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

static void buildHead() {
  lv_obj_t* title = lv_label_create(s_box);
  lv_label_set_text(title, T(STR_PRICE_PAD_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(title, UI_FONT_SMALL, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, PP_TITLE_Y);

  lv_obj_t* box = lv_obj_create(s_box);
  lv_obj_set_size(box, PP_PAD_W, PP_FIELD_H);
  lv_obj_set_pos(box, PP_EDGE, PP_FIELD_Y);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_GROUND), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_INPUT, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);
  s_lbl_input = lv_label_create(box);
  lv_obj_set_style_text_color(s_lbl_input, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(s_lbl_input, UI_FONT_ICON, 0);
  lv_obj_center(s_lbl_input);

  lv_obj_t* info = lv_label_create(s_box);
  lv_label_set_text(info, T(STR_PRICE_PAD_INFO));
  lv_label_set_long_mode(info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(info, PP_COL_W);
  lv_obj_set_pos(info, PP_COL_X, PP_FIELD_Y);
  lv_obj_set_style_text_color(info, lv_color_hex(UI_COL_CAPTION), 0);
  lv_obj_set_style_text_font(info, UI_FONT_CAPTION, 0);
}

static void buildKeys() {
  static const char* const KEYS[12] = { "1","2","3","4","5","6","7","8","9",".","0","" };
  for (int i = 0; i < 12; i++) {
    const int x = PP_EDGE + (i % 3) * (PP_KEY_W + PP_GAP);
    const int y = PP_KEYS_Y + (i / 3) * (PP_KEY_H + PP_GAP);
    lv_obj_t* b = padButton(s_box, x, y, PP_KEY_W, PP_KEY_H, UI_COL_ROW, UI_COL_LINE);
    if (KEYS[i][0]) {
      padLabel(b, KEYS[i], UI_COL_INK, UI_FONT_HEADLINE);
      lv_obj_add_event_cb(b, onKey, LV_EVENT_CLICKED, NULL);
    } else {
      padLabel(b, LV_SYMBOL_BACKSPACE, UI_COL_INK_2, UI_FONT_BODY);
      lv_obj_add_event_cb(b, onBackspace, LV_EVENT_CLICKED, NULL);
    }
  }
}

// OK and Back only park the answer: the pad is deleted from the loop, not
// from inside its own button's callback.
static void buildAnswers() {
  // OK starts level with the second row of keys, so the hint above it has
  // room to breathe; Back keeps the bottom.
  const int cancel_h = UI_TOUCH_MIN + 10;
  const int ok_y     = PP_KEYS_Y + PP_KEY_H + PP_GAP;
  const int cancel_y = PP_KEYS_Y + PP_KEYS_H - cancel_h;
  const int ok_h     = cancel_y - PP_GAP - ok_y;

  lv_obj_t* ok = padButton(s_box, PP_COL_X, ok_y, PP_COL_W, ok_h, UI_COL_OK_BG, UI_COL_OK_BG_PRESSED);
  padLabel(ok, T(STR_BTN_OK), UI_COL_OK_TEXT, UI_FONT_BODY);
  lv_obj_add_event_cb(ok, [](lv_event_t*) {
    if (s_pad) lv_obj_add_flag(s_pad, LV_OBJ_FLAG_HIDDEN);
    s_answer = PA_OK;
  }, LV_EVENT_CLICKED, NULL);

  // Back to the Options the pad was opened from, the price as it was.
  lv_obj_t* no = padButton(s_box, PP_COL_X, cancel_y, PP_COL_W, cancel_h,
                           UI_COL_ROW, UI_COL_ROW_PRESS_FILL);
  padLabel(no, T(STR_BACK), UI_COL_INK_2, UI_FONT_SMALL);
  styleLeaveButton(no, LV_SYMBOL_LEFT);
  lv_obj_add_event_cb(no, [](lv_event_t*) {
    if (s_pad) lv_obj_add_flag(s_pad, LV_OBJ_FLAG_HIDDEN);
    s_answer = PA_CANCEL;
  }, LV_EVENT_CLICKED, NULL);
}

void showPricePad(float current, void (*done)(bool ok, float price)) {
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

  s_box = uiPopupBox(&s_pad, UI_POPUP_LARGE_W, UI_POPUP_LARGE_H);

  buildHead();
  buildKeys();
  buildAnswers();
  refreshInput();
}

void pricePadTick() {
  if (!s_pad || s_answer == PA_NONE) return;
  const bool ok = s_answer == PA_OK;
  const float price = ok && s_input[0] ? (float)atof(s_input) : 0.0f;
  void (*done)(bool, float) = s_done;
  closePricePad();
  logSDf("UI: price pad %s, %.2f", ok ? "OK" : "back", price);
  if (done) done(ok, price);
}
