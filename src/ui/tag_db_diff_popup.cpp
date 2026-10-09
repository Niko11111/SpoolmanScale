#include "ui/tag_db_diff_popup.h"

#include <Arduino.h>
#include <lvgl.h>
#include <stdio.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui/theme.h"
#include "ui/ui_common.h"

// The table: a header line, then one line per difference.
#define TDP_TITLE_Y     16
#define TDP_HEAD_Y      52
#define TDP_ROW_Y0      78
#define TDP_ROW_H       26
#define TDP_LABEL_X     20
#define TDP_LABEL_W    120
#define TDP_TAG_X      150
#define TDP_DB_X       270
#define TDP_VALUE_W    116
#define TDP_SWATCH      16
#define TDP_GAP          8
#define TDP_BTN_W      ((UI_POPUP_W - 2 * UI_CARD_ROW_X - TDP_GAP) / 2)

enum TdpAnswer : uint8_t { TDP_NONE = 0, TDP_KEEP, TDP_TAKE };

static lv_obj_t*  s_box_scr = nullptr;
static void     (*s_done)(bool) = nullptr;
static TdpAnswer  s_answer = TDP_NONE;

bool tagDbDiffPopupOpen() { return s_box_scr != nullptr; }

void closeTagDbDiffPopup() {
  releaseScreen(&s_box_scr);
  s_answer = TDP_NONE;
}

// One line of text in the body font, ending in dots where it is too long.
static lv_obj_t* label(lv_obj_t* box, const char* text, int x, int y, int w) {
  lv_obj_t* l = lv_label_create(box);
  lv_label_set_text(l, text);
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
  lv_obj_set_width(l, w);
  lv_obj_set_pos(l, x, y);
  lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK), 0);
  return l;
}

static void restyle(lv_obj_t* l, const lv_font_t* font, uint32_t color) {
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(color), 0);
}

// A colour as a small swatch with its value beside it.
static void colorCell(lv_obj_t* box, const char* hex, int x, int y) {
  lv_obj_t* sw = lv_obj_create(box);
  lv_obj_set_size(sw, TDP_SWATCH, TDP_SWATCH);
  lv_obj_set_pos(sw, x, y + 2);
  lv_obj_set_style_radius(sw, UI_RADIUS_INPUT, 0);
  lv_obj_set_style_border_width(sw, 1, 0);
  lv_obj_set_style_border_color(sw, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_pad_all(sw, 0, 0);
  lv_obj_clear_flag(sw, LV_OBJ_FLAG_SCROLLABLE);
  swatchPaintHex(sw, hex);
  char text[10];
  snprintf(text, sizeof(text), "#%s", hex);
  label(box, text, x + TDP_SWATCH + TDP_GAP / 2, y, TDP_VALUE_W - TDP_SWATCH - TDP_GAP / 2);
}

static int fieldText(uint8_t field) {
  switch (field) {
    case TDF_COLOR:      return STR_TAGDB_COLOR;
    case TDF_NOZZLE_MIN: return STR_TAGDB_NOZZLE_MIN;
    case TDF_NOZZLE_MAX: return STR_TAGDB_NOZZLE_MAX;
    default:             return STR_TAGDB_WEIGHT;
  }
}

static void diffRow(lv_obj_t* box, const TagDbDiff& d, int y) {
  restyle(label(box, T(fieldText(d.field)), TDP_LABEL_X, y, TDP_LABEL_W), UI_FONT_BODY, UI_COL_INK_SOFT);
  if (d.field == TDF_COLOR) {
    colorCell(box, d.tag_hex, TDP_TAG_X, y);
    colorCell(box, d.db_hex, TDP_DB_X, y);
    return;
  }
  const char* unit = d.field == TDF_WEIGHT ? "g" : "\xC2\xB0" "C";
  char text[16];
  snprintf(text, sizeof(text), "%d %s", d.tag_value, unit);
  label(box, text, TDP_TAG_X, y, TDP_VALUE_W);
  snprintf(text, sizeof(text), "%d %s", d.db_value, unit);
  label(box, text, TDP_DB_X, y, TDP_VALUE_W);
}

static void park(lv_event_t* e) {
  s_answer = (TdpAnswer)(intptr_t)lv_event_get_user_data(e);
  logSDf("BTN: TagDbDiff -> %s", s_answer == TDP_TAKE ? "take database" : "keep tag");
  // Hidden here, deleted by the loop: this is the button's own callback.
  if (s_box_scr) lv_obj_add_flag(s_box_scr, LV_OBJ_FLAG_HIDDEN);
}

static void answer(lv_obj_t* box, int x, bool keep) {
  lv_obj_t* btn = lv_btn_create(box);
  lv_obj_set_size(btn, TDP_BTN_W, UI_POPUP_BTN_H);
  lv_obj_set_pos(btn, x, UI_CARD_ROW_Y);
  lv_obj_set_style_bg_color(btn, lv_color_hex(keep ? UI_COL_OK_BG : UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(keep ? UI_COL_OK_BG_PRESSED : UI_COL_ROW_PRESS_FILL),
                            LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn, keep ? 0 : 1, 0);
  lv_obj_set_style_border_color(btn, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, park, LV_EVENT_CLICKED, (void*)(intptr_t)(keep ? TDP_KEEP : TDP_TAKE));
  lv_obj_t* l = lv_label_create(btn);
  lv_label_set_text(l, T(keep ? STR_TAGDB_KEEP : STR_TAGDB_TAKE));
  lv_obj_set_style_text_color(l, lv_color_hex(keep ? UI_COL_OK_TEXT : UI_COL_INK), 0);
  lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
  lv_obj_center(l);
}

static lv_obj_t* buildBox() {
  s_box_scr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(s_box_scr, LV_HOR_RES, LV_VER_RES);
  lv_obj_set_pos(s_box_scr, 0, 0);
  lv_obj_set_style_bg_color(s_box_scr, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(s_box_scr, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(s_box_scr, 0, 0);
  lv_obj_set_style_radius(s_box_scr, 0, 0);
  lv_obj_set_style_pad_all(s_box_scr, 0, 0);
  lv_obj_clear_flag(s_box_scr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t* box = lv_obj_create(s_box_scr);
  lv_obj_set_size(box, UI_POPUP_W, UI_CARD_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_WARN), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);
  return box;
}

void showTagDbDiffPopup(const TagDbDiff* diffs, int n, void (*done)(bool take_db)) {
  logSDf("SHOW: TagDbDiff (%d)", n);
  closeTagDbDiffPopup();
  s_done = done;
  lv_obj_t* box = buildBox();
  lv_obj_t* title = label(box, T(STR_TAGDB_TITLE), 0, TDP_TITLE_Y, UI_POPUP_W);
  restyle(title, UI_FONT_HEADLINE, UI_COL_INK);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
  restyle(label(box, T(STR_TAGDB_TAG), TDP_TAG_X, TDP_HEAD_Y, TDP_VALUE_W), UI_FONT_SMALL, UI_COL_CAPTION);
  restyle(label(box, T(STR_TAGDB_DB), TDP_DB_X, TDP_HEAD_Y, TDP_VALUE_W), UI_FONT_SMALL, UI_COL_CAPTION);
  for (int i = 0; i < n && i < TAG_DB_DIFFS_MAX; i++) diffRow(box, diffs[i], TDP_ROW_Y0 + i * TDP_ROW_H);
  answer(box, UI_CARD_ROW_X, true);
  answer(box, UI_CARD_ROW_X + TDP_BTN_W + TDP_GAP, false);
}

void tagDbDiffPopupTick() {
  if (s_answer == TDP_NONE) return;
  const bool take = s_answer == TDP_TAKE;
  void (*done)(bool) = s_done;
  closeTagDbDiffPopup();
  if (done) done(take);
}
