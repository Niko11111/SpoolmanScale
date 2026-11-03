#include "tare_missing_popup.h"

#include <Arduino.h>
#include <lvgl.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "tare_entry.h"
#include "theme.h"
#include "ui_common.h"

static lv_obj_t *s_popup = nullptr;
static int       s_spool_id = 0;

static lv_obj_t* cardText(lv_obj_t *box, const char *text, const lv_font_t *font, uint32_t col, int y) {
  lv_obj_t *l = lv_label_create(box);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_color(l, lv_color_hex(col), 0);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(l, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(l, LV_ALIGN_TOP_MID, 0, y);
  return l;
}

static lv_obj_t* cardButton(lv_obj_t *box, int x, const char *text, uint32_t fill, uint32_t pressed) {
  lv_obj_t *b = lv_btn_create(box);
  lv_obj_set_size(b, UI_POPUP_BTN_W, UI_POPUP_BTN_H);
  lv_obj_set_pos(b, x, UI_CARD_ROW_Y);
  lv_obj_set_style_bg_color(b, lv_color_hex(fill), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(pressed), LV_STATE_PRESSED);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_border_width(b, 0, 0);
  lv_obj_set_style_pad_all(b, 0, 0);
  lv_obj_clear_flag(b, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_t *l = lv_label_create(b);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK), 0);
  lv_obj_center(l);
  return b;
}

void showTareMissingPopup() {
  logSDf("SHOW: TareMissingPopup (spool %d)", sm_id);
  s_spool_id = sm_id;
  lv_obj_t *box = uiPopupBox(&s_popup, UI_POPUP_W, UI_CARD_H);
  lv_obj_t *icon = cardText(box, LV_SYMBOL_WARNING, UI_FONT_ICON, UI_COL_WARN, UI_CARD_ICON_Y);
  lv_obj_set_width(icon, LV_SIZE_CONTENT);
  lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, UI_CARD_ICON_Y);
  cardText(box, T(STR_TARE_MISSING), UI_FONT_HEADLINE, UI_COL_INK, UI_CARD_TITLE_Y);
  cardText(box, T(STR_TARE_MISSING_TEXT), UI_FONT_BODY, UI_COL_INK_2, UI_CARD_TEXT_Y);

  lv_obj_t *enter = cardButton(box, UI_CARD_ROW_X, T(STR_TARE_MISSING_ENTER), UI_COL_OK_BG, UI_COL_OK_BG_PRESSED);
  lv_obj_add_event_cb(enter, [](lv_event_t *e) {
    releaseScreen(&s_popup);
    showTareEntryPad();
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *close = cardButton(box, UI_POPUP_W - UI_POPUP_BTN_W - UI_CARD_ROW_X, T(STR_BT_CLOSE),
                               UI_COL_ROW, UI_COL_ROW_PRESS_FILL);
  styleLeaveButton(close);
  lv_obj_add_event_cb(close, [](lv_event_t *e) { releaseScreen(&s_popup); }, LV_EVENT_CLICKED, NULL);
}

bool isTareMissingOpen() {
  return s_popup != nullptr;
}

void tareMissingTick() {
  if (!s_popup || sm_id == s_spool_id) return;
  logSDf("UI: empty weight question for spool %d closed, spool %d is loaded now", s_spool_id, sm_id);
  releaseScreen(&s_popup);
}
