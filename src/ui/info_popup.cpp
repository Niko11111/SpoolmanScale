#include "info_popup.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"

// Longest German explanation is around 180 bytes, and an umlaut costs two of
// them. 256 leaves room to grow a text without silently truncating it mid
// character, which would render as a broken glyph.
#define INFO_TEXT_BUF   256
#define INFO_TITLE_BUF   48

void showInfoPopup(int title_id, int text_id) {
  if (title_id < 0 || title_id >= STR_COUNT) return;
  if (text_id  < 0 || text_id  >= STR_COUNT) return;

  lv_obj_t *pop = lv_obj_create(lv_scr_act());
  lv_obj_set_size(pop, 480, 320);
  lv_obj_set_pos(pop, 0, 0);
  lv_obj_set_style_bg_color(pop, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(pop, LV_OPA_70, 0);
  lv_obj_set_style_border_width(pop, 0, 0);
  lv_obj_set_style_radius(pop, 0, 0);
  lv_obj_set_style_pad_all(pop, 0, 0);
  lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(pop);
  lv_obj_set_size(box, 440, 250);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x2a4080), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // Title: the name of the setting, so the popup is anchored to the row the
  // user tapped rather than being a floating paragraph.
  lv_obj_t *title = lv_label_create(box);
  char tbuf[INFO_TITLE_BUF];
  strncpy(tbuf, T(title_id), sizeof(tbuf) - 1);
  tbuf[sizeof(tbuf) - 1] = '\0';
  lv_label_set_text(title, tbuf);
  lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(title, 424);
  lv_obj_set_pos(title, 8, 14);

  lv_obj_t *info = lv_label_create(box);
  char ibuf[INFO_TEXT_BUF];
  strncpy(ibuf, T(text_id), sizeof(ibuf) - 1);
  ibuf[sizeof(ibuf) - 1] = '\0';
  lv_label_set_text(info, ibuf);
  lv_obj_set_style_text_color(info, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(info, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(info, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(info, 424);
  lv_obj_set_pos(info, 8, 52);

  lv_obj_t *btn = lv_btn_create(box);
  lv_obj_set_size(btn, 200, 48);
  lv_obj_set_pos(btn, 120, 188);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x2a4080), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 8, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, [](lv_event_t *e) {
    // Two levels up from the button: box, then the scrim that owns everything.
    // Deleted asynchronously because this runs inside the dispatch of an event
    // belonging to a child of what is being freed.
    lv_obj_t *box = lv_obj_get_parent(lv_event_get_target(e));
    lv_obj_del_async(lv_obj_get_parent(box));
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *l = lv_label_create(btn);
  char bbuf[24];
  strncpy(bbuf, T(STR_BACK), sizeof(bbuf) - 1);
  bbuf[sizeof(bbuf) - 1] = '\0';
  lv_label_set_text(l, bbuf);
  lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(l, LV_ALIGN_CENTER, 0, 0);
}

void infoPopupEventCb(lv_event_t *e) {
  const intptr_t packed = (intptr_t)lv_event_get_user_data(e);
  showInfoPopup((int)(packed >> 16), (int)(packed & 0xFFFF));
}
