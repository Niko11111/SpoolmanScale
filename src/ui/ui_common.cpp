#include "ui_common.h"
#include "navigation.h"

#include <cstdio>
#include <cstring>

#include "hardware/sd_logger.h"


lv_color_t swatchColorFromHex(const char* hex) {
  if (!hex) return lv_color_hex(SWATCH_FALLBACK_COLOR);
  const char* h = (hex[0] == '#') ? hex + 1 : hex;
  if (strlen(h) < 6) return lv_color_hex(SWATCH_FALLBACK_COLOR);

  unsigned int r, g, b;
  if (sscanf(h, "%02X%02X%02X", &r, &g, &b) != 3) return lv_color_hex(SWATCH_FALLBACK_COLOR);
  return lv_color_hex(((uint32_t)r << 16) | ((uint32_t)g << 8) | b);
}


lv_obj_t* addInfoRow(lv_obj_t* parent, int y, const char* label,
                     lv_obj_t** out_label) {
  lv_obj_t *l = lv_label_create(parent);
  lv_label_set_text(l, label);
  lv_obj_set_style_text_color(l, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(l, INFO_ROW_LABEL_X, y + 3);
  if (out_label) *out_label = l;

  lv_obj_t *v = lv_label_create(parent);
  lv_label_set_text(v, "-");
  lv_obj_set_style_text_color(v, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(v, &lv_font_montserrat_ext_16, 0);
  lv_label_set_long_mode(v, LV_LABEL_LONG_DOT);
  lv_obj_set_width(v, INFO_ROW_VALUE_W);
  lv_obj_set_pos(v, INFO_ROW_VALUE_X, y);
  return v;
}

void addBackButton(lv_obj_t *parent, lv_event_cb_t cb) {
  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, 44, 44);
  lv_obj_align(btn, LV_ALIGN_TOP_LEFT, 4, 2);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 8, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl = lv_label_create(btn);
  lv_label_set_text(lbl, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_color(lbl, lv_color_hex(0x28d49a), 0);
  lv_obj_center(lbl);
}

void addCloseButton(lv_obj_t *parent) {
  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, 44, 44);
  lv_obj_align(btn, LV_ALIGN_TOP_RIGHT, -4, 2);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 8, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, [](lv_event_t *e){ logSD("BTN: Close -> Main"); showMainScreen(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl = lv_label_create(btn);
  lv_label_set_text(lbl, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_color(lbl, lv_color_hex(0xff8080), 0);
  lv_obj_center(lbl);
}

void buildSubHeader(lv_obj_t *parent, const char *title,
                    lv_event_cb_t back_cb, const char *back_hint) {
  (void)back_hint;
  addBackButton(parent, back_cb);

  lv_obj_t *lbl_title = lv_label_create(parent);
  lv_label_set_text(lbl_title, title);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);

  addCloseButton(parent);
}

void releaseScreen(lv_obj_t **scr) {
  if (!scr || !*scr) return;
  lv_obj_del_async(*scr);
  *scr = nullptr;
}

lv_obj_t* buildOverlayScreen() {
  lv_obj_t *scr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr, 480, 320);
  lv_obj_set_pos(scr, 0, 0);
  lv_obj_add_flag(scr, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr, 0, 0);
  lv_obj_set_style_border_width(scr, 0, 0);
  lv_obj_set_style_pad_all(scr, 0, 0);
  lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr, lv_color_hex(0x0a1020), 0);
  return scr;
}
