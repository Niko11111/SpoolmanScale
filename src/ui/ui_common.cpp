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

lv_obj_t* makeListBtn(lv_obj_t* list, const char* ico_sym, const char* title,
                      const char* sub, bool toggle_active,
                      lv_obj_t** out_help) {
  // The help button eats 30 px on the right, so the text has to give way.
  // Only when there is one - a row without help keeps its old width and its
  // old line breaks.
  const int text_w = out_help ? 290 : 320;
  lv_obj_t *btn = lv_btn_create(list);
  lv_obj_set_size(btn, 456, 64);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 10, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 1, 0);
  lv_obj_set_style_border_color(btn, toggle_active ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a3050), 0);
  lv_obj_set_style_pad_all(btn, 0, 0);

  lv_obj_t *ico = lv_label_create(btn);
  lv_label_set_text(ico, ico_sym);
  lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_20, 0);
  lv_obj_align(ico, LV_ALIGN_LEFT_MID, 14, 0);

  lv_obj_t *lbl = lv_label_create(btn);
  lv_label_set_text(lbl, title);
  lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_width(lbl, text_w);
  lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 52, sub && strlen(sub) > 0 ? -10 : 0);

  if (sub && strlen(sub) > 0) {
    lv_obj_t *slbl = lv_label_create(btn);
    lv_label_set_text(slbl, sub);
    lv_obj_set_style_text_color(slbl, toggle_active ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(slbl, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_width(slbl, text_w);
    lv_obj_align(slbl, LV_ALIGN_LEFT_MID, 52, 12);
  }

  // Built BEFORE the arrow on purpose. Three call sites reach for the arrow
  // with lv_obj_get_child(btn, -1) to turn it into ON/OFF; appending here
  // instead would hand them this button and the toggles would lose their
  // state display.
  //
  // A circled ASCII "?" rather than an icon: FontAwesome's question-circle is
  // in none of the 23 generated fonts and adding it would mean regenerating
  // all of them, while 0x20-0x7F is in every one. The web UI already draws its
  // help trigger exactly like this, so the two now match.
  if (out_help) {
    lv_obj_t *help = lv_btn_create(btn);
    lv_obj_set_size(help, 34, 34);
    lv_obj_align(help, LV_ALIGN_RIGHT_MID, -56, 0);
    lv_obj_set_style_bg_opa(help, LV_OPA_TRANSP, 0);
    lv_obj_set_style_bg_color(help, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
    lv_obj_set_style_bg_opa(help, LV_OPA_COVER, LV_STATE_PRESSED);
    lv_obj_set_style_border_color(help, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_border_width(help, 1, 0);
    lv_obj_set_style_radius(help, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_shadow_width(help, 0, 0);
    lv_obj_set_style_pad_all(help, 0, 0);
    // Below the 44 px touch minimum by design - a circle that big crowds the
    // row. The hit area is widened instead, which costs nothing visually.
    lv_obj_set_ext_click_area(help, 6);
    lv_obj_t *q = lv_label_create(help);
    lv_label_set_text(q, "?");
    lv_obj_set_style_text_color(q, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(q, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(q, LV_ALIGN_CENTER, 0, 0);
    *out_help = help;
  }

  lv_obj_t *arr = lv_label_create(btn);
  lv_label_set_text(arr, LV_SYMBOL_RIGHT);
  lv_obj_set_style_text_color(arr, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(arr, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(arr, LV_ALIGN_RIGHT_MID, -14, 0);
  return btn;
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
