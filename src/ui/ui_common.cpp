#include "ui_common.h"

#include <Arduino.h>
#include "navigation.h"

#include <cstdio>
#include <cstring>

#include "hardware/sd_logger.h"
#include "theme.h"


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
  lv_obj_set_style_text_color(l, tc(TH_TEXT_MUTED), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(l, INFO_ROW_LABEL_X, y + 3);
  if (out_label) *out_label = l;

  lv_obj_t *v = lv_label_create(parent);
  lv_label_set_text(v, "-");
  lv_obj_set_style_text_color(v, tc(TH_TEXT_BRIGHT), 0);
  lv_obj_set_style_text_font(v, &lv_font_montserrat_ext_16, 0);
  lv_label_set_long_mode(v, LV_LABEL_LONG_DOT);
  lv_obj_set_width(v, INFO_ROW_VALUE_W);
  lv_obj_set_pos(v, INFO_ROW_VALUE_X, y);
  return v;
}

lv_obj_t* makeListBtn(lv_obj_t* list, const char* ico_sym, const char* title,
                      const char* sub, bool toggle_active) {
  lv_obj_t *btn = lv_btn_create(list);
  lv_obj_set_size(btn, 456, 64);
  lv_obj_set_style_bg_color(btn, tc(TH_TILE_BG), 0);
  lv_obj_set_style_bg_color(btn, tc(TH_BORDER), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 10, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 1, 0);
  lv_obj_set_style_border_color(btn, toggle_active ? tc(TH_ACCENT) : tc(TH_BORDER), 0);
  lv_obj_set_style_pad_all(btn, 0, 0);

  lv_obj_t *ico = lv_label_create(btn);
  lv_label_set_text(ico, ico_sym);
  lv_obj_set_style_text_color(ico, tc(TH_ACCENT), 0);
  lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_20, 0);
  lv_obj_align(ico, LV_ALIGN_LEFT_MID, 14, 0);

  lv_obj_t *lbl = lv_label_create(btn);
  lv_label_set_text(lbl, title);
  lv_obj_set_style_text_color(lbl, tc(TH_TEXT_BRIGHT), 0);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_width(lbl, 320);
  lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 52, sub && strlen(sub) > 0 ? -10 : 0);

  if (sub && strlen(sub) > 0) {
    lv_obj_t *slbl = lv_label_create(btn);
    lv_label_set_text(slbl, sub);
    lv_obj_set_style_text_color(slbl, toggle_active ? tc(TH_ACCENT) : tc(TH_TEXT_MUTED), 0);
    lv_obj_set_style_text_font(slbl, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_width(slbl, 320);
    lv_obj_align(slbl, LV_ALIGN_LEFT_MID, 52, 12);
  }

  lv_obj_t *arr = lv_label_create(btn);
  lv_label_set_text(arr, LV_SYMBOL_RIGHT);
  lv_obj_set_style_text_color(arr, tc(TH_TEXT_DIM), 0);
  lv_obj_set_style_text_font(arr, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(arr, LV_ALIGN_RIGHT_MID, -14, 0);
  return btn;
}

void addBackButton(lv_obj_t *parent, lv_event_cb_t cb) {
  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, 44, 44);
  lv_obj_align(btn, LV_ALIGN_TOP_LEFT, 4, 2);
  lv_obj_set_style_bg_color(btn, tc(TH_SURFACE), 0);
  lv_obj_set_style_bg_color(btn, tc(TH_SURFACE_2), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 8, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl = lv_label_create(btn);
  lv_label_set_text(lbl, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_color(lbl, tc(TH_ACCENT), 0);
  lv_obj_center(lbl);
}

void addCloseButton(lv_obj_t *parent) {
  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, 44, 44);
  lv_obj_align(btn, LV_ALIGN_TOP_RIGHT, -4, 2);
  lv_obj_set_style_bg_color(btn, tc(TH_DANGER_BG), 0);
  lv_obj_set_style_bg_color(btn, tc(TH_DANGER_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 8, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, [](lv_event_t *e){ logSD("BTN: Close -> Main"); showMainScreen(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl = lv_label_create(btn);
  lv_label_set_text(lbl, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_color(lbl, tc(TH_DANGER_TEXT), 0);
  lv_obj_center(lbl);
}

void buildSubHeader(lv_obj_t *parent, const char *title,
                    lv_event_cb_t back_cb, const char *back_hint) {
  (void)back_hint;
  addBackButton(parent, back_cb);

  lv_obj_t *lbl_title = lv_label_create(parent);
  lv_label_set_text(lbl_title, title);
  lv_obj_set_style_text_color(lbl_title, tc(TH_ACCENT), 0);
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
  lv_obj_set_style_bg_color(scr, tc(TH_BG), 0);
  return scr;
}

// ---------------------------------------------------------------- registry
//
// Slots, not screens: the screen behind a slot is replaced constantly, so the
// registry stores the address of the pointer and reads it when it is needed.
// Registering the same slot twice is a no-op, so calling buildOverlayScreen()
// on every open costs nothing.
static lv_obj_t **s_slots[40];
static int s_slot_count = 0;

void overlayRegister(lv_obj_t **slot) {
  if (!slot) return;
  for (int i = 0; i < s_slot_count; i++) {
    if (s_slots[i] == slot) return;
  }
  if (s_slot_count >= (int)(sizeof(s_slots) / sizeof(s_slots[0]))) {
    // Silently dropping a screen here would resurrect exactly the bugs this
    // registry exists to prevent, so make it loud.
    Serial.println("overlayRegister: slot table full, raise the size");
    return;
  }
  s_slots[s_slot_count++] = slot;
}

lv_obj_t* buildOverlayScreen(lv_obj_t **slot) {
  lv_obj_t *scr = buildOverlayScreen();
  if (slot) {
    *slot = scr;
    overlayRegister(slot);
  }
  return scr;
}

void overlayHideAll() {
  for (int i = 0; i < s_slot_count; i++) {
    if (*s_slots[i]) lv_obj_add_flag(*s_slots[i], LV_OBJ_FLAG_HIDDEN);
  }
}

void overlayDropAll() {
  for (int i = 0; i < s_slot_count; i++) {
    if (*s_slots[i]) { lv_obj_del(*s_slots[i]); *s_slots[i] = nullptr; }
  }
}
