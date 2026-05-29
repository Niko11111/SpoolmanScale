#include "language_screen.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"

void showMainScreen();
void showRebootPopup();

void showLanguageScreen() {
  logSD("SHOW: LanguageScreen");
  logSD("UI: Screen -> Language");
  lv_obj_t *scr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr, 480, 320);
  lv_obj_set_pos(scr, 0, 0);
  lv_obj_set_style_bg_color(scr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(scr, 0, 0);
  lv_obj_set_style_radius(scr, 0, 0);
  lv_obj_set_style_pad_all(scr, 0, 0);
  lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *btn_back = lv_btn_create(scr);
  lv_obj_set_size(btn_back, 44, 44);
  lv_obj_set_pos(btn_back, 4, 2);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_back, 0, 0);
  lv_obj_set_style_border_width(btn_back, 0, 0);
  lv_obj_t *lbl_bk = lv_label_create(btn_back);
  lv_label_set_text(lbl_bk, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_color(lbl_bk, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_bk, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_bk);
  lv_obj_add_event_cb(btn_back, [](lv_event_t *e){
    lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *hdr = lv_label_create(scr);
  lv_label_set_text(hdr, "Language / Sprache");
  lv_obj_set_style_text_color(hdr, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(hdr, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(hdr, LV_ALIGN_TOP_MID, 0, 12);

  lv_obj_t *btn_x = lv_btn_create(scr);
  lv_obj_set_size(btn_x, 44, 44);
  lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_x, 0, 0);
  lv_obj_set_style_border_width(btn_x, 0, 0);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e){
    lv_obj_t *scr_lang = lv_obj_get_parent(lv_event_get_target(e));
    lv_obj_del(scr_lang);
    showMainScreen();
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *hint = lv_label_create(scr);
  lv_label_set_text(hint, T(STR_LANG_HINT));
  lv_obj_set_style_text_color(hint, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(hint, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(hint, 440);
  lv_obj_align(hint, LV_ALIGN_TOP_MID, 0, 52);

  const int LB_W = 218, LB_H = 52, LB_Y0 = 90;

  lv_obj_t *btn_de = lv_btn_create(scr);
  lv_obj_set_size(btn_de, LB_W, LB_H);
  lv_obj_set_pos(btn_de, 8, LB_Y0);
  bool de_active = (g_lang == LANG_DE);
  lv_obj_set_style_bg_color(btn_de, lv_color_hex(de_active ? 0x0a2a40 : 0x0a1828), 0);
  lv_obj_set_style_radius(btn_de, 10, 0);
  lv_obj_set_style_shadow_width(btn_de, 0, 0);
  lv_obj_set_style_border_width(btn_de, 2, 0);
  lv_obj_set_style_border_color(btn_de, lv_color_hex(de_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_t *lbl_de = lv_label_create(btn_de);
  lv_label_set_text(lbl_de, "DE   Deutsch");
  lv_obj_set_style_text_color(lbl_de, lv_color_hex(de_active ? 0x28d49a : 0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_de, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_de);
  lv_obj_add_event_cb(btn_de, [](lv_event_t *e){
    g_lang = LANG_DE;
    prefsPutUChar("lang", 0);
    Serial.println("Language: German -> Reboot");
    showRebootPopup();
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_en = lv_btn_create(scr);
  lv_obj_set_size(btn_en, LB_W, LB_H);
  lv_obj_set_pos(btn_en, 254, LB_Y0);
  bool en_active = (g_lang == LANG_EN);
  lv_obj_set_style_bg_color(btn_en, lv_color_hex(en_active ? 0x0a2a40 : 0x0a1828), 0);
  lv_obj_set_style_radius(btn_en, 10, 0);
  lv_obj_set_style_shadow_width(btn_en, 0, 0);
  lv_obj_set_style_border_width(btn_en, 2, 0);
  lv_obj_set_style_border_color(btn_en, lv_color_hex(en_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_t *lbl_en = lv_label_create(btn_en);
  lv_label_set_text(lbl_en, "EN   English");
  lv_obj_set_style_text_color(lbl_en, lv_color_hex(en_active ? 0x28d49a : 0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_en, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_en);
  lv_obj_add_event_cb(btn_en, [](lv_event_t *e){
    g_lang = LANG_EN;
    prefsPutUChar("lang", 1);
    Serial.println("Language: English -> Reboot");
    showRebootPopup();
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_date = lv_label_create(scr);
  lv_label_set_text(lbl_date, T(STR_DATE_FMT_LABEL));
  lv_obj_set_style_text_color(lbl_date, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_date, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(lbl_date, 12, 158);

  const int DB_W = 218, DB_H = 52, DB_Y = 178;

  lv_obj_t *btn_dmy = lv_btn_create(scr);
  lv_obj_set_size(btn_dmy, DB_W, DB_H);
  lv_obj_set_pos(btn_dmy, 8, DB_Y);
  bool dmy_active = (g_date_fmt == 0);
  lv_obj_set_style_bg_color(btn_dmy, lv_color_hex(dmy_active ? 0x0a2a40 : 0x0a1828), 0);
  lv_obj_set_style_radius(btn_dmy, 10, 0);
  lv_obj_set_style_shadow_width(btn_dmy, 0, 0);
  lv_obj_set_style_border_width(btn_dmy, 2, 0);
  lv_obj_set_style_border_color(btn_dmy, lv_color_hex(dmy_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_t *lbl_dmy = lv_label_create(btn_dmy);
  lv_label_set_text(lbl_dmy, "DD.MM.YYYY");
  lv_obj_set_style_text_color(lbl_dmy, lv_color_hex(dmy_active ? 0x28d49a : 0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_dmy, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_dmy);
  lv_obj_add_event_cb(btn_dmy, [](lv_event_t *e){
    g_date_fmt = 0;
    prefsPutUChar("date_fmt", 0);
    showRebootPopup();
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_iso = lv_btn_create(scr);
  lv_obj_set_size(btn_iso, DB_W, DB_H);
  lv_obj_set_pos(btn_iso, 254, DB_Y);
  bool iso_active = (g_date_fmt == 1);
  lv_obj_set_style_bg_color(btn_iso, lv_color_hex(iso_active ? 0x0a2a40 : 0x0a1828), 0);
  lv_obj_set_style_radius(btn_iso, 10, 0);
  lv_obj_set_style_shadow_width(btn_iso, 0, 0);
  lv_obj_set_style_border_width(btn_iso, 2, 0);
  lv_obj_set_style_border_color(btn_iso, lv_color_hex(iso_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_t *lbl_iso = lv_label_create(btn_iso);
  lv_label_set_text(lbl_iso, "YYYY-MM-DD");
  lv_obj_set_style_text_color(lbl_iso, lv_color_hex(iso_active ? 0x28d49a : 0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_iso, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_iso);
  lv_obj_add_event_cb(btn_iso, [](lv_event_t *e){
    g_date_fmt = 1;
    prefsPutUChar("date_fmt", 1);
    showRebootPopup();
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *hint2 = lv_label_create(scr);
  lv_label_set_text(hint2, T(STR_LANG_HINT));
  lv_obj_set_style_text_color(hint2, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(hint2, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(hint2, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(hint2, LV_ALIGN_BOTTOM_MID, 0, -8);
}
