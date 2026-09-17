#include "language_screen.h"
#include "navigation.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "reboot_popup.h"
#include "app/deferred_actions.h"
#include "services/time_service.h"


// The screen manages itself rather than living in app_state: it is created
// on demand and deleted by its own buttons. The pointer exists so the time
// zone screen can take its place without leaving it alive underneath.
static lv_obj_t *scr_language = nullptr;

// What a button picked, held until the restart is confirmed and written to
// NVS only then. The buttons used to save and set g_lang on the spot, so
// cancelling the restart left a half translated screen and the new language
// on the next boot anyway. Each button clears the other's pick: a cancelled
// choice must not ride along with the next one.
static int s_pick_lang = -1;   // 0 DE, 1 EN, 2 FR, -1 untouched
static int s_pick_date = -1;   // 0 DD.MM.YYYY, 1 YYYY-MM-DD, -1 untouched

static void commitLanguageChoice() {
  if (s_pick_lang >= 0) prefsPutUChar("lang", (uint8_t)s_pick_lang);
  if (s_pick_date >= 0) prefsPutUChar("date_fmt", (uint8_t)s_pick_date);
  logSDf("Language: committed lang=%d date_fmt=%d", s_pick_lang, s_pick_date);
  s_pick_lang = s_pick_date = -1;
}

void hideLanguageScreen() {
  if (scr_language) lv_obj_add_flag(scr_language, LV_OBJ_FLAG_HIDDEN);
}

void closeLanguageScreen() {
  if (!scr_language) return;
  lv_obj_del_async(scr_language);
  scr_language = nullptr;
}

void showLanguageScreen() {
  logSD("SHOW: LanguageScreen");
  logSD("UI: Screen -> Language");
  closeLanguageScreen();
  s_pick_lang = s_pick_date = -1;
  lv_obj_t *scr = lv_obj_create(lv_scr_act());
  scr_language = scr;
  // Whoever deletes it, the pointer stops pointing at it. The back and close
  // buttons below delete the screen directly, so clearing the pointer in one
  // place beats remembering it in three.
  //
  // Only when it is still this object. closeLanguageScreen() deletes
  // asynchronously, so opening the screen twice in quick succession builds the
  // replacement before the old one is destroyed - and an unconditional clear
  // would then null the pointer to the screen that is now up.
  lv_obj_add_event_cb(scr, [](lv_event_t *e){
    if (scr_language == lv_event_get_target(e)) scr_language = nullptr;
  }, LV_EVENT_DELETE, NULL);
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
    closeLanguageScreen();      // asynchronous: this button sits on it
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
    closeLanguageScreen();
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

  // Three buttons on the one row this screen has: 8 px margins as before, two
  // 10 px gaps, so (480 - 16 - 20) / 3 = 148. Nothing below y = 90 moves,
  // which matters - the time zone row already ends at 302 of 320. The labels
  // lose their "DE " / "EN " prefix to make room; "Deutsch" measures 69 px at
  // this font, "Français" 68, so 148 is comfortable.
  const int LB_W = 148, LB_H = 52, LB_Y0 = 90;
  const int LB_X_DE = 8, LB_X_EN = 166, LB_X_FR = 324;

  lv_obj_t *btn_de = lv_btn_create(scr);
  lv_obj_set_size(btn_de, LB_W, LB_H);
  lv_obj_set_pos(btn_de, LB_X_DE, LB_Y0);
  bool de_active = (g_lang == LANG_DE);
  lv_obj_set_style_bg_color(btn_de, lv_color_hex(de_active ? 0x0a2a40 : 0x0a1828), 0);
  lv_obj_set_style_radius(btn_de, 10, 0);
  lv_obj_set_style_shadow_width(btn_de, 0, 0);
  lv_obj_set_style_border_width(btn_de, 2, 0);
  lv_obj_set_style_border_color(btn_de, lv_color_hex(de_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_t *lbl_de = lv_label_create(btn_de);
  lv_label_set_text(lbl_de, "Deutsch");
  lv_obj_set_style_text_color(lbl_de, lv_color_hex(de_active ? 0x28d49a : 0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_de, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_de);
  lv_obj_add_event_cb(btn_de, [](lv_event_t *e){
    s_pick_lang = 0; s_pick_date = -1;
    Serial.println("Language: German -> Reboot");
    showRebootPopup(commitLanguageChoice);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_en = lv_btn_create(scr);
  lv_obj_set_size(btn_en, LB_W, LB_H);
  lv_obj_set_pos(btn_en, LB_X_EN, LB_Y0);
  bool en_active = (g_lang == LANG_EN);
  lv_obj_set_style_bg_color(btn_en, lv_color_hex(en_active ? 0x0a2a40 : 0x0a1828), 0);
  lv_obj_set_style_radius(btn_en, 10, 0);
  lv_obj_set_style_shadow_width(btn_en, 0, 0);
  lv_obj_set_style_border_width(btn_en, 2, 0);
  lv_obj_set_style_border_color(btn_en, lv_color_hex(en_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_t *lbl_en = lv_label_create(btn_en);
  lv_label_set_text(lbl_en, "English");
  lv_obj_set_style_text_color(lbl_en, lv_color_hex(en_active ? 0x28d49a : 0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_en, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_en);
  lv_obj_add_event_cb(btn_en, [](lv_event_t *e){
    s_pick_lang = 1; s_pick_date = -1;
    Serial.println("Language: English -> Reboot");
    showRebootPopup(commitLanguageChoice);
  }, LV_EVENT_CLICKED, NULL);

  // The cedilla comes from the Latin-1 supplement reached through the font's
  // fallback, so this label needs src/fonts/lv_font_fr_supp_16.c to be present.
  lv_obj_t *btn_fr = lv_btn_create(scr);
  lv_obj_set_size(btn_fr, LB_W, LB_H);
  lv_obj_set_pos(btn_fr, LB_X_FR, LB_Y0);
  bool fr_active = (g_lang == LANG_FR);
  lv_obj_set_style_bg_color(btn_fr, lv_color_hex(fr_active ? 0x0a2a40 : 0x0a1828), 0);
  lv_obj_set_style_radius(btn_fr, 10, 0);
  lv_obj_set_style_shadow_width(btn_fr, 0, 0);
  lv_obj_set_style_border_width(btn_fr, 2, 0);
  lv_obj_set_style_border_color(btn_fr, lv_color_hex(fr_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_t *lbl_fr = lv_label_create(btn_fr);
  lv_label_set_text(lbl_fr, "Français");
  lv_obj_set_style_text_color(lbl_fr, lv_color_hex(fr_active ? 0x28d49a : 0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_fr, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_fr);
  lv_obj_add_event_cb(btn_fr, [](lv_event_t *e){
    s_pick_lang = 2; s_pick_date = -1;
    Serial.println("Language: French -> Reboot");
    showRebootPopup(commitLanguageChoice);
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
    s_pick_date = 0; s_pick_lang = -1;
    showRebootPopup(commitLanguageChoice);
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
    s_pick_date = 1; s_pick_lang = -1;
    showRebootPopup(commitLanguageChoice);
  }, LV_EVENT_CLICKED, NULL);

  // Time zone. A row rather than a pair of buttons, because there are twelve
  // of them: the button carries the current zone so the setting can be read
  // without opening the picker.
  //
  // The hint that used to sit here was a second copy of the one at the top of
  // the screen, word for word.
  lv_obj_t *lbl_tz = lv_label_create(scr);
  { char buf[32]; copyT(buf, sizeof(buf), STR_TZ_TITLE);
    lv_label_set_text(lbl_tz, buf); }
  lv_obj_set_style_text_color(lbl_tz, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_tz, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(lbl_tz, 12, 238);

  lv_obj_t *btn_tz = lv_btn_create(scr);
  lv_obj_set_size(btn_tz, 464, 44);
  lv_obj_set_pos(btn_tz, 8, 258);
  lv_obj_set_style_bg_color(btn_tz, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_tz, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_tz, 10, 0);
  lv_obj_set_style_shadow_width(btn_tz, 0, 0);
  lv_obj_set_style_border_width(btn_tz, 1, 0);
  lv_obj_set_style_border_color(btn_tz, lv_color_hex(0x1a3050), 0);

  lv_obj_t *lbl_tz_val = lv_label_create(btn_tz);
  { char buf[48]; strncpy(buf, timeZoneName(), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    lv_label_set_text(lbl_tz_val, buf); }
  lv_obj_set_style_text_color(lbl_tz_val, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl_tz_val, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_tz_val, LV_ALIGN_LEFT_MID, 14, 0);

  lv_obj_t *lbl_tz_arr = lv_label_create(btn_tz);
  lv_label_set_text(lbl_tz_arr, LV_SYMBOL_RIGHT);
  lv_obj_set_style_text_color(lbl_tz_arr, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_tz_arr, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_tz_arr, LV_ALIGN_RIGHT_MID, -14, 0);

  // No reboot popup: unlike the language and the date format above, a zone
  // takes effect on the next localtime_r().
  lv_obj_add_event_cb(btn_tz, [](lv_event_t *e){
    logSD("BTN: Language -> Time zone");
    show_timezone_pending = true;
  }, LV_EVENT_CLICKED, NULL);
}
