#include "setup_welcome_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "ui_common.h"
#include "wifi_setup_screen.h"
#include "services/backend.h"



void showWelcomeScreen() {
  logSD("SHOW: WelcomeScreen");
  logSD("UI: Screen -> Welcome");
  hideAllOverlays();
  if (!scr_welcome) buildWelcomeScreen();
  lv_obj_clear_flag(scr_welcome, LV_OBJ_FLAG_HIDDEN);
}

void buildWelcomeScreen() {
  logSD("BUILD: WelcomeScreen");
  releaseScreen(&scr_welcome);
  scr_welcome = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_welcome, 480, 320);
  lv_obj_set_pos(scr_welcome, 0, 0);
  lv_obj_add_flag(scr_welcome, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_welcome, 0, 0);
  lv_obj_set_style_border_width(scr_welcome, 0, 0);
  lv_obj_set_style_pad_all(scr_welcome, 0, 0);
  lv_obj_clear_flag(scr_welcome, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_welcome, lv_color_hex(0x0a1020), 0);

  lv_obj_t *lbl_logo = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_logo, "SpoolmanScale");
  lv_obj_set_style_text_color(lbl_logo, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_logo, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(lbl_logo, LV_ALIGN_TOP_MID, 0, 24);

  lv_obj_t *lbl_sub = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_sub, T(STR_WELCOME_LANG_TITLE));
  lv_obj_set_style_text_color(lbl_sub, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_sub, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_sub, LV_ALIGN_TOP_MID, 0, 64);

  lv_obj_t *lbl_hint = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_hint, T(STR_WELCOME_LANG_HINT));
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint, 420);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 96);

  if (cfg_lang_set) {
    lv_obj_t *btn_x = lv_btn_create(scr_welcome);
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
    lv_obj_add_event_cb(btn_x, [](lv_event_t *e){ logSD("BTN: Close -> Main"); showMainScreen(); }, LV_EVENT_CLICKED, NULL);
  }

  const int LB_W = 218, LB_H = 60, LB_Y = 136;

  lv_obj_t *btn_en = lv_btn_create(scr_welcome);
  lv_obj_set_size(btn_en, LB_W, LB_H);
  lv_obj_set_pos(btn_en, 8, LB_Y);
  lv_obj_set_style_bg_color(btn_en, lv_color_hex(0x0a2a40), 0);
  lv_obj_set_style_bg_color(btn_en, lv_color_hex(0x1a4060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_en, 10, 0);
  lv_obj_set_style_shadow_width(btn_en, 0, 0);
  lv_obj_set_style_border_width(btn_en, 2, 0);
  lv_obj_set_style_border_color(btn_en, lv_color_hex(0x28d49a), 0);
  lv_obj_t *lbl_en = lv_label_create(btn_en);
  lv_label_set_text(lbl_en, "EN   English");
  lv_obj_set_style_text_color(lbl_en, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_en, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_en);
  lv_obj_add_event_cb(btn_en, [](lv_event_t *e){
    prefsPutUChar("lang", 1);
    prefsPutBool("lang_set", true);
    prefsPutBool("first_boot", true);
    g_lang = LANG_EN;
    cfg_lang_set = true;
    cfg_first_boot = true;
    lang_selected_no_reboot = true;
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_de = lv_btn_create(scr_welcome);
  lv_obj_set_size(btn_de, LB_W, LB_H);
  lv_obj_set_pos(btn_de, 254, LB_Y);
  lv_obj_set_style_bg_color(btn_de, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_de, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_de, 10, 0);
  lv_obj_set_style_shadow_width(btn_de, 0, 0);
  lv_obj_set_style_border_width(btn_de, 2, 0);
  lv_obj_set_style_border_color(btn_de, lv_color_hex(0x1a3060), 0);
  lv_obj_t *lbl_de = lv_label_create(btn_de);
  lv_label_set_text(lbl_de, "DE   Deutsch");
  lv_obj_set_style_text_color(lbl_de, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_de, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_de);
  lv_obj_add_event_cb(btn_de, [](lv_event_t *e){
    g_lang = LANG_DE;
    prefsPutUChar("lang", 0);
    prefsPutBool("lang_set", true);
    prefsPutBool("first_boot", true);
    ESP.restart();
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_skip = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_skip, T(STR_LANG_HINT));
  lv_obj_set_style_text_color(lbl_skip, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_skip, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_skip, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_skip, LV_ALIGN_BOTTOM_MID, 0, -10);
}

void showFirstBootScreen() {
  logSD("SHOW: FirstBootScreen");
  logSD("UI: Screen -> FirstBoot");
  hideAllOverlays();
  if (!scr_first_boot) buildFirstBootScreen();
  lv_obj_clear_flag(scr_first_boot, LV_OBJ_FLAG_HIDDEN);
}

void buildFirstBootScreen() {
  logSD("BUILD: FirstBootScreen");
  releaseScreen(&scr_first_boot);
  scr_first_boot = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_first_boot, 480, 320);
  lv_obj_set_pos(scr_first_boot, 0, 0);
  lv_obj_add_flag(scr_first_boot, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_first_boot, 0, 0);
  lv_obj_set_style_border_width(scr_first_boot, 0, 0);
  lv_obj_set_style_pad_all(scr_first_boot, 0, 0);
  lv_obj_clear_flag(scr_first_boot, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_first_boot, lv_color_hex(0x0a1020), 0);

  lv_obj_t *lbl_logo = lv_label_create(scr_first_boot);
  lv_label_set_text(lbl_logo, "SpoolmanScale");
  lv_obj_set_style_text_color(lbl_logo, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_logo, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(lbl_logo, LV_ALIGN_TOP_MID, 0, 32);

  lv_obj_t *lbl_title = lv_label_create(scr_first_boot);
  lv_label_set_text(lbl_title, T(STR_FIRSTBOOT_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_20, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 72);

  lv_obj_t *lbl_sub = lv_label_create(scr_first_boot);
  lv_label_set_text(lbl_sub, T(STR_FIRSTBOOT_SUB));
  lv_obj_set_style_text_color(lbl_sub, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_sub, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_sub, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_sub, LV_ALIGN_TOP_MID, 0, 104);

  lv_obj_t *lbl_hint = lv_label_create(scr_first_boot);
  // No backendText() here: at this point no backend has been chosen, and the
  // text deliberately names both. Substituting would turn it into
  // "FilaMan/FilaMan" once a mode is stored.
  { char hb[128]; strncpy(hb, T(STR_FIRSTBOOT_HINT), sizeof(hb) - 1); hb[sizeof(hb) - 1] = '\0';
    lv_label_set_text(lbl_hint, hb); }
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint, 420);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 138);

  if (strlen(cfg_wifi_ssid) > 0) {
    lv_obj_t *btn_cx = lv_btn_create(scr_first_boot);
    lv_obj_set_size(btn_cx, 44, 44);
    lv_obj_align(btn_cx, LV_ALIGN_TOP_RIGHT, -4, 2);
    lv_obj_set_style_bg_color(btn_cx, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_cx, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_cx, 8, 0);
    lv_obj_set_style_shadow_width(btn_cx, 0, 0);
    lv_obj_set_style_border_width(btn_cx, 0, 0);
    lv_obj_add_event_cb(btn_cx, [](lv_event_t *e){ logSD("BTN: Close -> Main"); showMainScreen(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_cx = lv_label_create(btn_cx);
    lv_label_set_text(lbl_cx, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(lbl_cx, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_cx, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(lbl_cx);
  }

  lv_obj_t *btn_start = lv_btn_create(scr_first_boot);
  lv_obj_set_size(btn_start, 226, 48);
  lv_obj_set_pos(btn_start, 12, 252);
  lv_obj_set_style_bg_color(btn_start, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_start, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_start, 10, 0);
  lv_obj_set_style_shadow_width(btn_start, 0, 0);
  lv_obj_set_style_border_width(btn_start, 1, 0);
  lv_obj_set_style_border_color(btn_start, lv_color_hex(0x2a5030), 0);
  lv_obj_add_event_cb(btn_start, [](lv_event_t *e) {
    prefsPutBool("first_boot", false);
    cfg_first_boot = false;
    showWifiSetupScreen();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_start = lv_label_create(btn_start);
  lv_label_set_text(lbl_start, T(STR_FIRSTBOOT_BTN));
  lv_obj_set_style_text_color(lbl_start, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_start, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_start, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_start, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *btn_skip = lv_btn_create(scr_first_boot);
  lv_obj_set_size(btn_skip, 226, 48);
  lv_obj_set_pos(btn_skip, 242, 252);
  lv_obj_set_style_bg_color(btn_skip, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_skip, lv_color_hex(0x1a2840), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_skip, 10, 0);
  lv_obj_set_style_shadow_width(btn_skip, 0, 0);
  lv_obj_set_style_border_width(btn_skip, 1, 0);
  lv_obj_set_style_border_color(btn_skip, lv_color_hex(0x1a2840), 0);
  lv_obj_add_event_cb(btn_skip, [](lv_event_t *e) {
    skip_setup_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_skip = lv_label_create(btn_skip);
  char skip_buf[32];
  strncpy(skip_buf, T(STR_BTN_SKIP_SETUP), sizeof(skip_buf)-1);
  lv_label_set_text(lbl_skip, skip_buf);
  lv_obj_set_style_text_color(lbl_skip, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_skip, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_skip, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_skip, LV_ALIGN_CENTER, 0, 0);
}
