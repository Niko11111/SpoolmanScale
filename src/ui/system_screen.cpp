#include "system_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <SD.h>
#include <lvgl.h>
#include <nvs_flash.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/ota_state.h"
#include "ui_common.h"
#include "update_badges.h"
#include "web_screen.h"
#include "services/backend.h"


void showLanguageScreen();

void buildSystemScreen() {
  logSD("BUILD: SystemScreen");
  if (sd_verbose) logSD("[verbose] buildSystemScreen: start");
  releaseScreen(&scr_system);
  scr_system = buildOverlayScreen();
  buildSubHeader(scr_system, T(STR_SYSTEM_TITLE),
    [](lv_event_t *e){ logSD("BTN: Back -> Settings"); showSettingsScreen(); });

  // 3 main buttons 62px + 1 reset button 44px, gap=5, y0=52
  const int BTN_W = 456, BTN_H = 52, RESET_H = 44, BTN_GAP = 3, BTN_X = 12, BTN_Y0 = 52;

  // ── Button 1: Language ──
  lv_obj_t *btn_lang = lv_btn_create(scr_system);
  lv_obj_set_size(btn_lang, BTN_W, BTN_H);
  lv_obj_set_pos(btn_lang, BTN_X, BTN_Y0);
  lv_obj_set_style_bg_color(btn_lang, lv_color_hex(0x0a1a2a), 0);
  lv_obj_set_style_bg_color(btn_lang, lv_color_hex(0x1a2a40), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_lang, 10, 0);
  lv_obj_set_style_shadow_width(btn_lang, 0, 0);
  lv_obj_set_style_border_width(btn_lang, 1, 0);
  lv_obj_set_style_border_color(btn_lang, lv_color_hex(0x1a2a40), 0);
  { lv_obj_t *ico = lv_label_create(btn_lang);
    lv_label_set_text(ico, LV_SYMBOL_LIST);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -17);
    lv_obj_t *lbl = lv_label_create(btn_lang);
    lv_label_set_text(lbl, T(STR_LANG_TITLE));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 3);
    lv_obj_t *sub = lv_label_create(btn_lang);
    lv_label_set_text(sub, T(STR_BTN_LANG_SUB));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 20); }
  lv_obj_add_event_cb(btn_lang, [](lv_event_t *e){ logSD("BTN: System -> Language"); showLanguageScreen(); }, LV_EVENT_CLICKED, NULL);

  // ── Button 2: Firmware update ──
  lv_obj_t *btn_upd = lv_btn_create(scr_system);
  lv_obj_set_size(btn_upd, BTN_W, BTN_H);
  lv_obj_set_pos(btn_upd, BTN_X, BTN_Y0 + BTN_H + BTN_GAP);
  lv_obj_set_style_bg_color(btn_upd, lv_color_hex(0x0a1a2a), 0);
  lv_obj_set_style_bg_color(btn_upd, lv_color_hex(0x1a2a40), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_upd, 10, 0);
  lv_obj_set_style_shadow_width(btn_upd, 0, 0);
  lv_obj_set_style_border_width(btn_upd, 1, 0);
  lv_obj_set_style_border_color(btn_upd, lv_color_hex(0x1a2a40), 0);
  { lv_obj_t *ico = lv_label_create(btn_upd);
    lv_label_set_text(ico, LV_SYMBOL_DOWNLOAD);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -17);
    lv_obj_t *lbl = lv_label_create(btn_upd);
    lv_label_set_text(lbl, T(STR_BTN_FW_UPDATE));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 3);
    lv_obj_t *sub = lv_label_create(btn_upd);
    lv_label_set_text(sub, T(STR_BTN_FW_SUB));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 20); }
  lv_obj_add_event_cb(btn_upd, [](lv_event_t *e){ logSD("BTN: -> OTA"); show_ota_pending = true; }, LV_EVENT_CLICKED, NULL);

  lbl_fw_badge = createUpdateBadge(scr_system, btn_upd);

  // ── Button 3: Info & support ──
  lv_obj_t *btn_info = lv_btn_create(scr_system);
  lv_obj_set_size(btn_info, BTN_W, BTN_H);
  lv_obj_set_pos(btn_info, BTN_X, BTN_Y0 + 2*(BTN_H + BTN_GAP));
  lv_obj_set_style_bg_color(btn_info, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_info, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_info, 10, 0);
  lv_obj_set_style_shadow_width(btn_info, 0, 0);
  lv_obj_set_style_border_width(btn_info, 1, 0);
  lv_obj_set_style_border_color(btn_info, lv_color_hex(0x1a3050), 0);
  { lv_obj_t *ico = lv_label_create(btn_info);
    lv_label_set_text(ico, LV_SYMBOL_BELL);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -17);
    lv_obj_t *lbl = lv_label_create(btn_info);
    lv_label_set_text(lbl, T(STR_BTN_INFO));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 3);
    lv_obj_t *sub = lv_label_create(btn_info);
    lv_label_set_text(sub, T(STR_BTN_INFO_SUB));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 20); }
  lv_obj_add_event_cb(btn_info, [](lv_event_t *e){ logSD("BTN: System -> Info"); show_info_pending = true; }, LV_EVENT_CLICKED, NULL);

  // ── Button 4: Web interface ──
  lv_obj_t *btn_web = lv_btn_create(scr_system);
  lv_obj_set_size(btn_web, BTN_W, BTN_H);
  lv_obj_set_pos(btn_web, BTN_X, BTN_Y0 + 3*(BTN_H + BTN_GAP));
  lv_obj_set_style_bg_color(btn_web, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_web, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_web, 10, 0);
  lv_obj_set_style_shadow_width(btn_web, 0, 0);
  lv_obj_set_style_border_width(btn_web, 1, 0);
  lv_obj_set_style_border_color(btn_web, lv_color_hex(0x1a3050), 0);
  { lv_obj_t *ico = lv_label_create(btn_web);
    lv_label_set_text(ico, LV_SYMBOL_WIFI);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -17);
    lv_obj_t *lbl = lv_label_create(btn_web);
    lv_label_set_text(lbl, T(STR_WEB_TITLE));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 3);
    lv_obj_t *sub = lv_label_create(btn_web);
    lv_label_set_text(sub, T(STR_BTN_WEB_SUB));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 20); }
  lv_obj_add_event_cb(btn_web, [](lv_event_t *e){
    logSD("BTN: System -> Web");
    showWebScreen();
  }, LV_EVENT_CLICKED, NULL);

  // ── Button 5: Factory Reset (half width, left) + Reboot (half width, right) ──
  int reset_y = BTN_Y0 + 4*(BTN_H + BTN_GAP);
  const int HALF_W = 220;

  lv_obj_t *btn_reset = lv_btn_create(scr_system);
  lv_obj_set_size(btn_reset, HALF_W, RESET_H);
  lv_obj_set_pos(btn_reset, BTN_X, reset_y);
  lv_obj_set_style_bg_color(btn_reset, lv_color_hex(0x0a1a2a), 0);
  lv_obj_set_style_bg_color(btn_reset, lv_color_hex(0x1a2a40), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_reset, 8, 0);
  lv_obj_set_style_shadow_width(btn_reset, 0, 0);
  lv_obj_set_style_border_width(btn_reset, 2, 0);
  lv_obj_set_style_border_color(btn_reset, lv_color_hex(0x3a1010), 0);
  { lv_obj_t *lbl = lv_label_create(btn_reset);
    char buf[32]; strncpy(buf, T(STR_BTN_FACTORY_RESET), sizeof(buf)-1);
    lv_label_set_text(lbl, buf);
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xff6060), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, -7);
    lv_obj_t *sub = lv_label_create(btn_reset);
    char sub_buf[48]; strncpy(sub_buf, T(STR_BTN_FACTORY_RESET_SUB), sizeof(sub_buf)-1);
    lv_label_set_text(sub, sub_buf);
    lv_obj_set_style_text_color(sub, lv_color_hex(0x804040), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 9); }
  lv_obj_add_event_cb(btn_reset, [](lv_event_t *e) {
    // Confirmation popup
    lv_obj_t *pop = lv_obj_create(lv_scr_act());
    lv_obj_set_size(pop, 480, 320);
    lv_obj_set_pos(pop, 0, 0);
    lv_obj_set_style_bg_color(pop, lv_color_hex(0x000000), 0);
    lv_obj_set_style_bg_opa(pop, LV_OPA_80, 0);
    lv_obj_set_style_border_width(pop, 0, 0);
    lv_obj_set_style_radius(pop, 0, 0);
    lv_obj_set_style_pad_all(pop, 0, 0);
    lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *box = lv_obj_create(pop);
    lv_obj_set_size(box, 440, 240);
    lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_bg_color(box, lv_color_hex(0x1a0808), 0);
    lv_obj_set_style_border_color(box, lv_color_hex(0x602020), 0);
    lv_obj_set_style_border_width(box, 2, 0);
    lv_obj_set_style_radius(box, 12, 0);
    lv_obj_set_style_pad_all(box, 0, 0);
    lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *lbl_t = lv_label_create(box);
    char buf_t[48]; strncpy(buf_t, T(STR_FACTORY_RESET_TITLE), sizeof(buf_t)-1);
    lv_label_set_text(lbl_t, buf_t);
    lv_obj_set_style_text_color(lbl_t, lv_color_hex(0xff6060), 0);
    lv_obj_set_style_text_font(lbl_t, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_t, LV_ALIGN_TOP_MID, 0, 16);

    lv_obj_t *lbl_m = lv_label_create(box);
    char buf_m[256]; backendText(T(STR_FACTORY_RESET_MSG), buf_m, sizeof(buf_m));
    lv_label_set_text(lbl_m, buf_m);
    lv_obj_set_style_text_color(lbl_m, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(lbl_m, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(lbl_m, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(lbl_m, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(lbl_m, 400);
    lv_obj_align(lbl_m, LV_ALIGN_TOP_MID, 0, 50);

    // Cancel button (links)
    lv_obj_t *btn_c = lv_btn_create(box);
    lv_obj_set_size(btn_c, 180, 44);
    lv_obj_set_pos(btn_c, 12, 184);
    lv_obj_set_style_bg_color(btn_c, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(btn_c, lv_color_hex(0x1a2840), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_c, 8, 0);
    lv_obj_set_style_shadow_width(btn_c, 0, 0);
    lv_obj_set_style_border_width(btn_c, 1, 0);
    lv_obj_set_style_border_color(btn_c, lv_color_hex(0x1a2840), 0);
    lv_obj_add_event_cb(btn_c, [](lv_event_t *e){
      lv_obj_del(lv_obj_get_parent(lv_obj_get_parent(lv_event_get_target(e))));
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_c = lv_label_create(btn_c);
    char buf_c[32]; strncpy(buf_c, T(STR_CANCEL), sizeof(buf_c)-1);
    lv_label_set_text(lbl_c, buf_c);
    lv_obj_set_style_text_color(lbl_c, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_c, &lv_font_montserrat_ext_14, 0);
    lv_obj_align(lbl_c, LV_ALIGN_CENTER, 0, 0);

    // Confirm button (rechts, rot)
    lv_obj_t *btn_ok = lv_btn_create(box);
    lv_obj_set_size(btn_ok, 228, 44);
    lv_obj_set_pos(btn_ok, 200, 184);
    lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_ok, 8, 0);
    lv_obj_set_style_shadow_width(btn_ok, 0, 0);
    lv_obj_set_style_border_width(btn_ok, 1, 0);
    lv_obj_set_style_border_color(btn_ok, lv_color_hex(0x602020), 0);
    lv_obj_add_event_cb(btn_ok, [](lv_event_t *e){
      logSD("Factory Reset: erasing NVS flash partition");
      Serial.println("Factory Reset: erasing NVS flash partition");
      // Close SD logging before erase to avoid corruption
      if (sd_available) SD.end();
      delay(100);
      // Full NVS partition erase — more reliable than p.clear()
      nvs_flash_erase();
      nvs_flash_init();
      delay(200);
      ESP.restart();
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_ok = lv_label_create(btn_ok);
    char buf_ok[48]; strncpy(buf_ok, T(STR_FACTORY_RESET_CONFIRM), sizeof(buf_ok)-1);
    lv_label_set_text(lbl_ok, buf_ok);
    lv_obj_set_style_text_color(lbl_ok, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_ok, &lv_font_montserrat_ext_14, 0);
    lv_obj_align(lbl_ok, LV_ALIGN_CENTER, 0, 0);
  }, LV_EVENT_CLICKED, NULL);

  // ── Reboot Button (right of Factory Reset) ──
  lv_obj_t *btn_reboot = lv_btn_create(scr_system);
  lv_obj_set_size(btn_reboot, HALF_W, RESET_H);
  lv_obj_set_pos(btn_reboot, BTN_X + HALF_W + 16, reset_y);
  lv_obj_set_style_bg_color(btn_reboot, lv_color_hex(0x0a1a2a), 0);
  lv_obj_set_style_bg_color(btn_reboot, lv_color_hex(0x1a2a40), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_reboot, 8, 0);
  lv_obj_set_style_shadow_width(btn_reboot, 0, 0);
  lv_obj_set_style_border_width(btn_reboot, 1, 0);
  lv_obj_set_style_border_color(btn_reboot, lv_color_hex(0x1a2a40), 0);
  { lv_obj_t *lbl = lv_label_create(btn_reboot);
    char buf[32]; strncpy(buf, T(STR_BTN_REBOOT), sizeof(buf)-1);
    lv_label_set_text(lbl, buf);
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, -7);
    lv_obj_t *sub = lv_label_create(btn_reboot);
    char sub_buf[32]; strncpy(sub_buf, T(STR_BTN_REBOOT_SUB), sizeof(sub_buf)-1);
    lv_label_set_text(sub, sub_buf);
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 9); }
  lv_obj_add_event_cb(btn_reboot, [](lv_event_t *e) {
    logSD("BTN: System -> Reboot");
    if (sd_available) SD.end();
    delay(100);
    ESP.restart();
  }, LV_EVENT_CLICKED, NULL);

  if (sd_verbose) logSD("[verbose] buildSystemScreen: done");
}
