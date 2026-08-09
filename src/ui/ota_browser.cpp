#include "ota_browser.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <IPAddress.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/ota_web_server.h"
#include "services/wifi_manager.h"
#include "ui_common.h"


void showOtaBrowserScreen() {
  logSD("SHOW: OtaBrowserScreen");
  logSD("UI: Screen -> OTA Browser");
  hideAllOverlays();
  stopOtaServer();
  lbl_ota_status = nullptr;
  if (scr_ota_browser) {
    lv_obj_del(scr_ota_browser);
    scr_ota_browser = nullptr;
  }
  buildOtaBrowserScreen();
  lv_obj_clear_flag(scr_ota_browser, LV_OBJ_FLAG_HIDDEN);
  if (wifi_ok) startOtaServer();
}

void buildOtaBrowserScreen() {
  logSD("BUILD: OtaBrowserScreen");
  releaseScreen(&scr_ota_browser);
  scr_ota_browser = buildOverlayScreen();
  buildSubHeader(scr_ota_browser, T(STR_OTA_BROWSER_TITLE),
    [](lv_event_t *e){
      logSD("BTN: OtaBrowser -> Back");
      stopOtaServer();
      show_ota_pending = true;
    });

  if (!wifi_ok) {
    lv_obj_t *lbl_err = lv_label_create(scr_ota_browser);
    lv_label_set_text(lbl_err, T(STR_OTA_NO_WIFI));
    lv_obj_set_style_text_color(lbl_err, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_err, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl_err, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_err, LV_ALIGN_CENTER, 0, 0);
    return;
  }

  char ip_buf[64];
  IPAddress ip = wifiManagerLocalIP();
  if (ip == IPAddress(0,0,0,0) && wifi_ok) {
    unsigned long t = millis();
    while (wifiManagerLocalIP() == IPAddress(0,0,0,0) && millis() - t < 3000) {
      delay(100);
      lv_timer_handler();
    }
    ip = wifiManagerLocalIP();
  }
  snprintf(ip_buf, sizeof(ip_buf), "http://%s/", ip.toString().c_str());

  lv_obj_t *lbl_hint = lv_label_create(scr_ota_browser);
  lv_label_set_text(lbl_hint, T(STR_OTA_OPEN_BROWSER));
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_14, 0);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 58);

  lv_obj_t *lbl_ip = lv_label_create(scr_ota_browser);
  lv_label_set_text(lbl_ip, ip_buf);
  lv_obj_set_style_text_color(lbl_ip, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_ip, &lv_font_montserrat_ext_20, 0);
  lv_obj_align(lbl_ip, LV_ALIGN_TOP_MID, 0, 80);

  lv_obj_t *lbl_hint2 = lv_label_create(scr_ota_browser);
  lv_label_set_text(lbl_hint2, T(STR_OTA_FILE_HINT));
  lv_obj_set_style_text_color(lbl_hint2, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_hint2, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_hint2, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_hint2, LV_ALIGN_TOP_MID, 0, 112);
  lv_label_set_long_mode(lbl_hint2, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint2, 440);

  lbl_ota_status = lv_label_create(scr_ota_browser);
  lv_label_set_text(lbl_ota_status, T(STR_OTA_WAITING));
  lv_obj_set_style_text_color(lbl_ota_status, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_ota_status, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_ota_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_ota_status, LV_ALIGN_CENTER, 0, 40);

  lv_obj_t *btn_stop = lv_btn_create(scr_ota_browser);
  lv_obj_set_size(btn_stop, 200, 48);
  lv_obj_align(btn_stop, LV_ALIGN_BOTTOM_MID, 0, -20);
  lv_obj_set_style_bg_color(btn_stop, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_stop, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_stop, 8, 0);
  lv_obj_set_style_shadow_width(btn_stop, 0, 0);
  lv_obj_set_style_border_width(btn_stop, 0, 0);
  lv_obj_add_event_cb(btn_stop, [](lv_event_t *e){
    logSD("BTN: OtaBrowser -> Stop server");
    stopOtaServer();
    show_ota_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_stop = lv_label_create(btn_stop);
  lv_label_set_text(lbl_stop, T(STR_BTN_STOP_SERVER));
  lv_obj_set_style_text_color(lbl_stop, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_stop, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_stop);
}
