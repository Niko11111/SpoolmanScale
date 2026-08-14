#include "wifi_info.h"
#include "navigation.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>

#include "connection_screen.h"
#include "lang.h"
#include "services/wifi_manager.h"
#include "ui_common.h"
#include "services/backend.h"



void buildWifiScreen() {
  scr_wifi = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_wifi, 480, 320);
  lv_obj_set_pos(scr_wifi, 0, 0);
  lv_obj_add_flag(scr_wifi, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_wifi, 0, 0);
  lv_obj_set_style_border_width(scr_wifi, 0, 0);
  lv_obj_set_style_pad_all(scr_wifi, 0, 0);
  lv_obj_clear_flag(scr_wifi, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_wifi, lv_color_hex(0x0a1020), 0);

  lv_obj_t *title_wifi = lv_label_create(scr_wifi);
  lv_label_set_text(title_wifi, "WiFi Status");
  lv_obj_set_style_text_color(title_wifi, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(title_wifi, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(title_wifi, LV_ALIGN_TOP_MID, 0, 14);

  lbl_wifi_info = lv_label_create(scr_wifi);
  lv_label_set_text(lbl_wifi_info, T(STR_WAIT));
  lv_obj_set_style_text_color(lbl_wifi_info, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_wifi_info, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_wifi_info, LV_ALIGN_CENTER, 0, 10);
  lv_label_set_long_mode(lbl_wifi_info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_wifi_info, 380);
  lv_obj_set_style_text_align(lbl_wifi_info, LV_TEXT_ALIGN_LEFT, 0);

  addBackButton(scr_wifi, [](lv_event_t *e) {
    if (!scr_connection) buildConnectionScreen();
    if (!scr_connection) buildConnectionScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
  });
  addCloseButton(scr_wifi);
}

void updateWifiInfo() {
  if (!lbl_wifi_info) return;

  char buf[200];
  int rssi = wifiManagerRSSI();
  const char* qual;
  if      (rssi >= -50) qual = T(STR_WIFI_QUAL_EXCELLENT);
  else if (rssi >= -65) qual = T(STR_WIFI_QUAL_GOOD);
  else if (rssi >= -75) qual = T(STR_WIFI_QUAL_MEDIUM);
  else                  qual = T(STR_WIFI_QUAL_WEAK);

  snprintf(buf, sizeof(buf),
    "SSID:    %s\n"
    "Status:  %s\n"
    "IP:      %s\n"
    "RSSI:    %d dBm  (%s)\n"
    "%s:\n%s",   // backendName() is passed as the first argument
    cfg_wifi_ssid,
    wifi_ok ? T(STR_WIFI_STATUS_CONNECTED) : T(STR_WIFI_STATUS_DISCONNECTED),
    wifi_ok ? wifiManagerLocalIP().toString().c_str() : "-",
    rssi, qual,
    backendName(), backendBaseUrl()
  );
  lv_label_set_text(lbl_wifi_info, buf);
}
