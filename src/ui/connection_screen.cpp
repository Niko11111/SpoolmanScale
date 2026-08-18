#include "connection_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "lang.h"
#include "ui_common.h"
#include "wifi_info.h"
#include "services/wifi_manager.h"


void showWifiSetupScreen();

// The address is read when the tile is built, so a Connection screen opened
// while WiFi is still negotiating would otherwise show 0.0.0.0 for as long as
// it stayed open. A timer re-reads it so the tile tracks the address appearing,
// changing or going away.
static lv_obj_t   *lbl_wifi_ip   = nullptr;
static lv_timer_t *wifi_ip_timer = nullptr;

static void wifiIpText(char *buf, size_t n) {
  if (wifi_ok && wifiManagerIsConnected()) {
    IPAddress ip = wifiManagerLocalIP();
    if (ip != IPAddress(0, 0, 0, 0)) {
      snprintf(buf, n, "%s", ip.toString().c_str());
      return;
    }
  }
  snprintf(buf, n, "%s", T(STR_BTN_WIFI_STATUS_SUB));
}

static void refreshWifiIp(lv_timer_t *t) {
  // The screen can be torn down between ticks; lv_obj_is_valid keeps this from
  // writing through a dangling pointer.
  if (!lbl_wifi_ip || !lv_obj_is_valid(lbl_wifi_ip)) return;
  char buf[24];
  wifiIpText(buf, sizeof(buf));
  if (strcmp(lv_label_get_text(lbl_wifi_ip), buf) != 0) {
    lv_label_set_text(lbl_wifi_ip, buf);
  }
}

void buildConnectionScreen() {
  logSD("BUILD: ConnectionScreen");
  // Drop the previous screen's timer before the new one is built, so the two
  // never race over lbl_wifi_ip when releaseScreen() deletes asynchronously.
  if (wifi_ip_timer) { lv_timer_del(wifi_ip_timer); wifi_ip_timer = nullptr; }
  lbl_wifi_ip = nullptr;
  if (sd_verbose) logSD("[verbose] buildConnectionScreen: start");
  releaseScreen(&scr_connection);
  scr_connection = buildOverlayScreen();
  buildSubHeader(scr_connection, T(STR_TILE_CONNECTION),
    [](lv_event_t *e){ logSD("BTN: Back -> Settings"); showSettingsScreen(); });

  // Back to the 80px tiles this screen always had. They only ever got squeezed
  // to make room for a fourth tile; with extra fields moved to the filament
  // manager screen there are three again in both backend modes, and three at
  // 80px end at 310 of 320.
  const int BTN_W = 456, BTN_H = 80, BTN_X = 12;
  const int BTN_Y[] = { 54, 142, 230 };

  lv_obj_t *btn_wifi = lv_btn_create(scr_connection);
  lv_obj_set_size(btn_wifi, BTN_W, BTN_H);
  lv_obj_set_pos(btn_wifi, BTN_X, BTN_Y[0]);
  lv_obj_set_style_bg_color(btn_wifi, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_wifi, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_wifi, 10, 0);
  lv_obj_set_style_shadow_width(btn_wifi, 0, 0);
  lv_obj_set_style_border_width(btn_wifi, 1, 0);
  lv_obj_set_style_border_color(btn_wifi, lv_color_hex(0x1a3050), 0);
  { lv_obj_t *ico = lv_label_create(btn_wifi);
    lv_label_set_text(ico, LV_SYMBOL_WIFI);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_wifi);
    lv_label_set_text(lbl, T(STR_BTN_WIFI_SETTINGS));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_wifi);
    lv_label_set_text(sub, cfg_wifi_ssid[0] ? cfg_wifi_ssid : T(STR_BTN_WIFI_NONE));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_wifi, [](lv_event_t *e){ logSD("BTN: Conn -> WifiSetup"); showWifiSetupScreen(); }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_ws = lv_btn_create(scr_connection);
  lv_obj_set_size(btn_ws, BTN_W, BTN_H);
  lv_obj_set_pos(btn_ws, BTN_X, BTN_Y[1]);
  lv_obj_set_style_bg_color(btn_ws, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_ws, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ws, 10, 0);
  lv_obj_set_style_shadow_width(btn_ws, 0, 0);
  lv_obj_set_style_border_width(btn_ws, 1, 0);
  lv_obj_set_style_border_color(btn_ws, lv_color_hex(0x1a3050), 0);
  { lv_obj_t *ico = lv_label_create(btn_ws);
    lv_label_set_text(ico, LV_SYMBOL_GPS);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_ws);
    lv_label_set_text(lbl, T(STR_BTN_WIFI_STATUS));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_ws);
    lbl_wifi_ip = sub;
    { char ipbuf[24]; wifiIpText(ipbuf, sizeof(ipbuf)); lv_label_set_text(sub, ipbuf); }
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_ws, [](lv_event_t *e){
    logSD("BTN: Conn -> WiFi Status");
    showWifiStatusScreen();
  }, LV_EVENT_CLICKED, NULL);

  // Created here rather than at the end of the function: the FilaMan path
  // returns early, and the tile needs refreshing on both backends.
  wifi_ip_timer = lv_timer_create(refreshWifiIp, 2000, nullptr);

  lv_obj_t *btn_sp = lv_btn_create(scr_connection);
  lv_obj_set_size(btn_sp, BTN_W, BTN_H);
  lv_obj_set_pos(btn_sp, BTN_X, BTN_Y[2]);
  lv_obj_set_style_bg_color(btn_sp, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_sp, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_sp, 10, 0);
  lv_obj_set_style_shadow_width(btn_sp, 0, 0);
  lv_obj_set_style_border_width(btn_sp, 1, 0);
  lv_obj_set_style_border_color(btn_sp, lv_color_hex(0x1a3050), 0);
  { lv_obj_t *ico = lv_label_create(btn_sp);
    lv_label_set_text(ico, LV_SYMBOL_SETTINGS);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    char buf_backend[32];
    strncpy(buf_backend, T(STR_BACKEND_TITLE), sizeof(buf_backend)-1);
    buf_backend[sizeof(buf_backend)-1] = '\0';
    lv_obj_t *lbl = lv_label_create(btn_sp);
    lv_label_set_text(lbl, buf_backend);
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    // Shows which backend is active and where it lives, so the user does
    // not have to open the screen to find out.
    char buf_sub[80];
    const char *host = backendHost();
    snprintf(buf_sub, sizeof(buf_sub), "%s  %s",
      backendName(),
      (host && host[0]) ? host : T(STR_BTN_WIFI_NONE));
    lv_obj_t *sub = lv_label_create(btn_sp);
    lv_label_set_text(sub, buf_sub);
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_sp, [](lv_event_t *e){
    logSD("BTN: Conn -> Backend");
    show_backend_pending = true;
  }, LV_EVENT_CLICKED, NULL);

  if (sd_verbose) logSD("[verbose] buildConnectionScreen: done");
}
