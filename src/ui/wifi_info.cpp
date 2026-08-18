#include "wifi_info.h"
#include "navigation.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>

#include "connection_screen.h"
#include "lang.h"
#include "services/wifi_manager.h"
#include "ui_common.h"

// One fact per row, label and value in two columns across the full width, so
// nothing has to wrap and every row stays on its own baseline.
//
// The backend name and URL used to be shown here as a wrapped block. They are
// gone: the Connection screen has a dedicated filament-manager tile sitting
// directly beside the one that opens this screen, so repeating the backend
// address here was duplication.
static const int ROW_Y0   = 62;
static const int ROW_STEP = 42;
static const int LABEL_X  = 28;
static const int VALUE_X  = 172;
static const int VALUE_W  = 288;   // 172 + 288 = 460, leaving a 20px margin

// Same reasoning as the Connection tile: the screen is populated on entry, so
// without a timer it would keep showing whatever the link looked like at that
// moment for as long as it stayed open.
static lv_timer_t *wifi_info_timer = nullptr;

static lv_obj_t *val_ssid  = nullptr;
static lv_obj_t *val_state = nullptr;
static lv_obj_t *val_ip    = nullptr;
static lv_obj_t *val_gw    = nullptr;
static lv_obj_t *val_dns   = nullptr;
static lv_obj_t *val_rssi  = nullptr;

static lv_obj_t* addRow(int index, const char *label) {
  const int y = ROW_Y0 + index * ROW_STEP;

  lv_obj_t *l = lv_label_create(scr_wifi);
  lv_label_set_text(l, label);
  lv_obj_set_style_text_color(l, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(l, LABEL_X, y + 5);

  lv_obj_t *v = lv_label_create(scr_wifi);
  lv_label_set_text(v, "-");
  lv_obj_set_style_text_color(v, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(v, &lv_font_montserrat_ext_20, 0);
  // Ellipsis rather than wrap: a long SSID must not push the rows below it
  // off their baselines.
  lv_label_set_long_mode(v, LV_LABEL_LONG_DOT);
  lv_obj_set_width(v, VALUE_W);
  lv_obj_set_pos(v, VALUE_X, y);
  return v;
}

static void refreshWifiInfo(lv_timer_t *t) {
  if (!val_ssid || !lv_obj_is_valid(val_ssid)) return;
  updateWifiInfo();
}

void buildWifiScreen() {
  if (wifi_info_timer) { lv_timer_del(wifi_info_timer); wifi_info_timer = nullptr; }
  val_ssid = nullptr;
  releaseScreen(&scr_wifi);
  scr_wifi = buildOverlayScreen();
  buildSubHeader(scr_wifi, T(STR_BTN_WIFI_STATUS), [](lv_event_t *e) {
    if (!scr_connection) buildConnectionScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
  });

  val_ssid  = addRow(0, "SSID");
  val_state = addRow(1, "Status");
  val_ip    = addRow(2, "IP");
  val_gw    = addRow(3, "Gateway");
  val_dns   = addRow(4, "DNS");
  val_rssi  = addRow(5, "Signal");

  wifi_info_timer = lv_timer_create(refreshWifiInfo, 2000, nullptr);
}

// The screen and its updater existed but nothing ever called them, so the
// device had no way to show its own IP. Entry point for the Connection screen.
void showWifiStatusScreen() {
  if (!scr_wifi) buildWifiScreen();
  hideAllOverlays();
  updateWifiInfo();
  lv_obj_clear_flag(scr_wifi, LV_OBJ_FLAG_HIDDEN);
}

void updateWifiInfo() {
  if (!val_ssid) return;

  lv_label_set_text(val_ssid, cfg_wifi_ssid[0] ? cfg_wifi_ssid : "-");

  lv_label_set_text(val_state, wifi_ok ? T(STR_WIFI_STATUS_CONNECTED)
                                       : T(STR_WIFI_STATUS_DISCONNECTED));
  lv_obj_set_style_text_color(val_state,
    lv_color_hex(wifi_ok ? 0x40c080 : 0xff8080), 0);

  if (!wifi_ok) {
    lv_label_set_text(val_ip,   "-");
    lv_label_set_text(val_gw,   "-");
    lv_label_set_text(val_dns,  "-");
    lv_label_set_text(val_rssi, "-");
    return;
  }

  lv_label_set_text(val_ip,  wifiManagerLocalIP().toString().c_str());
  lv_label_set_text(val_gw,  wifiManagerGatewayIP().toString().c_str());
  lv_label_set_text(val_dns, wifiManagerDNSIP().toString().c_str());

  const int rssi = wifiManagerRSSI();
  const char *qual;
  if      (rssi >= -50) qual = T(STR_WIFI_QUAL_EXCELLENT);
  else if (rssi >= -65) qual = T(STR_WIFI_QUAL_GOOD);
  else if (rssi >= -75) qual = T(STR_WIFI_QUAL_MEDIUM);
  else                  qual = T(STR_WIFI_QUAL_WEAK);

  char buf[48];
  snprintf(buf, sizeof(buf), "%d dBm  (%s)", rssi, qual);
  lv_label_set_text(val_rssi, buf);
}
