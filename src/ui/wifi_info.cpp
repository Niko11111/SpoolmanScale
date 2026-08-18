#include "wifi_info.h"
#include "navigation.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>

#include "connection_screen.h"
#include "hardware/sd_logger.h"
#include "header_status.h"
#include "lang.h"
#include "services/backend.h"
#include "services/prefs_store.h"
#include "services/user_options.h"
#include "services/wifi_manager.h"
#include "ui_common.h"
#include "theme.h"

// One fact per row, label and value in two columns across the full width, so
// nothing has to wrap and every row stays on its own baseline.
//
// The backend name and URL used to be shown here as a wrapped block. They are
// gone: the Connection screen has a dedicated filament-manager tile sitting
// directly beside the one that opens this screen, so repeating the backend
// address here was duplication.
// Row labels stay as plain literals: SSID, Status, IP, Gateway, DNS, MAC and
// Signal read identically in German and English, so putting them through the
// string table would add fourteen entries without translating anything.
static const int ROW_Y0   = 58;   // sub-header back button ends at ~46
static const int ROW_STEP = 30;
static const int ROW_COUNT = 7;

// Bottom of the last row is ~258, leaving room for the selector below.
static const int SELECTOR_Y = 266;

// Same reasoning as the Connection tile: the screen is populated on entry, so
// without a timer it would keep showing whatever the link looked like at that
// moment for as long as it stayed open.
static lv_timer_t *wifi_info_timer = nullptr;

static lv_obj_t *val_ssid  = nullptr;
static lv_obj_t *val_state = nullptr;
static lv_obj_t *val_ip    = nullptr;
static lv_obj_t *val_gw    = nullptr;
static lv_obj_t *val_dns   = nullptr;
static lv_obj_t *val_mac   = nullptr;
static lv_obj_t *val_rssi  = nullptr;

static lv_obj_t *lbl_ipbar_mode = nullptr;   // ON/OFF style text of the selector
static lv_obj_t *btn_ipbar      = nullptr;   // border colour follows the mode

static lv_obj_t* addRow(int index, const char *label) {
  return addInfoRow(scr_wifi, ROW_Y0 + index * ROW_STEP, label);
}

// Third state labels itself with the live backend name, so the button says
// "Spoolman" or "FilaMan" rather than a vague "Backend" and the user can see
// what they are about to get.
static void ipBarModeText(char *buf, size_t len) {
  if (g_ip_bar_mode == IP_BAR_DEVICE)       strncpy(buf, T(STR_IP_BAR_DEVICE), len - 1);
  else if (g_ip_bar_mode == IP_BAR_BACKEND) strncpy(buf, backendName(), len - 1);
  else                                      strncpy(buf, T(STR_OFF), len - 1);
  buf[len - 1] = '\0';
}

static void refreshIpBarButton() {
  if (!btn_ipbar || !lv_obj_is_valid(btn_ipbar)) return;
  const bool on = (g_ip_bar_mode != IP_BAR_OFF);
  lv_obj_set_style_border_color(btn_ipbar,
    lv_color_hex(on ? g_theme[TH_ACCENT] : g_theme[TH_BORDER]), 0);
  if (lbl_ipbar_mode) {
    char buf[24];
    ipBarModeText(buf, sizeof(buf));
    lv_label_set_text(lbl_ipbar_mode, buf);
    lv_obj_set_style_text_color(lbl_ipbar_mode,
      lv_color_hex(on ? g_theme[TH_ACCENT] : g_theme[TH_TEXT_MUTED]), 0);
  }
}

static void refreshWifiInfo(lv_timer_t *t) {
  if (!val_ssid || !lv_obj_is_valid(val_ssid)) return;
  updateWifiInfo();
}

// Styled like the list buttons in scale_menu.cpp: title on the left, current
// state on the right, green border while active. Tapping cycles off -> device
// -> backend -> off, the same way the drying mode button cycles.
static void buildIpBarSelector() {
  btn_ipbar = lv_btn_create(scr_wifi);
  lv_obj_set_size(btn_ipbar, 456, 44);
  lv_obj_set_pos(btn_ipbar, 12, SELECTOR_Y);
  lv_obj_set_style_bg_color(btn_ipbar, tc(TH_TILE_BG), 0);
  lv_obj_set_style_bg_color(btn_ipbar, tc(TH_BORDER), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ipbar, 10, 0);
  lv_obj_set_style_shadow_width(btn_ipbar, 0, 0);
  lv_obj_set_style_border_width(btn_ipbar, 1, 0);
  lv_obj_set_style_pad_all(btn_ipbar, 0, 0);

  lv_obj_t *title = lv_label_create(btn_ipbar);
  { char buf[40];
    strncpy(buf, T(STR_BTN_IP_STATUSBAR), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    lv_label_set_text(title, buf); }
  lv_obj_set_style_text_color(title, tc(TH_TEXT_BRIGHT), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(title, LV_ALIGN_LEFT_MID, 12, 0);

  lbl_ipbar_mode = lv_label_create(btn_ipbar);
  lv_obj_set_style_text_font(lbl_ipbar_mode, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_ipbar_mode, LV_ALIGN_RIGHT_MID, -14, 0);

  lv_obj_add_event_cb(btn_ipbar, [](lv_event_t *e) {
    g_ip_bar_mode = (g_ip_bar_mode + 1) % IP_BAR_COUNT;
    prefsPutUChar("ip_bar_mode", g_ip_bar_mode);
    logSDf("BTN: WiFi Status -> IP bar mode %d", (int)g_ip_bar_mode);
    refreshIpBarButton();
    // The status bar belongs to the main screen, which is still alive behind
    // this overlay, so the change shows the moment the user goes back.
    updateHeaderStatus();
  }, LV_EVENT_CLICKED, NULL);

  refreshIpBarButton();
}

void buildWifiScreen() {
  if (wifi_info_timer) { lv_timer_del(wifi_info_timer); wifi_info_timer = nullptr; }
  val_ssid = nullptr;
  btn_ipbar = nullptr;
  lbl_ipbar_mode = nullptr;
  releaseScreen(&scr_wifi);
  scr_wifi = buildOverlayScreen(&scr_wifi);
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
  // The one field a router needs to hand out a fixed address, which is the
  // usual answer to "the scale's IP keeps moving".
  val_mac   = addRow(5, "MAC");
  val_rssi  = addRow(6, "Signal");

  buildIpBarSelector();

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

  // This is the configured SSID, not a connected one. While the link is down
  // it is muted to the label colour so the row cannot be read as "connected to
  // this" - the value still matters, it says which network is set up.
  lv_label_set_text(val_ssid, cfg_wifi_ssid[0] ? cfg_wifi_ssid : "-");
  lv_obj_set_style_text_color(val_ssid,
    lv_color_hex(wifi_ok ? g_theme[TH_TEXT_BRIGHT] : g_theme[TH_TEXT_MUTED]), 0);

  lv_label_set_text(val_state, wifi_ok ? T(STR_WIFI_STATUS_CONNECTED)
                                       : T(STR_WIFI_STATUS_DISCONNECTED));
  lv_obj_set_style_text_color(val_state,
    lv_color_hex(wifi_ok ? g_theme[TH_SUCCESS_TEXT] : g_theme[TH_DANGER_TEXT]), 0);

  // The MAC belongs to the radio, not to the link, so it stays readable while
  // disconnected - that is exactly when someone is setting up a reservation.
  lv_label_set_text(val_mac, wifiManagerMacAddress().c_str());

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
