#include "wifi_setup_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "connection_screen.h"
#include "header_status.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/app_settings.h"
#include "services/time_service.h"
#include "services/wifi_manager.h"
#include "setup_welcome_screen.h"
#include "ui_common.h"
#include "services/backend.h"



// Rows rendered in the scan list, and therefore the number of full SSIDs kept
// for the click handler. The scan itself may return more; anything past this is
// not shown and not selectable.
#define WIFI_SCAN_ROWS_MAX  20
// Entries the RSSI sort covers. Networks beyond this stay in scan order, which
// only matters in places dense enough to see more than this many APs at once.
#define WIFI_SCAN_SORT_MAX  64

// Held by name rather than looked up with lv_obj_get_child(screen, -1/-2).
// The index form silently pointed at the wrong widget as soon as anything new
// was added after the buttons, which is exactly what the summary block below
// does.
static lv_obj_t *btn_conn_retry = nullptr;
static lv_obj_t *btn_conn_next  = nullptr;
static lv_obj_t *lbl_conn_status = nullptr;

// Summary rows, filled once the link is up. Built hidden so the failure path
// looks exactly as it did before.
static lv_obj_t *conn_val_ssid = nullptr;
static lv_obj_t *conn_val_ip   = nullptr;
static lv_obj_t *conn_val_gw   = nullptr;
static lv_obj_t *conn_val_rssi = nullptr;
static lv_obj_t *conn_lbl_ssid = nullptr;
static lv_obj_t *conn_lbl_ip   = nullptr;
static lv_obj_t *conn_lbl_gw   = nullptr;
static lv_obj_t *conn_lbl_rssi = nullptr;

static char  wifi_setup_ssid[33]  = "";
static lv_obj_t *lbl_wifi_setup_status = nullptr;
static lv_obj_t *lbl_wifi_scan_list = nullptr;
static lv_obj_t *ta_wifi_pass = nullptr;
static lv_obj_t *kb_wifi_pass = nullptr;

// ============================================================
//  WIFI SETUP: STEP 1 — Network scan + selection
// ============================================================
void showWifiSetupScreen() {
  logSD("SHOW: WifiSetupScreen");
  logSD("UI: Screen -> WifiSetup");
  hideAllOverlays();
  if (scr_wifi_setup) { lv_obj_del(scr_wifi_setup); scr_wifi_setup = nullptr; }
  // Null global pointers — otherwise they point to deleted objects
  lbl_wifi_scan_list    = nullptr;
  lbl_wifi_setup_status = nullptr;
  buildWifiSetupScreen();
  lv_obj_clear_flag(scr_wifi_setup, LV_OBJ_FLAG_HIDDEN);
}

void buildWifiSetupScreen() {
  logSD("BUILD: WifiSetupScreen");
  releaseScreen(&scr_wifi_setup);
  scr_wifi_setup = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_wifi_setup, 480, 320);
  lv_obj_set_pos(scr_wifi_setup, 0, 0);
  lv_obj_add_flag(scr_wifi_setup, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_wifi_setup, 0, 0);
  lv_obj_set_style_border_width(scr_wifi_setup, 0, 0);
  lv_obj_set_style_pad_all(scr_wifi_setup, 0, 0);
  lv_obj_clear_flag(scr_wifi_setup, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_wifi_setup, lv_color_hex(0x0a1020), 0);

  // Header
  lv_obj_t *title = lv_label_create(scr_wifi_setup);
  lv_label_set_text(title, T(STR_WIFI_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 14);

  // Back button (←)
  addBackButton(scr_wifi_setup, [](lv_event_t *e) {
    if (strlen(cfg_wifi_ssid) == 0) {
      showWelcomeScreen();
    } else {
      hideAllOverlays();
      buildConnectionScreen();
      lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
    }
  });

  // X button (✕)
  addCloseButton(scr_wifi_setup);

  // Refresh button (next to title, center-right)
  lv_obj_t *btn_scan = lv_btn_create(scr_wifi_setup);
  lv_obj_set_size(btn_scan, 44, 36);
  lv_obj_align(btn_scan, LV_ALIGN_TOP_MID, 100, 4);
  lv_obj_set_style_bg_color(btn_scan, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_scan, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_scan, 6, 0);
  lv_obj_set_style_shadow_width(btn_scan, 0, 0);
  lv_obj_set_style_border_width(btn_scan, 0, 0);
  lv_obj_t *lbl_scan_btn = lv_label_create(btn_scan);
  lv_label_set_text(lbl_scan_btn, LV_SYMBOL_REFRESH);
  lv_obj_set_style_text_color(lbl_scan_btn, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_scan_btn, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_scan_btn);

  // Scrollable network list (y=50 → y=56 due to header)
  lv_obj_t *list = lv_obj_create(scr_wifi_setup);
  lv_obj_set_size(list, 460, 218);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  lv_obj_clear_flag(list, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_flag(list, LV_OBJ_FLAG_SCROLLABLE);
  lbl_wifi_scan_list = list;

  // Status label (initially "scanning...")
  lbl_wifi_setup_status = lv_label_create(scr_wifi_setup);
  lv_label_set_text(lbl_wifi_setup_status, T(STR_WIFI_SCAN));
  lv_obj_set_style_text_color(lbl_wifi_setup_status, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_wifi_setup_status, &lv_font_montserrat_ext_14, 0);
  lv_obj_align(lbl_wifi_setup_status, LV_ALIGN_BOTTOM_MID, 0, -8);

  // Scan button callback (after building list)
  lv_obj_add_event_cb(btn_scan, [](lv_event_t *e) {
    lv_label_set_text(lbl_wifi_setup_status, T(STR_WIFI_SCAN));
    doWifiScan();
  }, LV_EVENT_CLICKED, NULL);

  // Immediate scan on open
  doWifiScan();
}

// Perform scan and populate list
void doWifiScan() {
  // Liste leeren
  lv_obj_clean(lbl_wifi_scan_list);
  lv_timer_handler();

  // Disconnect required after failed WiFi.begin() —
  // otherwise scanNetworks() returns 0
  wifiManagerPrepareScan();
  int n = wifiManagerScanNetworks();

  // Negative means WIFI_SCAN_FAILED (-2) or WIFI_SCAN_RUNNING (-1). Checking
  // only for 0 let those fall through into "-2 networks found" above an empty
  // list. Both branches release the scan results, which the empty one forgot.
  if (n <= 0) {
    if (n < 0) logSDf("WiFi scan failed (rc=%d)", n);
    lv_label_set_text(lbl_wifi_setup_status, T(STR_WIFI_NO_NET));
    wifiManagerClearScan();
    return;
  }

  char status_buf[48];
  snprintf(status_buf, sizeof(status_buf), T(STR_WIFI_NETWORKS_FOUND), n);
  lv_label_set_text(lbl_wifi_setup_status, status_buf);

  // Sort strongest first. The body of this loop used to be empty - only
  // comments - so the list came out in scan order. Sorting an index array keeps
  // the scan results themselves untouched, so the accessors below still work.
  int sort_n = n < WIFI_SCAN_SORT_MAX ? n : WIFI_SCAN_SORT_MAX;
  static int idx[WIFI_SCAN_SORT_MAX];
  for (int i = 0; i < sort_n; i++) idx[i] = i;
  for (int i = 0; i < sort_n - 1; i++) {
    for (int j = 0; j < sort_n - i - 1; j++) {
      if (wifiManagerScannedRSSI(idx[j]) < wifiManagerScannedRSSI(idx[j + 1])) {
        int tmp = idx[j]; idx[j] = idx[j + 1]; idx[j + 1] = tmp;
      }
    }
  }

  // Full SSID per rendered row. The label is LV_LABEL_LONG_DOT at 300 px, so
  // reading the SSID back out of it returned "LongNetworkNam..." and the
  // connection failed for no visible reason. The click handler reads this instead.
  static char row_ssid[WIFI_SCAN_ROWS_MAX][33];

  int row_count = 0;
  for (int disp = 0; disp < sort_n && row_count < WIFI_SCAN_ROWS_MAX; disp++) {
    int i = idx[disp];
    int rssi = wifiManagerScannedRSSI(i);
    String ssid = wifiManagerScannedSSID(i);
    if (ssid.length() == 0) continue;

    int slot = row_count++;
    strncpy(row_ssid[slot], ssid.c_str(), sizeof(row_ssid[slot])-1);
    row_ssid[slot][sizeof(row_ssid[slot])-1] = '\0';

    // Signal bar (3 levels)
    const char* signal_icon;
    if      (rssi >= -65) signal_icon = LV_SYMBOL_WIFI "   ";
    else if (rssi >= -80) signal_icon = LV_SYMBOL_WIFI "   ";
    else                  signal_icon = LV_SYMBOL_WIFI "   ";

    // Signal color
    uint32_t sig_color;
    if      (rssi >= -65) sig_color = 0x28d49a;  // green
    else if (rssi >= -80) sig_color = 0xf0b838;  // yellow
    else                  sig_color = 0xff8000;   // orange

    // Row button
    lv_obj_t *row = lv_btn_create(lbl_wifi_scan_list);
    lv_obj_set_size(row, 452, 46);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_pad_all(row, 0, 0);
    lv_obj_set_user_data(row, row_ssid[slot]);

    // SSID Label
    lv_obj_t *lbl_ssid = lv_label_create(row);
    lv_label_set_text(lbl_ssid, ssid.c_str());
    lv_obj_set_style_text_color(lbl_ssid, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl_ssid, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_ssid, LV_ALIGN_LEFT_MID, 12, 0);
    lv_label_set_long_mode(lbl_ssid, LV_LABEL_LONG_DOT);
    lv_obj_set_width(lbl_ssid, 300);

    // RSSI Label
    char rssi_buf[16];
    snprintf(rssi_buf, sizeof(rssi_buf), "%d dBm", rssi);
    lv_obj_t *lbl_rssi = lv_label_create(row);
    lv_label_set_text(lbl_rssi, rssi_buf);
    lv_obj_set_style_text_color(lbl_rssi, lv_color_hex(sig_color), 0);
    lv_obj_set_style_text_font(lbl_rssi, &lv_font_montserrat_ext_12, 0);
    lv_obj_align(lbl_rssi, LV_ALIGN_RIGHT_MID, -8, 0);

    // Click: store SSID → password screen
    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      lv_obj_t *btn = (lv_obj_t*)lv_event_get_target(e);
      const char* ssid_str = (const char*)lv_obj_get_user_data(btn);
      if (!ssid_str) return;
      strncpy(wifi_setup_ssid, ssid_str, sizeof(wifi_setup_ssid)-1);
      wifi_setup_ssid[sizeof(wifi_setup_ssid)-1] = '\0';
      showWifiPassScreen();
    }, LV_EVENT_CLICKED, NULL);
  }

  wifiManagerClearScan();
}

// ============================================================
//  WIFI SETUP: STEP 2 — Password entry
// ============================================================
void showWifiPassScreen() {
  logSD("SHOW: WifiPassScreen");
  logSD("UI: Screen -> WifiPass");
  hideAllOverlays();
  if (scr_wifi_pass) { lv_obj_del(scr_wifi_pass); scr_wifi_pass = nullptr; }
  ta_wifi_pass = nullptr;
  kb_wifi_pass = nullptr;
  buildWifiPassScreen();
  lv_obj_clear_flag(scr_wifi_pass, LV_OBJ_FLAG_HIDDEN);
}

void buildWifiPassScreen() {
  logSD("BUILD: WifiPassScreen");
  releaseScreen(&scr_wifi_pass);
  scr_wifi_pass = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_wifi_pass, 480, 320);
  lv_obj_set_pos(scr_wifi_pass, 0, 0);
  lv_obj_add_flag(scr_wifi_pass, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_wifi_pass, 0, 0);
  lv_obj_set_style_border_width(scr_wifi_pass, 0, 0);
  lv_obj_set_style_pad_all(scr_wifi_pass, 0, 0);
  lv_obj_clear_flag(scr_wifi_pass, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_wifi_pass, lv_color_hex(0x0a1020), 0);

  // Back button
  addBackButton(scr_wifi_pass, [](lv_event_t *e) { showWifiSetupScreen(); });
  addCloseButton(scr_wifi_pass);

  // Title
  lv_obj_t *title = lv_label_create(scr_wifi_pass);
  lv_label_set_text(title, T(STR_WIFI_PASS_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 14);

  // Show selected SSID
  char ssid_hint[64];
  snprintf(ssid_hint, sizeof(ssid_hint), T(STR_WIFI_PASS_HINT), wifi_setup_ssid);
  lv_obj_t *lbl_ssid_show = lv_label_create(scr_wifi_pass);
  lv_label_set_text(lbl_ssid_show, ssid_hint);
  lv_obj_set_style_text_color(lbl_ssid_show, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_ssid_show, &lv_font_montserrat_ext_14, 0);
  lv_obj_align(lbl_ssid_show, LV_ALIGN_TOP_MID, 0, 52);

  // Password textarea
  ta_wifi_pass = lv_textarea_create(scr_wifi_pass);
  lv_textarea_set_one_line(ta_wifi_pass, true);
  lv_textarea_set_password_mode(ta_wifi_pass, false);
  lv_textarea_set_placeholder_text(ta_wifi_pass, T(STR_WIFI_PASS_PLACEHOLDER));
  lv_obj_set_size(ta_wifi_pass, 380, 44);
  lv_obj_align(ta_wifi_pass, LV_ALIGN_TOP_MID, 0, 74);
  lv_obj_set_style_text_font(ta_wifi_pass, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_color(ta_wifi_pass, lv_color_hex(0xffffff), 0);
  lv_obj_set_style_bg_color(ta_wifi_pass, lv_color_hex(0x1e2e4a), 0);
  lv_obj_set_style_border_color(ta_wifi_pass, lv_color_hex(0x2a4080), 0);

  // Keyboard
  kb_wifi_pass = lv_keyboard_create(scr_wifi_pass);
  lv_keyboard_set_textarea(kb_wifi_pass, ta_wifi_pass);
  lv_obj_set_size(kb_wifi_pass, 480, 160);
  lv_obj_align(kb_wifi_pass, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_set_style_bg_color(kb_wifi_pass, lv_color_hex(0x182238), 0);
  lv_obj_set_style_border_width(kb_wifi_pass, 0, 0);

  // Enter on keyboard → connect
  lv_obj_add_event_cb(kb_wifi_pass, [](lv_event_t *e) {
    if (lv_event_get_code(e) == LV_EVENT_READY) {
      const char* pass = lv_textarea_get_text(ta_wifi_pass);
      saveWifiCredentials(wifi_setup_ssid, pass);
      showWifiConnectingScreen();
    }
  }, LV_EVENT_ALL, NULL);
}

// ============================================================
//  WIFI SETUP: STEP 3 — Connect + result
// ============================================================
// The rows are four label pairs rather than one container, so visibility is
// toggled over the value labels and their siblings. Built hidden and only
// revealed once a link actually exists.
static void setConnSummaryHidden(bool hidden) {
  lv_obj_t *objs[] = { conn_val_ssid, conn_val_ip, conn_val_gw, conn_val_rssi,
                       conn_lbl_ssid, conn_lbl_ip, conn_lbl_gw, conn_lbl_rssi };
  for (lv_obj_t *o : objs) {
    if (!o) continue;
    if (hidden) lv_obj_add_flag(o, LV_OBJ_FLAG_HIDDEN);
    else        lv_obj_clear_flag(o, LV_OBJ_FLAG_HIDDEN);
  }
}

void showWifiConnectingScreen() {
  logSD("SHOW: WifiConnectingScreen");
  logSD("UI: Screen -> WifiConnecting");
  hideAllOverlays();
  if (scr_wifi_connecting) { lv_obj_del(scr_wifi_connecting); scr_wifi_connecting = nullptr; }
  buildWifiConnectingScreen();
  lv_obj_clear_flag(scr_wifi_connecting, LV_OBJ_FLAG_HIDDEN);
  lv_timer_handler();

  // Actually connect now
  wifi_ok = false;

  lv_obj_t *status_lbl = lbl_conn_status;

  wifiManagerPrepareScan();
  wifi_ok = wifiManagerConnect(cfg_wifi_ssid, cfg_wifi_password, 20, 500);
  lv_timer_handler();

  if (wifi_ok) {
    syncNTP();
    updateHeaderStatus();
    lv_label_set_text(lbl_spoolman_weight, T(STR_WAIT_SCAN_SM));
    // The IP used to be crammed into this line; it now has a row of its own
    // below, so the headline is just the result.
    char ok_buf[48];
    snprintf(ok_buf, sizeof(ok_buf), LV_SYMBOL_OK "  %s", T(STR_WIFI_SUCCESS));
    if (status_lbl) lv_label_set_text(status_lbl, ok_buf);
    lv_obj_set_style_text_color(status_lbl, lv_color_hex(0x28d49a), 0);

    if (conn_val_ssid) {
      lv_label_set_text(conn_val_ssid, cfg_wifi_ssid[0] ? cfg_wifi_ssid : "-");
      lv_label_set_text(conn_val_ip,   wifiManagerLocalIP().toString().c_str());
      lv_label_set_text(conn_val_gw,   wifiManagerGatewayIP().toString().c_str());
      const int rssi = wifiManagerRSSI();
      const char *qual;
      if      (rssi >= -50) qual = T(STR_WIFI_QUAL_EXCELLENT);
      else if (rssi >= -65) qual = T(STR_WIFI_QUAL_GOOD);
      else if (rssi >= -75) qual = T(STR_WIFI_QUAL_MEDIUM);
      else                  qual = T(STR_WIFI_QUAL_WEAK);
      char rssi_buf[48];
      snprintf(rssi_buf, sizeof(rssi_buf), "%d dBm  (%s)", rssi, qual);
      lv_label_set_text(conn_val_rssi, rssi_buf);
      setConnSummaryHidden(false);
    }

    // Show next button
    if (btn_conn_next) lv_obj_clear_flag(btn_conn_next, LV_OBJ_FLAG_HIDDEN);
  } else {
    updateHeaderStatus();
    char fail_buf[80];
    snprintf(fail_buf, sizeof(fail_buf), T(STR_WIFI_CONN_FAILED), cfg_wifi_ssid);
    if (status_lbl) lv_label_set_text(status_lbl, fail_buf);
    lv_obj_set_style_text_color(status_lbl, lv_color_hex(0xff8080), 0);

    // Show retry button
    if (btn_conn_retry) lv_obj_clear_flag(btn_conn_retry, LV_OBJ_FLAG_HIDDEN);
    if (btn_conn_next)  lv_obj_clear_flag(btn_conn_next,  LV_OBJ_FLAG_HIDDEN);
  }
  lv_timer_handler();
}

void buildWifiConnectingScreen() {
  logSD("BUILD: WifiConnectingScreen");
  // Cleared before the old screen goes away, so nothing can be touched between
  // the delete and the rebuild below.
  btn_conn_retry = btn_conn_next = lbl_conn_status = nullptr;
  conn_val_ssid = conn_val_ip = conn_val_gw = conn_val_rssi = nullptr;
  conn_lbl_ssid = conn_lbl_ip = conn_lbl_gw = conn_lbl_rssi = nullptr;
  releaseScreen(&scr_wifi_connecting);
  scr_wifi_connecting = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_wifi_connecting, 480, 320);
  lv_obj_set_pos(scr_wifi_connecting, 0, 0);
  lv_obj_add_flag(scr_wifi_connecting, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_wifi_connecting, 0, 0);
  lv_obj_set_style_border_width(scr_wifi_connecting, 0, 0);
  lv_obj_set_style_pad_all(scr_wifi_connecting, 0, 0);
  lv_obj_clear_flag(scr_wifi_connecting, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_wifi_connecting, lv_color_hex(0x0a1020), 0);

  lv_obj_t *title = lv_label_create(scr_wifi_connecting);
  lv_label_set_text(title, T(STR_WIFI_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 24);

  addBackButton(scr_wifi_connecting, [](lv_event_t *e) { showWifiSetupScreen(); });
  addCloseButton(scr_wifi_connecting);

  char conn_buf[64];
  snprintf(conn_buf, sizeof(conn_buf), T(STR_WIFI_CONNECTING), wifi_setup_ssid);
  lv_obj_t *lbl_connecting = lv_label_create(scr_wifi_connecting);
  lv_label_set_text(lbl_connecting, conn_buf);
  lv_obj_set_style_text_color(lbl_connecting, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_connecting, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_connecting, LV_ALIGN_TOP_MID, 0, 68);

  // Status label — larger font, filled after connection
  lbl_conn_status = lv_label_create(scr_wifi_connecting);
  lv_obj_t *lbl_status_conn = lbl_conn_status;
  lv_label_set_text(lbl_status_conn, "");
  lv_obj_set_style_text_color(lbl_status_conn, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_status_conn, &lv_font_montserrat_ext_20, 0);
  lv_obj_set_style_text_align(lbl_status_conn, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_status_conn, LV_ALIGN_TOP_MID, 0, 100);
  lv_label_set_long_mode(lbl_status_conn, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_status_conn, 420);

  // Summary of the link that was just established. The screen used to show a
  // single centred line in an otherwise empty 480x320, which told the user
  // nothing beyond "it worked". Same two column rows as the WiFi status
  // screen, so the two read alike.
  // Last row ends at ~244, the buttons start at 252 (48px tall, 20px off the
  // bottom edge), so the block stops just clear of them.
  conn_val_ssid = addInfoRow(scr_wifi_connecting, 134, "SSID",    &conn_lbl_ssid);
  conn_val_ip   = addInfoRow(scr_wifi_connecting, 164, "IP",      &conn_lbl_ip);
  conn_val_gw   = addInfoRow(scr_wifi_connecting, 194, "Gateway", &conn_lbl_gw);
  conn_val_rssi = addInfoRow(scr_wifi_connecting, 224, "Signal",  &conn_lbl_rssi);
  setConnSummaryHidden(true);

  // Retry button (initially hidden)
  btn_conn_retry = lv_btn_create(scr_wifi_connecting);
  lv_obj_t *btn_retry = btn_conn_retry;
  lv_obj_set_size(btn_retry, 200, 48);
  lv_obj_align(btn_retry, LV_ALIGN_BOTTOM_MID, -110, -20);
  lv_obj_add_flag(btn_retry, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_retry, 8, 0);
  lv_obj_set_style_shadow_width(btn_retry, 0, 0);
  lv_obj_set_style_border_width(btn_retry, 0, 0);
  lv_obj_add_event_cb(btn_retry, [](lv_event_t *e) { logSD("BTN: Retry -> WifiSetup"); showWifiSetupScreen(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_retry = lv_label_create(btn_retry);
  lv_label_set_text(lbl_retry, LV_SYMBOL_LEFT "  "); { char rb[32]; snprintf(rb,sizeof(rb),"%s",T(STR_RETRY)); lv_label_set_text(lbl_retry,rb); }
  lv_obj_set_style_text_color(lbl_retry, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_retry, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_retry);

  // Next button → Spoolman IP (initially hidden)
  btn_conn_next = lv_btn_create(scr_wifi_connecting);
  lv_obj_t *btn_next = btn_conn_next;
  lv_obj_set_size(btn_next, 200, 48);
  lv_obj_align(btn_next, LV_ALIGN_BOTTOM_MID, 110, -20);
  lv_obj_add_flag(btn_next, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_bg_color(btn_next, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_next, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_next, 8, 0);
  lv_obj_set_style_shadow_width(btn_next, 0, 0);
  lv_obj_set_style_border_width(btn_next, 0, 0);
  lv_obj_add_event_cb(btn_next, [](lv_event_t *e) {
    // The backend choice comes before the address, because the address is
    // only meaningful once we know which server it points at. Outside the
    // setup this button keeps leading straight to the address screen.
    if (setup_active) {
      logSD("BTN: WifiConnecting -> Next (Backend)");
      show_backend_pending = true;
    } else {
      logSD("BTN: WifiConnecting -> Next (Address)");
      show_spoolman_pending = true;
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_next = lv_label_create(btn_next);
  { char nb[32];
    if (setup_active) strncpy(nb, T(STR_BTN_NEXT), sizeof(nb) - 1);
    else              strncpy(nb, backendName(), sizeof(nb) - 1);
    nb[sizeof(nb) - 1] = '\0';
    size_t n = strlen(nb);
    snprintf(nb + n, sizeof(nb) - n, "  " LV_SYMBOL_RIGHT);
    lv_label_set_text(lbl_next, nb); }
  lv_obj_set_style_text_color(lbl_next, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_next, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_next);
}
