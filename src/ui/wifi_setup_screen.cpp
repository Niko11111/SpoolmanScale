#include "wifi_setup_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "header_status.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/app_settings.h"
#include "services/time_service.h"
#include "services/wifi_manager.h"
#include "services/wifi_known.h"
#include "services/improv_serial.h"
#include "services/setup_portal.h"
#include "setup_welcome_screen.h"
#include "wifi_portal_screen.h"
#include "ui_common.h"
#include "setup_frame.h"
#include "ui/theme.h"
#include "services/backend.h"



// Rows rendered in the scan list, and therefore the number of full SSIDs kept
// for the click handler. The scan itself may return more; anything past this is
// not shown and not selectable.
#define WIFI_SCAN_ROWS_MAX  20
// Entries the RSSI sort covers. Networks beyond this stay in scan order, which
// only matters in places dense enough to see more than this many APs at once.
#define WIFI_SCAN_SORT_MAX  64
// What the list takes of the screen: under the header, over the action bar.
#define WIFI_LIST_X         12
#define WIFI_BAND_Y         52   // the 2.4 GHz line above the list
#define WIFI_LIST_Y         74
#define WIFI_LIST_W        456
#define WIFI_LIST_H        180
#define WIFI_ROW_H          44
#define WIFI_ROW_INSET      14
#define WIFI_SSID_W        360
#define WIFI_MARK_GAP       12   // between the tick or "saved" and the signal
// Under the spinner while there is no list yet, or no network.
#define WIFI_STATUS_Y      200
#define WIFI_STATUS_W      440

static char  wifi_setup_ssid[33]  = "";
// What the callbacks park for appLoop(): a scan takes seconds and the connect
// attempt ten, and both used to run inside the button that asked for them.
// The password is copied out of the textarea here, because that textarea is
// gone by the time the connect runs.
static bool  wifi_scan_pending    = false;
// A scan runs in the background while the list shows a spinner; the loop
// polls it. The time bounds a scan that never reports back.
static bool  wifi_scan_running    = false;
static unsigned long wifi_scan_started_ms = 0;
#define WIFI_SCAN_TIMEOUT_MS 15000
#define WIFI_SCAN_SPINNER    48
static void finishWifiScan(int n);
static bool  wifi_connect_pending = false;
static bool  wifi_reconnect_pending = false;
static char  wifi_setup_pass[WIFI_PASS_MAX_LEN + 1] = "";
static lv_obj_t *lbl_wifi_setup_status = nullptr;
static lv_obj_t *lbl_wifi_scan_list = nullptr;

const char *wifiSetupChosenSsid() { return wifi_setup_ssid; }

void wifiSetupSubmitPassword(const char *pass) {
  strncpy(wifi_setup_pass, pass ? pass : "", sizeof(wifi_setup_pass) - 1);
  wifi_setup_pass[sizeof(wifi_setup_pass) - 1] = '\0';
  wifi_connect_pending = true;
}

// ============================================================
//  WIFI SETUP: STEP 1 - Network scan + selection
// ============================================================
void showWifiSetupScreen() {
  logSD("SHOW: WifiSetupScreen");
  logSD("UI: Screen -> WifiSetup");
  hideAllOverlays();
  releaseScreen(&scr_wifi_setup);   // the rescan button sits on it
  // Null global pointers - otherwise they point to deleted objects
  lbl_wifi_scan_list    = nullptr;
  lbl_wifi_setup_status = nullptr;
  buildWifiSetupScreen();
  lv_obj_clear_flag(scr_wifi_setup, LV_OBJ_FLAG_HIDDEN);
}

static void onWifiListBack(lv_event_t *e) {
  // Into the setup's welcome only from the setup itself: from the settings,
  // with no network stored yet, back is the WiFi menu like always.
  if (setup_active && cfg_wifi_ssid[0] == '\0') {
    showFirstBootScreen();
  } else if (setup_active) {
    // In the setup with a network already stored. The scan has dropped that
    // link, so back means connecting to it again, not a trip into the
    // settings menu in the middle of the setup.
    wifi_reconnect_pending = true;
  } else {
    // Into the WiFi menu the setup is reached from. Deferred: the menu is
    // built on the loop, not inside this callback.
    show_wifi_menu_pending = true;
  }
}

void buildWifiSetupScreen() {
  logSD("BUILD: WifiSetupScreen");
  releaseScreen(&scr_wifi_setup);
  scr_wifi_setup = buildOverlayScreen();
  setupOrSettingsHeader(scr_wifi_setup, T(STR_WIFI_TITLE), SETUP_STEP_WIFI, onWifiListBack);

  // The ESP32-S3 has no 5 GHz radio. A network that only sends there is not
  // in the list at all, which looks like a fault unless this says why.
  lv_obj_t *band = lv_label_create(scr_wifi_setup);
  lv_label_set_text(band, T(STR_WIFI_24_ONLY));
  lv_obj_set_style_text_font(band, UI_FONT_CAPTION, 0);
  lv_obj_set_style_text_color(band, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_pos(band, WIFI_LIST_X + 2, WIFI_BAND_Y);

  lv_obj_t *list = lv_obj_create(scr_wifi_setup);
  lv_obj_set_size(list, WIFI_LIST_W, WIFI_LIST_H);
  lv_obj_set_pos(list, WIFI_LIST_X, WIFI_LIST_Y);
  lv_obj_set_style_bg_opa(list, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 0, 0);
  lv_obj_set_style_pad_row(list, 6, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  lv_obj_add_flag(list, LV_OBJ_FLAG_SCROLLABLE);
  lbl_wifi_scan_list = list;

  // Only while there is nothing to pick: scanning, or nothing found. A count
  // over a list the user can see said nothing.
  lbl_wifi_setup_status = lv_label_create(scr_wifi_setup);
  lv_label_set_text(lbl_wifi_setup_status, T(STR_WIFI_SCAN));
  lv_obj_set_style_text_color(lbl_wifi_setup_status, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_style_text_font(lbl_wifi_setup_status, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_align(lbl_wifi_setup_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_wifi_setup_status, LV_LABEL_LONG_DOT);
  lv_obj_set_size(lbl_wifi_setup_status, WIFI_STATUS_W, lv_font_get_line_height(UI_FONT_SMALL));
  lv_obj_align(lbl_wifi_setup_status, LV_ALIGN_TOP_MID, 0, WIFI_STATUS_Y);

  // Rescan on the left; on the right the other way in, where the scale opens
  // a network of its own and the phone does the typing. Neither is the way
  // on - that is a tap on a network - so the right one is an outline.
  SetupBar bar = setupActionBar(scr_wifi_setup,
    T(STR_WIFI_RESCAN), [](lv_event_t *e) {
      if (wifi_scan_running) return;   // the spinner already says it is on it
      if (lbl_wifi_setup_status) lv_label_set_text(lbl_wifi_setup_status, T(STR_WIFI_SCAN));
      wifi_scan_pending = true;
    },
    T(STR_BTN_WIFI_PORTAL), [](lv_event_t *e) {
      logSD("BTN: WifiSetup -> Portal");
      showWifiPortalScreen();
    });
  setupBarMainOutline(bar);

  // Scan on the next loop pass. The status line already says so; a scan
  // from here would run inside whichever callback opened this screen.
  wifi_scan_pending = true;
}

static bool wifiSetupScreenVisible() {
  return (scr_wifi_setup      && !lv_obj_has_flag(scr_wifi_setup,      LV_OBJ_FLAG_HIDDEN)) ||
         (scr_wifi_pass       && !lv_obj_has_flag(scr_wifi_pass,       LV_OBJ_FLAG_HIDDEN)) ||
         (scr_wifi_connecting && !lv_obj_has_flag(scr_wifi_connecting, LV_OBJ_FLAG_HIDDEN)) ||
         (scr_wifi_portal     && !lv_obj_has_flag(scr_wifi_portal,     LV_OBJ_FLAG_HIDDEN));
}

void wifiSetupConnectWith(const char *ssid, const char *pass) {
  strncpy(wifi_setup_ssid, ssid, sizeof(wifi_setup_ssid) - 1);
  wifi_setup_ssid[sizeof(wifi_setup_ssid) - 1] = '\0';
  strncpy(wifi_setup_pass, pass, sizeof(wifi_setup_pass) - 1);
  wifi_setup_pass[sizeof(wifi_setup_pass) - 1] = '\0';
  wifi_connect_pending = true;
}

void handleWifiSetupDeferredActions() {
  // First, because it decides what the rest of this pass may do. A scan that
  // was parked while the browser connected - the button, or a screen opened
  // meanwhile - would otherwise run now, and its radio reset
  // (wifiManagerPrepareScan() disconnects) took the link the browser had just
  // made straight down again: a green "connected" screen with no address.
  if (improvSerialTakeProvisioned()) {
    wifi_scan_pending = false;
    updateHeaderStatus();
    // What a boot without a network left on the home screen.
    if (lbl_spoolman_weight &&
        strcmp(lv_label_get_text(lbl_spoolman_weight), T(STR_NO_WIFI)) == 0) {
      lv_label_set_text(lbl_spoolman_weight, T(STR_WAIT_SCAN_SM));
    }
    // A scan or a password the browser has just made moot.
    if (wifiSetupScreenVisible()) showWifiConnectedScreen();
  }
  // Held while the browser connects: the scan's radio reset would cut that
  // attempt off. Either it succeeds and the screen moves on, or the scan runs
  // right after.
  if (wifi_scan_pending && !improvSerialBusy()) {
    wifi_scan_pending = false;
    // Not once the list is behind another screen, and never while the setup
    // portal runs: a scan switches to station mode and ends its access point.
    if (scr_wifi_setup && lbl_wifi_scan_list && lbl_wifi_setup_status &&
        !lv_obj_has_flag(scr_wifi_setup, LV_OBJ_FLAG_HIDDEN) && !setupPortalActive()) {
      doWifiScan();
    }
  }
  if (wifi_scan_running) {
    const int n = wifiManagerScanPoll();
    const bool timed_out = millis() - wifi_scan_started_ms > WIFI_SCAN_TIMEOUT_MS;
    if (n >= 0 || n == -2 || timed_out) {
      wifi_scan_running = false;
      if (timed_out && n < 0) logSD("WiFi scan: no answer, given up");
      finishWifiScan(n);
    }
  }
  if (wifi_connect_pending) {
    wifi_connect_pending = false;
    saveWifiCredentials(wifi_setup_ssid, wifi_setup_pass);
    memset(wifi_setup_pass, 0, sizeof(wifi_setup_pass));
    showWifiConnectingScreen();
  }
  if (wifi_reconnect_pending) {
    wifi_reconnect_pending = false;
    // showWifiConnectingScreen() connects with the stored credentials. This
    // only names the network in its "Connecting to" line.
    strncpy(wifi_setup_ssid, cfg_wifi_ssid, sizeof(wifi_setup_ssid) - 1);
    wifi_setup_ssid[sizeof(wifi_setup_ssid) - 1] = '\0';
    showWifiConnectingScreen();
  }
}

// Perform scan and populate list
// The scan used to hold the loop for its 2 to 4 seconds, with nothing on the
// screen moving. It runs in the background now, with a spinner where the list
// will be, and finishWifiScan() fills the list once the loop sees it done.
void doWifiScan() {
  if (wifi_scan_running) return;
  lv_obj_clean(lbl_wifi_scan_list);
  lv_obj_t *spin = lv_spinner_create(lbl_wifi_scan_list, 1000, 70);
  lv_obj_add_flag(spin, LV_OBJ_FLAG_FLOATING);
  lv_obj_set_size(spin, WIFI_SCAN_SPINNER, WIFI_SCAN_SPINNER);
  lv_obj_center(spin);
  lv_obj_set_style_arc_width(spin, 6, LV_PART_MAIN);
  lv_obj_set_style_arc_width(spin, 6, LV_PART_INDICATOR);
  lv_obj_set_style_arc_color(spin, lv_color_hex(UI_COL_LINE), LV_PART_MAIN);
  lv_obj_set_style_arc_color(spin, lv_color_hex(UI_COL_ACCENT), LV_PART_INDICATOR);
  lv_obj_clear_flag(spin, LV_OBJ_FLAG_CLICKABLE);

  // Disconnect required after failed WiFi.begin() -
  // otherwise scanNetworks() returns 0. Only then: a connected station scans
  // beside its link. Taking the link down first turned the driver off while
  // the loop kept serving, and the web server freed a waiting connection's
  // buffers through the driver that was gone - PANIC in esp_pbuf_free under
  // lwip_accept on 26.09.2026. The blocking scan never served meanwhile.
  if (!wifiManagerIsConnected()) wifiManagerPrepareScan();
  if (!wifiManagerStartScanAsync()) {
    finishWifiScan(-2);
    return;
  }
  wifi_scan_running = true;
  wifi_scan_started_ms = millis();
}

// Full SSID per rendered row. The label is LV_LABEL_LONG_DOT at 300 px, so
// reading the SSID back out of it returned "LongNetworkNam..." and the
// connection failed for no visible reason. The click handler reads this instead.
static char row_ssid[WIFI_SCAN_ROWS_MAX][33];

// A known network connects with its stored password, any other one asks.
static void onScanRowClicked(lv_event_t *e) {
  lv_obj_t *btn = (lv_obj_t*)lv_event_get_target(e);
  const char* ssid_str = (const char*)lv_obj_get_user_data(btn);
  if (!ssid_str) return;
  const WifiKnownList &known = wifiKnownList();
  const int at = wifiKnownFind(known, ssid_str);
  if (at >= 0) {
    logSDf("BTN: WifiSetup -> known network %s, no password asked", ssid_str);
    wifiSetupConnectWith(ssid_str, known.e[at].pass);
    return;
  }
  strncpy(wifi_setup_ssid, ssid_str, sizeof(wifi_setup_ssid)-1);
  wifi_setup_ssid[sizeof(wifi_setup_ssid)-1] = '\0';
  showWifiPassScreen();
}

// One network on the list. A tick for the one the scale is on, "saved" for one
// it knows; both left of the signal so the signal stays in its column.
static void addScanRow(int slot, const char *ssid, int rssi, bool known, bool connected) {
  snprintf(row_ssid[slot], sizeof(row_ssid[slot]), "%s", ssid);

  // Signal as the WiFi symbol in its strength's colour: the dBm figure
  // meant nothing to most, and one label is cheaper than drawn bars.
  uint32_t sig_color;
  if      (rssi >= -65) sig_color = UI_COL_GOOD;
  else if (rssi >= -80) sig_color = UI_COL_WARN;
  else                  sig_color = UI_COL_SIGNAL_LOW_LIST;

  lv_obj_t *row = lv_btn_create(lbl_wifi_scan_list);
  lv_obj_set_size(row, LV_PCT(100), WIFI_ROW_H);
  lv_obj_set_style_bg_color(row, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_bg_color(row, lv_color_hex(UI_COL_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_radius(row, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(row, 0, 0);
  lv_obj_set_style_border_color(row, lv_color_hex(UI_COL_LINE_SOFT), 0);
  lv_obj_set_style_border_width(row, 1, 0);
  lv_obj_set_style_pad_all(row, 0, 0);
  lv_obj_set_user_data(row, row_ssid[slot]);

  lv_obj_t *lbl_sig = lv_label_create(row);
  lv_label_set_text(lbl_sig, LV_SYMBOL_WIFI);
  lv_obj_set_style_text_color(lbl_sig, lv_color_hex(sig_color), 0);
  lv_obj_set_style_text_font(lbl_sig, UI_FONT_BODY, 0);
  lv_obj_align(lbl_sig, LV_ALIGN_RIGHT_MID, -WIFI_ROW_INSET, 0);

  int ssid_w = WIFI_SSID_W;
  if (connected || known) {
    lv_obj_t *mark = lv_label_create(row);
    lv_label_set_text(mark, connected ? LV_SYMBOL_OK : T(STR_WIFI_KNOWN_WORD));
    lv_obj_set_style_text_font(mark, connected ? UI_FONT_BODY : UI_FONT_CAPTION, 0);
    lv_obj_set_style_text_color(mark, lv_color_hex(connected ? UI_COL_ACCENT : UI_COL_CAPTION), 0);
    lv_obj_align_to(mark, lbl_sig, LV_ALIGN_OUT_LEFT_MID, -WIFI_MARK_GAP, 0);
    lv_obj_update_layout(mark);
    ssid_w -= lv_obj_get_width(mark) + WIFI_MARK_GAP;
  }

  lv_obj_t *lbl_ssid = lv_label_create(row);
  lv_label_set_text(lbl_ssid, ssid);
  lv_obj_set_style_text_color(lbl_ssid, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(lbl_ssid, UI_FONT_BODY, 0);
  lv_label_set_long_mode(lbl_ssid, LV_LABEL_LONG_DOT);
  lv_obj_set_size(lbl_ssid, ssid_w, lv_font_get_line_height(UI_FONT_BODY));
  lv_obj_align(lbl_ssid, LV_ALIGN_LEFT_MID, WIFI_ROW_INSET, 0);

  lv_obj_add_event_cb(row, onScanRowClicked, LV_EVENT_CLICKED, NULL);
}

static void finishWifiScan(int n) {
  // The screen may have gone while the scan ran: then only the results go.
  if (!scr_wifi_setup || !lbl_wifi_scan_list || !lbl_wifi_setup_status) {
    wifiManagerClearScan();
    return;
  }
  lv_obj_clean(lbl_wifi_scan_list);   // the spinner

  // Negative means WIFI_SCAN_FAILED (-2) or WIFI_SCAN_RUNNING (-1). Checking
  // only for 0 let those fall through into "-2 networks found" above an empty
  // list. Both branches release the scan results, which the empty one forgot.
  if (n <= 0) {
    if (n < 0) logSDf("WiFi scan failed (rc=%d)", n);
    lv_label_set_text(lbl_wifi_setup_status, T(STR_WIFI_NO_NET));
    wifiManagerClearScan();
    return;
  }

  lv_label_set_text(lbl_wifi_setup_status, "");

  // Known networks first, then strongest first. The body of this loop used to
  // be empty - only comments - so the list came out in scan order. Sorting an
  // index array keeps the scan results themselves untouched, so the accessors
  // below still work.
  int sort_n = n < WIFI_SCAN_SORT_MAX ? n : WIFI_SCAN_SORT_MAX;
  static int idx[WIFI_SCAN_SORT_MAX];
  static bool known_at[WIFI_SCAN_SORT_MAX];
  const WifiKnownList &known = wifiKnownList();
  for (int i = 0; i < sort_n; i++) {
    idx[i] = i;
    known_at[i] = wifiKnownFind(known, wifiManagerScannedSSID(i).c_str()) >= 0;
  }
  for (int i = 0; i < sort_n - 1; i++) {
    for (int j = 0; j < sort_n - i - 1; j++) {
      const int a = idx[j], b = idx[j + 1];
      const bool later = known_at[a] != known_at[b]
        ? known_at[b]
        : wifiManagerScannedRSSI(a) < wifiManagerScannedRSSI(b);
      if (later) { idx[j] = b; idx[j + 1] = a; }
    }
  }

  char on[33];
  wifiManagerCurrentSsid(on, sizeof(on));
  int row_count = 0;
  for (int disp = 0; disp < sort_n && row_count < WIFI_SCAN_ROWS_MAX; disp++) {
    const int i = idx[disp];
    const String ssid = wifiManagerScannedSSID(i);
    if (ssid.length() == 0) continue;
    addScanRow(row_count++, ssid.c_str(), wifiManagerScannedRSSI(i),
               known_at[i], strcmp(on, ssid.c_str()) == 0);
  }

  wifiManagerClearScan();
}
