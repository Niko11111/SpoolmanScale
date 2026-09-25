#include "wifi_menu_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/wifi_manager.h"
#include "ui_common.h"
#include "wifi_info.h"
#include "wifi_setup_screen.h"

// The address is read when the row is built. The menu is rebuilt on every
// entry and the status screen behind it refreshes itself, so no timer here;
// the Connection tile used to carry one for exactly this text.
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

void closeWifiMenuScreen() {
  if (scr_wifi_menu) { lv_obj_del(scr_wifi_menu); scr_wifi_menu = nullptr; }
}

void buildWifiMenuScreen() {
  logSD("BUILD: WifiMenuScreen");
  releaseScreen(&scr_wifi_menu);
  scr_wifi_menu = buildOverlayScreen();
  buildSubHeader(scr_wifi_menu, T(STR_BTN_WIFI_SETTINGS),
    [](lv_event_t *e){
      logSD("BTN: Back -> Connection");
      // Deferred: the Connection screen is rebuilt, and not from inside the
      // callback of the screen it replaces.
      show_connection_from_spoolman_pending = true;
    });

  lv_obj_t *list = buildOptionList(scr_wifi_menu);

  { char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_WIFI_TITLE);
    char buf_s[40];
    if (cfg_wifi_ssid[0]) snprintf(buf_s, sizeof(buf_s), "%s", cfg_wifi_ssid);
    else copyT(buf_s, sizeof(buf_s), STR_BTN_WIFI_NONE);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_WIFI, buf_t, buf_s);
    // The same direct call the Connection tile made before: the setup screen
    // hides the overlays and releases its own instance, nothing blocks.
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: WifiMenu -> WifiSetup");
      showWifiSetupScreen();
    }, LV_EVENT_CLICKED, NULL); }

  { char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_BTN_WIFI_STATUS);
    char buf_s[40]; wifiIpText(buf_s, sizeof(buf_s));
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_GPS, buf_t, buf_s);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: WifiMenu -> WiFi Status");
      showWifiStatusScreen();
    }, LV_EVENT_CLICKED, NULL); }
}
