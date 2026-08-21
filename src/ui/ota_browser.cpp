#include "ota_browser.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <IPAddress.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/backend.h"
#include "services/ota_web_server.h"
#include "services/wifi_manager.h"
#include "ui_common.h"

// Which entry point brought the user here. Kept between show and build
// because buildOtaBrowserScreen() is also reached through the generic
// rebuild path and has no argument of its own.
static WebScreenContext s_web_ctx = WEB_CTX_FIRMWARE;

// Value labels of the two credential rows, refreshed while the user types on
// the other side. Null whenever the rows are not on screen.
static lv_obj_t *s_lbl_key_val   = nullptr;
static lv_obj_t *s_lbl_token_val = nullptr;

// Only the two FilaMan entry points need the credential rows. The drying
// thresholds are edited in the browser as well, but have nothing to do with
// tokens, so that context just shows the address.
static bool showsCredentials() {
  // Spoolman has nothing to enter, so the rows are a FilaMan and BamBuddy
  // affair even in the contexts that would otherwise show them.
  if (backendMode() == BACKEND_SPOOLMAN) return false;
  return s_web_ctx == WEB_CTX_BACKEND || s_web_ctx == WEB_CTX_SETUP;
}

// Everything except the firmware upload uses the neutral title and skips the
// .bin hint and the stop button.
static bool isFirmwareContext() {
  return s_web_ctx == WEB_CTX_FIRMWARE;
}

void showOtaBrowserScreen(WebScreenContext ctx) {
  logSD("SHOW: OtaBrowserScreen");
  logSDf("UI: Screen -> Web interface (ctx=%d)", (int)ctx);
  s_web_ctx = ctx;
  hideAllOverlays();
  stopOtaServer();
  lbl_ota_status = nullptr;
  s_lbl_key_val = nullptr;
  s_lbl_token_val = nullptr;
  if (scr_ota_browser) {
    lv_obj_del(scr_ota_browser);
    scr_ota_browser = nullptr;
  }
  buildOtaBrowserScreen();
  lv_obj_clear_flag(scr_ota_browser, LV_OBJ_FLAG_HIDDEN);
  if (wifi_ok) startOtaServer();
}

// One credential row: name on the left, state on the right. Returns the value
// label so it can be updated without rebuilding the screen.
static lv_obj_t* addCredentialRow(lv_obj_t *parent, int y, const char *name,
                                  bool present) {
  char name_buf[32];
  strncpy(name_buf, name, sizeof(name_buf) - 1);
  name_buf[sizeof(name_buf) - 1] = '\0';

  lv_obj_t *l = lv_label_create(parent);
  lv_label_set_text(l, name_buf);
  lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(l, 40, y);

  char val_buf[24];
  strncpy(val_buf, present ? T(STR_BACKEND_SET) : T(STR_BACKEND_MISSING),
          sizeof(val_buf) - 1);
  val_buf[sizeof(val_buf) - 1] = '\0';

  lv_obj_t *v = lv_label_create(parent);
  lv_label_set_text(v, val_buf);
  lv_obj_set_style_text_color(v, lv_color_hex(present ? 0x40c080 : 0xf0b838), 0);
  lv_obj_set_style_text_font(v, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(v, LV_ALIGN_TOP_RIGHT, -40, y);
  return v;
}

static void setCredentialRow(lv_obj_t *label, bool present) {
  if (!label) return;
  char val_buf[24];
  strncpy(val_buf, present ? T(STR_BACKEND_SET) : T(STR_BACKEND_MISSING),
          sizeof(val_buf) - 1);
  val_buf[sizeof(val_buf) - 1] = '\0';
  lv_label_set_text(label, val_buf);
  lv_obj_set_style_text_color(label, lv_color_hex(present ? 0x40c080 : 0xf0b838), 0);
}

// Remembers what the rows currently say. Rewriting a label invalidates it and
// forces a redraw, and this runs on every pass of the main loop, so the text
// is only touched when it actually changed.
static bool s_key_shown   = false;
static bool s_token_shown = false;

void refreshWebCredentialRows() {
  if (!s_lbl_key_val && !s_lbl_token_val) return;

  // Several navigation paths delete this screen without knowing about the two
  // labels on it. They all null the screen pointer, so that is the reliable
  // signal that the labels are gone too. Dropping them here means this runs
  // on every loop pass without ever reaching freed memory.
  if (!scr_ota_browser) {
    s_lbl_key_val = nullptr;
    s_lbl_token_val = nullptr;
    return;
  }
  if (lv_obj_has_flag(scr_ota_browser, LV_OBJ_FLAG_HIDDEN)) return;

  // BamBuddy has a single key and no second row at all, so the token half
  // stays untouched there.
  const bool bb = backendIsBamBuddy();
  bool key_now   = bb ? (bambuddyApiKey()[0] != '\0')
                      : (filamanApiKey()[0]  != '\0');
  bool token_now = bb ? false : (filamanDeviceToken()[0] != '\0');

  if (key_now != s_key_shown) {
    s_key_shown = key_now;
    setCredentialRow(s_lbl_key_val, key_now);
    logSDf("Web: API key now %s", key_now ? "set" : "missing");
  }
  if (s_lbl_token_val && token_now != s_token_shown) {
    s_token_shown = token_now;
    setCredentialRow(s_lbl_token_val, token_now);
    logSDf("Web: device token now %s", token_now ? "set" : "missing");
  }
}

void buildOtaBrowserScreen() {
  logSD("BUILD: OtaBrowserScreen");
  releaseScreen(&scr_ota_browser);
  s_lbl_key_val = nullptr;
  s_lbl_token_val = nullptr;
  scr_ota_browser = buildOverlayScreen();

  char title_buf[40];
  strncpy(title_buf, isFirmwareContext() ? T(STR_OTA_BROWSER_TITLE) : T(STR_WEB_TITLE),
          sizeof(title_buf) - 1);
  title_buf[sizeof(title_buf) - 1] = '\0';

  if (s_web_ctx == WEB_CTX_SETUP) {
    // No way back during setup, the previous step is already behind us.
    // A plain title keeps the screen consistent with the other setup steps.
    lv_obj_t *lbl_title = lv_label_create(scr_ota_browser);
    lv_label_set_text(lbl_title, title_buf);
    lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);
  } else {
    buildSubHeader(scr_ota_browser, title_buf,
      [](lv_event_t *e){
        logSD("BTN: Web interface -> Back");
        stopOtaServer();
        // Back goes where the user came from, not always to the update menu.
        switch (s_web_ctx) {
          case WEB_CTX_BACKEND: show_backend_pending         = true; break;
          case WEB_CTX_DRYING:  show_drying_reminder_pending  = true; break;
          default:              show_ota_pending              = true; break;
        }
      });
  }

  if (!wifi_ok) {
    lv_obj_t *lbl_err = lv_label_create(scr_ota_browser);
    char err_buf[64];
    strncpy(err_buf, T(STR_OTA_NO_WIFI), sizeof(err_buf) - 1);
    err_buf[sizeof(err_buf) - 1] = '\0';
    lv_label_set_text(lbl_err, err_buf);
    lv_obj_set_style_text_color(lbl_err, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_err, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl_err, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_err, LV_ALIGN_CENTER, 0, 0);
    return;
  }

  char ip_buf[64];
  IPAddress ip = wifiManagerLocalIP();
  if (ip == IPAddress(0,0,0,0) && wifi_ok) {
    // Only happens right after connecting. No lv_timer_handler() in here:
    // this screen is now also opened from button callbacks, and running the
    // LVGL handler from inside one would dispatch touch events again while
    // the screen is half built.
    unsigned long t = millis();
    while (wifiManagerLocalIP() == IPAddress(0,0,0,0) && millis() - t < 3000) {
      delay(50);
    }
    ip = wifiManagerLocalIP();
  }
  snprintf(ip_buf, sizeof(ip_buf), "http://%s/", ip.toString().c_str());

  char hint_buf[192];
  const char* hint_src = !showsCredentials() ? T(STR_OTA_OPEN_BROWSER)
                       : backendIsBamBuddy()  ? T(STR_WEB_SETUP_HINT_BB)
                                              : T(STR_WEB_SETUP_HINT);
  strncpy(hint_buf, hint_src, sizeof(hint_buf) - 1);
  hint_buf[sizeof(hint_buf) - 1] = '\0';

  lv_obj_t *lbl_hint = lv_label_create(scr_ota_browser);
  lv_label_set_text(lbl_hint, hint_buf);
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint, 440);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, showsCredentials() ? 50 : 58);

  lv_obj_t *lbl_ip = lv_label_create(scr_ota_browser);
  lv_label_set_text(lbl_ip, ip_buf);
  lv_obj_set_style_text_color(lbl_ip, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_ip, &lv_font_montserrat_ext_20, 0);
  lv_obj_align(lbl_ip, LV_ALIGN_TOP_MID, 0, showsCredentials() ? 108 : 80);

  if (showsCredentials()) {
    if (backendIsBamBuddy()) {
      // One credential, so one row - and it is left where the FilaMan pair
      // starts rather than centred between them, which would make the screen
      // jump when switching backends.
      s_key_shown   = (bambuddyApiKey()[0] != '\0');
      s_token_shown = false;
      s_lbl_key_val   = addCredentialRow(scr_ota_browser, 158, T(STR_BACKEND_APIKEY),
                                         s_key_shown);
      s_lbl_token_val = nullptr;
    } else {
      s_key_shown   = (filamanApiKey()[0]      != '\0');
      s_token_shown = (filamanDeviceToken()[0] != '\0');
      s_lbl_key_val   = addCredentialRow(scr_ota_browser, 158, T(STR_BACKEND_APIKEY),
                                         s_key_shown);
      s_lbl_token_val = addCredentialRow(scr_ota_browser, 192, T(STR_BACKEND_DEVICE_TOKEN),
                                         s_token_shown);
    }

    if (s_web_ctx == WEB_CTX_SETUP) {
      lv_obj_t *btn_done = lv_btn_create(scr_ota_browser);
      lv_obj_set_size(btn_done, 200, 48);
      lv_obj_align(btn_done, LV_ALIGN_BOTTOM_MID, 0, -20);
      lv_obj_set_style_bg_color(btn_done, lv_color_hex(0x1a3020), 0);
      lv_obj_set_style_bg_color(btn_done, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
      lv_obj_set_style_radius(btn_done, 8, 0);
      lv_obj_set_style_shadow_width(btn_done, 0, 0);
      lv_obj_set_style_border_width(btn_done, 0, 0);
      lv_obj_add_event_cb(btn_done, [](lv_event_t *e){
        logSD("BTN: Web interface -> Setup done");
        // Deferred: showMainScreen() deletes this very screen, which must not
        // happen while its own button callback is still running.
        finish_setup_pending = true;
      }, LV_EVENT_CLICKED, NULL);
      lv_obj_t *lbl_done = lv_label_create(btn_done);
      char done_buf[24];
      strncpy(done_buf, T(STR_BTN_FINISH), sizeof(done_buf) - 1);
      done_buf[sizeof(done_buf) - 1] = '\0';
      lv_label_set_text(lbl_done, done_buf);
      lv_obj_set_style_text_color(lbl_done, lv_color_hex(0x40c080), 0);
      lv_obj_set_style_text_font(lbl_done, &lv_font_montserrat_ext_16, 0);
      lv_obj_center(lbl_done);
    }
    return;
  }

  // Only the firmware context continues below: the .bin hint, the upload
  // status and the stop button make no sense when the browser is opened to
  // edit drying thresholds.
  if (!isFirmwareContext()) return;

  lv_obj_t *lbl_hint2 = lv_label_create(scr_ota_browser);
  char file_buf[160];
  strncpy(file_buf, T(STR_OTA_FILE_HINT), sizeof(file_buf) - 1);
  file_buf[sizeof(file_buf) - 1] = '\0';
  lv_label_set_text(lbl_hint2, file_buf);
  lv_obj_set_style_text_color(lbl_hint2, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_hint2, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_hint2, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_hint2, LV_ALIGN_TOP_MID, 0, 112);
  lv_label_set_long_mode(lbl_hint2, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint2, 440);

  lbl_ota_status = lv_label_create(scr_ota_browser);
  char wait_buf[64];
  strncpy(wait_buf, T(STR_OTA_WAITING), sizeof(wait_buf) - 1);
  wait_buf[sizeof(wait_buf) - 1] = '\0';
  lv_label_set_text(lbl_ota_status, wait_buf);
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
  char stop_buf[32];
  strncpy(stop_buf, T(STR_BTN_STOP_SERVER), sizeof(stop_buf) - 1);
  stop_buf[sizeof(stop_buf) - 1] = '\0';
  lv_label_set_text(lbl_stop, stop_buf);
  lv_obj_set_style_text_color(lbl_stop, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_stop, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_stop);
}
