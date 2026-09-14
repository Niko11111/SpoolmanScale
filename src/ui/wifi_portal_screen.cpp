#include "wifi_portal_screen.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "app/app_state.h"
#include "extra/libs/qrcode/lv_qrcode.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "navigation.h"
#include "services/setup_portal.h"
#include "ui_common.h"
#include "web/web_server.h"
#include "wifi_setup_screen.h"

// Two columns, one per step: a QR code in a white frame with its text below.
// The frame is the quiet zone a phone camera needs on the dark screen; the
// code itself fills its canvas almost to the edge.
#define PORTAL_QR_SIZE     120
#define PORTAL_QR_FRAME    6
#define PORTAL_COL_OFFSET  120   // column centres at 240 -/+ this
#define PORTAL_STEP_Y      48
#define PORTAL_QR_Y        70
#define PORTAL_LINE1_Y     210
#define PORTAL_LINE2_Y     230
#define PORTAL_HINT_Y      262
#define PORTAL_STATUS_Y    288
#define PORTAL_TEXT_W      440

static lv_obj_t *lbl_portal_status   = nullptr;
static bool portal_start_pending     = false;
static bool portal_close_pending     = false;
// The codes are on screen, so a portal that is gone has to take them along.
static bool portal_up_shown          = false;
static bool portal_received_shown    = false;

static lv_obj_t *portalLabel(const char *text, const lv_font_t *font, uint32_t color,
                             lv_coord_t x_ofs, lv_coord_t y) {
  lv_obj_t *l = lv_label_create(scr_wifi_portal);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_color(l, lv_color_hex(color), 0);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_align(l, LV_ALIGN_TOP_MID, x_ofs, y);
  return l;
}

static void portalQr(const char *data, lv_coord_t x_ofs) {
  lv_obj_t *frame = lv_obj_create(scr_wifi_portal);
  lv_obj_set_size(frame, PORTAL_QR_SIZE + 2 * PORTAL_QR_FRAME, PORTAL_QR_SIZE + 2 * PORTAL_QR_FRAME);
  lv_obj_align(frame, LV_ALIGN_TOP_MID, x_ofs, PORTAL_QR_Y);
  lv_obj_set_style_bg_color(frame, lv_color_hex(0xffffff), 0);
  lv_obj_set_style_border_width(frame, 0, 0);
  lv_obj_set_style_radius(frame, 4, 0);
  lv_obj_set_style_pad_all(frame, PORTAL_QR_FRAME, 0);
  lv_obj_clear_flag(frame, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *qr = lv_qrcode_create(frame, PORTAL_QR_SIZE, lv_color_hex(0x000000), lv_color_hex(0xffffff));
  if (!qr) {
    logSD("Portal: no room for a QR code in the LVGL pool");
    return;
  }
  if (lv_qrcode_update(qr, data, strlen(data)) != LV_RES_OK) {
    logSD("Portal: QR code update failed");
  }
  lv_obj_center(qr);
}

static void buildWifiPortalScreen() {
  logSD("BUILD: WifiPortalScreen");
  releaseScreen(&scr_wifi_portal);
  scr_wifi_portal = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_wifi_portal, 480, 320);
  lv_obj_set_pos(scr_wifi_portal, 0, 0);
  lv_obj_add_flag(scr_wifi_portal, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_wifi_portal, 0, 0);
  lv_obj_set_style_border_width(scr_wifi_portal, 0, 0);
  lv_obj_set_style_pad_all(scr_wifi_portal, 0, 0);
  lv_obj_clear_flag(scr_wifi_portal, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_wifi_portal, lv_color_hex(0x0a1020), 0);

  portalLabel(T(STR_PORTAL_TITLE), &lv_font_montserrat_ext_18, 0x28d49a, 0, 14);
  // Parked for the loop: going back takes the access point down, and the
  // screen this button sits on is deleted on the way.
  addBackButton(scr_wifi_portal, [](lv_event_t *e) { portal_close_pending = true; });
  addCloseButton(scr_wifi_portal);

  // In the middle while the scan runs; moves under the codes once they exist.
  lbl_portal_status = lv_label_create(scr_wifi_portal);
  lv_label_set_text(lbl_portal_status, T(STR_WIFI_SCAN));
  lv_obj_set_style_text_color(lbl_portal_status, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_portal_status, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_portal_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_portal_status, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_portal_status, PORTAL_TEXT_W);
  lv_obj_align(lbl_portal_status, LV_ALIGN_CENTER, 0, 0);
}

static void fillWifiPortalScreen() {
  char buf[96];
  char url[32];
  setupPortalUrl(url, sizeof(url));

  // Step 1: join the scale's network. The standard WiFi QR payload; neither
  // the generated name nor the generated password has a character it would
  // need escaped.
  portalLabel(T(STR_PORTAL_STEP_JOIN), &lv_font_montserrat_ext_14, 0xe8f0ff, -PORTAL_COL_OFFSET, PORTAL_STEP_Y);
  snprintf(buf, sizeof(buf), "WIFI:T:WPA;S:%s;P:%s;;", setupPortalSsid(), setupPortalPassword());
  portalQr(buf, -PORTAL_COL_OFFSET);
  snprintf(buf, sizeof(buf), T(STR_PORTAL_NET_FMT), setupPortalSsid());
  portalLabel(buf, &lv_font_montserrat_ext_14, 0xc8d8f0, -PORTAL_COL_OFFSET, PORTAL_LINE1_Y);
  snprintf(buf, sizeof(buf), T(STR_PORTAL_PASS_FMT), setupPortalPassword());
  portalLabel(buf, &lv_font_montserrat_ext_16, 0xffffff, -PORTAL_COL_OFFSET, PORTAL_LINE2_Y);

  // Step 2: the page, for a phone that does not open it by itself.
  portalLabel(T(STR_PORTAL_STEP_OPEN), &lv_font_montserrat_ext_14, 0xe8f0ff, PORTAL_COL_OFFSET, PORTAL_STEP_Y);
  portalQr(url, PORTAL_COL_OFFSET);
  portalLabel(url, &lv_font_montserrat_ext_14, 0xc8d8f0, PORTAL_COL_OFFSET, PORTAL_LINE1_Y);
  portalLabel(T(STR_PORTAL_OPENS_ITSELF), &lv_font_montserrat_ext_12, 0x4a6fa0, PORTAL_COL_OFFSET, PORTAL_LINE2_Y + 2);

  lv_obj_t *hint = portalLabel(T(STR_PORTAL_ANDROID_HINT), &lv_font_montserrat_ext_12, 0x4a6fa0, 0, PORTAL_HINT_Y);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(hint, PORTAL_TEXT_W);
  lv_obj_align(hint, LV_ALIGN_TOP_MID, 0, PORTAL_HINT_Y);

  if (lbl_portal_status) {
    lv_label_set_text(lbl_portal_status, T(STR_PORTAL_WAITING));
    lv_obj_set_style_text_font(lbl_portal_status, &lv_font_montserrat_ext_14, 0);
    lv_obj_align(lbl_portal_status, LV_ALIGN_TOP_MID, 0, PORTAL_STATUS_Y);
  }
}

void showWifiPortalScreen() {
  logSD("SHOW: WifiPortalScreen");
  logSD("UI: Screen -> WifiPortal");
  hideAllOverlays();
  closeWifiPortalScreen();
  buildWifiPortalScreen();
  lv_obj_clear_flag(scr_wifi_portal, LV_OBJ_FLAG_HIDDEN);
  // The scan takes seconds and belongs in the loop, not in the button.
  portal_start_pending = true;
}

void closeWifiPortalScreen() {
  lbl_portal_status     = nullptr;
  portal_start_pending  = false;
  portal_up_shown       = false;
  portal_received_shown = false;
  releaseScreen(&scr_wifi_portal);
}

void handleWifiPortalDeferredActions() {
  if (portal_close_pending) {
    portal_close_pending = false;
    setupPortalStop();
    webServerSyncState();
    closeWifiPortalScreen();
    showWifiSetupScreen();
    return;
  }

  const bool visible = scr_wifi_portal && !lv_obj_has_flag(scr_wifi_portal, LV_OBJ_FLAG_HIDDEN);

  if (portal_start_pending) {
    portal_start_pending = false;
    if (!visible) return;
    lv_timer_handler();   // the scan line is on screen before the scan blocks
    if (setupPortalStart()) {
      webServerSyncState();
      fillWifiPortalScreen();
      portal_up_shown = true;
    } else if (lbl_portal_status) {
      lv_label_set_text(lbl_portal_status, T(STR_PORTAL_START_FAILED));
      lv_obj_set_style_text_color(lbl_portal_status, lv_color_hex(0xff8080), 0);
    }
    return;
  }

  // The form was sent and the access point has closed: on to the connect,
  // exactly as if the password had been typed here.
  char ssid[33];
  char pass[65];
  if (setupPortalTakeCredentials(ssid, sizeof(ssid), pass, sizeof(pass))) {
    webServerSyncState();
    closeWifiPortalScreen();
    wifiSetupConnectWith(ssid, pass);
    memset(pass, 0, sizeof(pass));
    return;
  }

  if (visible && setupPortalSubmitted() && !portal_received_shown && lbl_portal_status) {
    portal_received_shown = true;
    lv_label_set_text(lbl_portal_status, T(STR_PORTAL_RECEIVED));
    lv_obj_set_style_text_color(lbl_portal_status, lv_color_hex(0x28d49a), 0);
  }

  // Whatever took the screen away also takes the access point down.
  if (setupPortalActive() && !visible) {
    setupPortalStop();
    webServerSyncState();
    return;
  }
  // And the other way round: Improv ended the portal under the open screen.
  if (visible && portal_up_shown && !setupPortalActive()) {
    closeWifiPortalScreen();
    showWifiSetupScreen();
  }
}
