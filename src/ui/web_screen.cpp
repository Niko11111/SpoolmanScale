#include "web_screen.h"
#include "navigation.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/mdns_service.h"
#include "services/wifi_manager.h"
#include "system_screen.h"
#include "web/web_access.h"
#include "web/web_server.h"
#include "ui_common.h"

lv_obj_t *scr_web = nullptr;

static lv_obj_t* toggle(int x, int y, int w, const char *label, bool on,
                        lv_event_cb_t cb) {
  lv_obj_t *b = lv_btn_create(scr_web);
  lv_obj_set_size(b, w, 44);
  lv_obj_set_pos(b, x, y);
  lv_obj_set_style_bg_color(b, on ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_radius(b, 8, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_border_width(b, 0, 0);
  lv_obj_add_event_cb(b, cb, LV_EVENT_CLICKED, nullptr);

  lv_obj_t *l = lv_label_create(b);
  lv_label_set_text(l, label);
  lv_obj_set_style_text_color(l, on ? lv_color_hex(0x000000) : lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(l, LV_ALIGN_LEFT_MID, 12, 0);

  lv_obj_t *s = lv_label_create(b);
  lv_label_set_text(s, on ? "ON" : "OFF");
  lv_obj_set_style_text_color(s, on ? lv_color_hex(0x000000) : lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(s, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(s, LV_ALIGN_RIGHT_MID, -12, 0);
  return b;
}

static void note(int y, const char *txt) {
  lv_obj_t *l = lv_label_create(scr_web);
  lv_label_set_text(l, txt);
  lv_obj_set_style_text_color(l, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_12, 0);
  lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(l, 456);
  lv_obj_set_pos(l, 12, y);
}

void buildWebScreen() {
  logSD("BUILD: WebScreen");
  releaseScreen(&scr_web);
  scr_web = buildOverlayScreen();
  buildSubHeader(scr_web, T(STR_WEB_TITLE),
    [](lv_event_t *e){ logSD("BTN: Back -> System");
                       buildSystemScreen();
                       hideAllOverlays();
                       lv_obj_clear_flag(scr_system, LV_OBJ_FLAG_HIDDEN); });

  toggle(12, 50, 456, T(STR_WEB_SERVER), webMasterEnabled(), [](lv_event_t *e) {
    webSetMasterEnabled(!webMasterEnabled());
    // The switch only records the wish. Ask the one owner of the socket to
    // act on it now, so the line below already tells the truth about whether
    // the address is reachable.
    webServerSyncState();
    buildWebScreen();
    lv_obj_clear_flag(scr_web, LV_OBJ_FLAG_HIDDEN);
  });

  char url[72];
  if (!webMasterEnabled()) {
    // STR_WEB_SERVER_HINT existed from the start and was never used - the
    // line was built in English right here instead, so a German device said
    // it in English.
    strncpy(url, T(STR_WEB_SERVER_HINT), sizeof(url) - 1);
    url[sizeof(url) - 1] = '\0';
  } else if (!wifi_ok) {
    snprintf(url, sizeof(url), "Waiting for WiFi.");
  } else if (mdnsRunning()) {
    snprintf(url, sizeof(url), "http://%s.local  shows status and these switches.",
             mdnsHostname());
  } else {
    snprintf(url, sizeof(url), "http://%s  shows status and these switches.",
             wifiManagerLocalIP().toString().c_str());
  }
  note(98, url);

  // Two switches rather than one. Changing a list limit and flashing firmware
  // used to hang on the same bit, which meant anyone who wanted to edit the
  // drying thresholds from the browser had to open the firmware upload to the
  // network as well.
  toggle(12, 124, 456, T(STR_WEB_CONFIG), webConfigEnabled(),
    [](lv_event_t *e) {
      webSetConfigEnabled(!webConfigEnabled());
      buildWebScreen();
      lv_obj_clear_flag(scr_web, LV_OBJ_FLAG_HIDDEN);
    });
  note(172, T(STR_WEB_CONFIG_HINT));

  toggle(12, 210, 456, T(STR_WEB_MAINT), webMaintenanceEnabled(),
    [](lv_event_t *e) {
      webSetMaintenanceEnabled(!webMaintenanceEnabled());
      buildWebScreen();
      lv_obj_clear_flag(scr_web, LV_OBJ_FLAG_HIDDEN);
    });
  note(258, T(STR_WEB_MAINT_HINT));
}

void showWebScreen() {
  buildWebScreen();
  hideAllOverlays();
  lv_obj_clear_flag(scr_web, LV_OBJ_FLAG_HIDDEN);
}
