#include "web_screen.h"
#include "navigation.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "system_screen.h"
#include "services/web_access.h"
#include "services/wifi_manager.h"
#include "theme.h"
#include "ui_common.h"

// Web access lives here rather than on the theme screen: the master switch and
// the firmware-upload gate are network and system settings, not appearance
// ones. Only the theme editor's own gate has anything to do with colours, and
// keeping all three together makes the exposure reviewable in one place.

lv_obj_t *scr_web = nullptr;

static lv_obj_t* toggle(int x, int y, int w, const char *label, bool on,
                        lv_event_cb_t cb) {
  lv_obj_t *b = lv_btn_create(scr_web);
  lv_obj_set_size(b, w, 44);
  lv_obj_set_pos(b, x, y);
  lv_obj_set_style_bg_color(b, on ? tc(TH_ACCENT) : tc(TH_SURFACE_2), 0);
  lv_obj_set_style_radius(b, 8, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_border_width(b, 0, 0);
  lv_obj_add_event_cb(b, cb, LV_EVENT_CLICKED, nullptr);

  lv_obj_t *l = lv_label_create(b);
  lv_label_set_text(l, label);
  lv_obj_set_style_text_color(l, on ? tc(TH_ON_ACCENT) : tc(TH_TEXT), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(l, LV_ALIGN_LEFT_MID, 12, 0);

  lv_obj_t *s = lv_label_create(b);
  lv_label_set_text(s, on ? "ON" : "OFF");
  lv_obj_set_style_text_color(s, on ? tc(TH_ON_ACCENT) : tc(TH_TEXT_MUTED), 0);
  lv_obj_set_style_text_font(s, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(s, LV_ALIGN_RIGHT_MID, -12, 0);
  return b;
}

static void note(int y, const char *txt) {
  lv_obj_t *l = lv_label_create(scr_web);
  lv_label_set_text(l, txt);
  lv_obj_set_style_text_color(l, tc(TH_TEXT_DIM), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_12, 0);
  lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(l, 456);
  lv_obj_set_pos(l, 12, y);
}

void buildWebScreen() {
  logSD("BUILD: WebScreen");
  releaseScreen(&scr_web);
  scr_web = buildOverlayScreen(&scr_web);
  buildSubHeader(scr_web, T(STR_WEB_TITLE),
    [](lv_event_t *e){ logSD("BTN: Back -> System");
                       buildSystemScreen();
                       hideAllOverlays();
                       lv_obj_clear_flag(scr_system, LV_OBJ_FLAG_HIDDEN); });

  toggle(12, 50, 456, T(STR_WEB_SERVER), webMasterEnabled(), [](lv_event_t *e) {
    webSetMasterEnabled(!webMasterEnabled());
    buildWebScreen();
    lv_obj_clear_flag(scr_web, LV_OBJ_FLAG_HIDDEN);
  });

  char url[52];
  if (!webMasterEnabled()) snprintf(url, sizeof(url), "Off. Nothing answers on port 80.");
  else if (!wifi_ok)       snprintf(url, sizeof(url), "Waiting for WiFi.");
  else snprintf(url, sizeof(url), "http://%s  shows status and these switches.",
                wifiManagerLocalIP().toString().c_str());
  note(98, url);

  toggle(12, 124, 456, T(STR_WEB_MAINT), webMaintenanceEnabled(),
    [](lv_event_t *e) {
      webSetMaintenanceEnabled(!webMaintenanceEnabled());
      buildWebScreen();
      lv_obj_clear_flag(scr_web, LV_OBJ_FLAG_HIDDEN);
    });
  note(172, T(STR_WEB_MAINT_HINT));

  toggle(12, 212, 456, T(STR_WEB_THEME_EDITOR), webThemeEnabled(), [](lv_event_t *e) {
    webSetThemeEnabled(!webThemeEnabled());
    buildWebScreen();
    lv_obj_clear_flag(scr_web, LV_OBJ_FLAG_HIDDEN);
  });
  note(260, T(STR_WEB_THEME_HINT));
}

void showWebScreen() {
  buildWebScreen();
  hideAllOverlays();
  lv_obj_clear_flag(scr_web, LV_OBJ_FLAG_HIDDEN);
}
