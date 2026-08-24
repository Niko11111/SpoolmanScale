#include "web_screen.h"
#include "navigation.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "info_popup.h"
#include "lang.h"
#include "services/device_name.h"
#include "services/wifi_manager.h"
#include "system_screen.h"
#include "ui_common.h"
#include "web/web_access.h"
#include "web/web_server.h"

lv_obj_t *scr_web = nullptr;

// One helper for all three rows. They differ only in which switch they read
// and write, so the row itself is built once - the hand rolled toggles this
// replaces looked nothing like the rest of the device.
static void addGateRow(lv_obj_t *list, const char *ico, int title_id,
                       const char *sub, int info_id, bool on,
                       lv_event_cb_t on_click) {
  char buf_t[40];
  strncpy(buf_t, T(title_id), sizeof(buf_t) - 1);
  buf_t[sizeof(buf_t) - 1] = '\0';

  lv_obj_t *help = nullptr;
  lv_obj_t *btn = makeListBtn(list, ico, buf_t, sub, on, &help);
  if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                INFO_POPUP_ARG(title_id, info_id));

  // Last child is the arrow, which a toggle turns into ON/OFF.
  lv_obj_t *arr = lv_obj_get_child(btn, -1);
  if (arr) {
    char buf_v[8];
    strncpy(buf_v, T(on ? STR_ON : STR_OFF), sizeof(buf_v) - 1);
    buf_v[sizeof(buf_v) - 1] = '\0';
    lv_label_set_text(arr, buf_v);
    lv_obj_set_style_text_color(arr,
      lv_color_hex(on ? 0x28d49a : 0x4a6fa0), 0);
    lv_obj_set_style_text_font(arr, &lv_font_montserrat_ext_14, 0);
  }
  lv_obj_add_event_cb(btn, on_click, LV_EVENT_CLICKED, NULL);
}

// Rebuilt from the callback of a row it owns, so the deletion has to wait for
// the next loop pass - releaseScreen() uses lv_obj_del_async() for exactly
// this, which is why the rebuild is safe here.
static void rebuild() {
  buildWebScreen();
  lv_obj_clear_flag(scr_web, LV_OBJ_FLAG_HIDDEN);
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

  // The list body every settings screen uses. makeListBtn() never positions
  // its button and relies on the parent's flex flow.
  lv_obj_t *list = lv_obj_create(scr_web);
  lv_obj_set_size(list, 480, 263);
  lv_obj_set_pos(list, 0, 57);
  lv_obj_set_style_bg_opa(list, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_left(list, 12, 0);
  lv_obj_set_style_pad_right(list, 12, 0);
  lv_obj_set_style_pad_top(list, 6, 0);
  lv_obj_set_style_pad_bottom(list, 6, 0);
  lv_obj_set_style_pad_row(list, 6, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(list, LV_OBJ_FLAG_SCROLL_ELASTIC);

  // The master switch carries the address as its subtitle rather than a
  // separate note underneath: it is the one line on this screen a user is
  // here to read, and makeListBtn() turns the subtitle green while the row
  // is active, so it reads as "this is live" instead of as a caption.
  char addr[56];
  if (!webMasterEnabled()) {
    strncpy(addr, T(STR_WEB_SERVER_HINT), sizeof(addr) - 1);
    addr[sizeof(addr) - 1] = '\0';
  } else if (!wifi_ok) {
    strncpy(addr, T(STR_WIFI_STATUS_DISCONNECTED), sizeof(addr) - 1);
    addr[sizeof(addr) - 1] = '\0';
  } else {
    deviceBrowserUrl(addr, sizeof(addr));
  }

  addGateRow(list, LV_SYMBOL_WIFI, STR_WEB_SERVER, addr, STR_WEB_SERVER_INFO,
    webMasterEnabled(),
    [](lv_event_t *e) {
      logSD("BTN: Web -> master toggle");
      webSetMasterEnabled(!webMasterEnabled());
      // The switch only records the wish. Ask the one owner of the socket to
      // act on it now, so the address below already tells the truth.
      webServerSyncState();
      rebuild();
    });

  char sub_cfg[48];
  strncpy(sub_cfg, T(STR_WEB_CONFIG_SUB), sizeof(sub_cfg) - 1);
  sub_cfg[sizeof(sub_cfg) - 1] = '\0';
  addGateRow(list, LV_SYMBOL_SETTINGS, STR_WEB_CONFIG, sub_cfg,
    STR_WEB_CONFIG_HINT, webConfigEnabled(),
    [](lv_event_t *e) {
      logSD("BTN: Web -> config toggle");
      webSetConfigEnabled(!webConfigEnabled());
      rebuild();
    });

  char sub_mnt[48];
  strncpy(sub_mnt, T(STR_WEB_MAINT_SUB), sizeof(sub_mnt) - 1);
  sub_mnt[sizeof(sub_mnt) - 1] = '\0';
  addGateRow(list, LV_SYMBOL_DOWNLOAD, STR_WEB_MAINT, sub_mnt,
    STR_WEB_MAINT_HINT, webMaintenanceEnabled(),
    [](lv_event_t *e) {
      logSD("BTN: Web -> maintenance toggle");
      webSetMaintenanceEnabled(!webMaintenanceEnabled());
      rebuild();
    });
}

void showWebScreen() {
  buildWebScreen();
  hideAllOverlays();
  lv_obj_clear_flag(scr_web, LV_OBJ_FLAG_HIDDEN);
}
