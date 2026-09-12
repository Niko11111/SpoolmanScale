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

// The password numpad and what has been typed into it so far.
static lv_obj_t *s_pin_scr = nullptr;
static lv_obj_t *s_pin_lbl = nullptr;
static char      s_pin[WEB_PASS_MAX + 1] = "";

void webPinScreenHide()  { if (s_pin_scr) lv_obj_add_flag(s_pin_scr, LV_OBJ_FLAG_HIDDEN); }
void webPinScreenClose() { releaseScreen(&s_pin_scr); s_pin_lbl = nullptr; }

static void rebuild();

static void pinRefresh() {
  if (!s_pin_lbl) return;
  lv_label_set_text(s_pin_lbl, s_pin[0] ? s_pin : "-");
}

// The same 3x4 pad the drying thresholds use. Digits only: it is what the
// device can type, and it is enough - this is a lock on a LAN interface, not
// an account.
static void buildWebPinScreen() {
  webPinScreenClose();
  s_pin[0] = '\0';
  s_pin_scr = buildOverlayScreen();

  char title[40];
  strncpy(title, T(STR_WEB_PASS_TITLE), sizeof(title) - 1);
  title[sizeof(title) - 1] = '\0';
  buildSubHeader(s_pin_scr, title, [](lv_event_t *e){
    logSD("BTN: Back -> Web (password untouched)");
    webPinScreenClose();
    rebuild();
  });

  lv_obj_t *hint = lv_label_create(s_pin_scr);
  { char hb[96];
    strncpy(hb, T(STR_WEB_PASS_HINT), sizeof(hb) - 1);
    hb[sizeof(hb) - 1] = '\0';
    lv_label_set_text(hint, hb); }
  lv_obj_set_style_text_color(hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(hint, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(hint, 464);
  lv_obj_set_pos(hint, 8, 58);

  lv_obj_t *val_box = lv_obj_create(s_pin_scr);
  lv_obj_set_size(val_box, 380, 40);
  lv_obj_set_pos(val_box, 50, 80);
  lv_obj_set_style_bg_color(val_box, lv_color_hex(0x050f1e), 0);
  lv_obj_set_style_border_color(val_box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(val_box, 1, 0);
  lv_obj_set_style_radius(val_box, 8, 0);
  lv_obj_clear_flag(val_box, LV_OBJ_FLAG_SCROLLABLE);
  s_pin_lbl = lv_label_create(val_box);
  lv_obj_set_style_text_color(s_pin_lbl, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(s_pin_lbl, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(s_pin_lbl, LV_ALIGN_CENTER, 0, 0);
  pinRefresh();

  const int NP_W = 136, NP_H = 36, NP_GAP = 4;
  const int NP_X0 = (480 - 3 * NP_W - 2 * NP_GAP) / 2;
  const int NP_Y0 = 128;
  static const char *keys[] = { "1","2","3","4","5","6","7","8","9","DEL","0","OK" };
  for (int i = 0; i < 12; i++) {
    const int col = i % 3, row = i / 3;
    const bool is_del = (strcmp(keys[i], "DEL") == 0);
    const bool is_ok  = (strcmp(keys[i], "OK")  == 0);
    lv_obj_t *kb = lv_btn_create(s_pin_scr);
    lv_obj_set_size(kb, NP_W, NP_H);
    lv_obj_set_pos(kb, NP_X0 + col * (NP_W + NP_GAP), NP_Y0 + row * (NP_H + NP_GAP));
    lv_obj_set_style_bg_color(kb, is_del ? lv_color_hex(0x1a1020) :
                                  is_ok  ? lv_color_hex(0x1a4030) :
                                           lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(kb, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
    lv_obj_set_style_radius(kb, 6, 0);
    lv_obj_set_style_shadow_width(kb, 0, 0);
    lv_obj_set_style_border_width(kb, 1, 0);
    lv_obj_set_style_border_color(kb, is_ok ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a3050), 0);
    lv_obj_t *kl = lv_label_create(kb);
    lv_label_set_text(kl, is_ok ? LV_SYMBOL_OK : keys[i]);
    lv_obj_set_style_text_color(kl, is_del ? lv_color_hex(0xe04040) :
                                     is_ok  ? lv_color_hex(0x28d49a) :
                                              lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(kl, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(kl, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_user_data(kb, (void*)keys[i]);
    lv_obj_add_event_cb(kb, [](lv_event_t *e){
      const char *k = (const char*)lv_obj_get_user_data(lv_event_get_target(e));
      if (!k || !s_pin_lbl) return;
      const size_t len = strlen(s_pin);
      if (strcmp(k, "DEL") == 0) {
        if (len) s_pin[len - 1] = '\0';
      } else if (strcmp(k, "OK") == 0) {
        // Empty removes the password; too short counts as empty, and
        // webSetPassword() says so in the log. NVS write from a callback is
        // the pattern every settings row here follows - one small key.
        webSetPassword(s_pin);
        webPinScreenClose();
        rebuild();
        return;
      } else if (len < WEB_PASS_MAX) {
        s_pin[len] = k[0];
        s_pin[len + 1] = '\0';
      }
      pinRefresh();
    }, LV_EVENT_CLICKED, NULL);
  }
}

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

  // The lock on the two rows above. Not a toggle: the row opens the numpad,
  // and the subtitle says whether a password is set. Green while it is, so
  // the state reads the same way the switches do.
  {
    char buf_t[40];
    strncpy(buf_t, T(STR_WEB_PASS), sizeof(buf_t) - 1);
    buf_t[sizeof(buf_t) - 1] = '\0';
    char buf_s[56];
    strncpy(buf_s, T(webHasPassword() ? STR_WEB_PASS_SET : STR_WEB_PASS_UNSET),
            sizeof(buf_s) - 1);
    buf_s[sizeof(buf_s) - 1] = '\0';
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_KEYBOARD, buf_t, buf_s,
                                webHasPassword(), &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_WEB_PASS, STR_WEB_PASS_INFO));
    lv_obj_add_event_cb(btn, [](lv_event_t *e) {
      logSD("BTN: Web -> password numpad");
      buildWebPinScreen();
      hideAllOverlays();
      if (s_pin_scr) lv_obj_clear_flag(s_pin_scr, LV_OBJ_FLAG_HIDDEN);
    }, LV_EVENT_CLICKED, NULL);
  }
}

void showWebScreen() {
  buildWebScreen();
  hideAllOverlays();
  lv_obj_clear_flag(scr_web, LV_OBJ_FLAG_HIDDEN);
}
