#include "connection_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/ble_service.h"
#include "lang.h"
#include "theme.h"
#include "ui_common.h"


void closeConnectionScreen() {
  if (scr_connection) { lv_obj_del(scr_connection); scr_connection = nullptr; }
}

void buildConnectionScreen() {
  logSD("BUILD: ConnectionScreen");
  if (sd_verbose) logSD("[verbose] buildConnectionScreen: start");
  releaseScreen(&scr_connection);
  scr_connection = buildOverlayScreen();
  buildSubHeader(scr_connection, T(STR_TILE_CONNECTION),
    [](lv_event_t *e){ logSD("BTN: Back -> Settings"); showSettingsScreen(); });

  // Three rows of 80 px tiles. WiFi and Bluetooth share the first row, which
  // is what makes room for the fourth: the way straight into the current
  // filament manager's options, one tap shorter than through its screen.
  const int BTN_W = 456, BTN_H = 80, BTN_X = 12;
  const int HALF_W = 222, HALF_X2 = BTN_X + HALF_W + 12;   // 222 + 12 + 222 = 456
  const int HALF_SUB_W = HALF_W - 16;                       // the subtitle's room on a half tile
  const int BTN_Y[] = { 54, 142, 230 };

  // WiFi. A small menu of its own behind the tile, setup and status, so the
  // tile stays what it says: the way to the WiFi settings.
  lv_obj_t *btn_wifi = lv_btn_create(scr_connection);
  lv_obj_set_size(btn_wifi, HALF_W, BTN_H);
  lv_obj_set_pos(btn_wifi, BTN_X, BTN_Y[0]);
  lv_obj_set_style_bg_color(btn_wifi, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(btn_wifi, lv_color_hex(UI_COL_ROW_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_wifi, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(btn_wifi, 0, 0);
  lv_obj_set_style_border_width(btn_wifi, 1, 0);
  lv_obj_set_style_border_color(btn_wifi, lv_color_hex(UI_COL_ROW_PRESSED), 0);
  { lv_obj_t *ico = lv_label_create(btn_wifi);
    lv_label_set_text(ico, LV_SYMBOL_WIFI);
    lv_obj_set_style_text_color(ico, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_set_style_text_font(ico, UI_FONT_ICON, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_wifi);
    lv_label_set_text(lbl, T(STR_BTN_WIFI_SETTINGS));
    lv_obj_set_style_text_color(lbl, lv_color_hex(UI_COL_INK), 0);
    lv_obj_set_style_text_font(lbl, UI_FONT_TITLE, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_wifi);
    lv_label_set_text(sub, cfg_wifi_ssid[0] ? cfg_wifi_ssid : T(STR_BTN_WIFI_NONE));
    lv_obj_set_style_text_color(sub, lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_set_style_text_font(sub, UI_FONT_SMALL, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    // An SSID can be 32 characters; on a half tile it is cut with dots.
    lv_obj_set_width(sub, HALF_SUB_W);
    lv_label_set_long_mode(sub, LV_LABEL_LONG_DOT);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_wifi, [](lv_event_t *e){
    logSD("BTN: Conn -> WiFi menu");
    show_wifi_menu_pending = true;
  }, LV_EVENT_CLICKED, NULL);

  // Bluetooth. The subtitle is the master switch, so the state can be read
  // here without opening the screen.
  lv_obj_t *btn_bt = lv_btn_create(scr_connection);
  lv_obj_set_size(btn_bt, HALF_W, BTN_H);
  lv_obj_set_pos(btn_bt, HALF_X2, BTN_Y[0]);
  lv_obj_set_style_bg_color(btn_bt, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(btn_bt, lv_color_hex(UI_COL_ROW_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_bt, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(btn_bt, 0, 0);
  lv_obj_set_style_border_width(btn_bt, 1, 0);
  lv_obj_set_style_border_color(btn_bt, lv_color_hex(UI_COL_ROW_PRESSED), 0);
  { lv_obj_t *ico = lv_label_create(btn_bt);
    lv_label_set_text(ico, LV_SYMBOL_BLUETOOTH);
    lv_obj_set_style_text_color(ico, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_set_style_text_font(ico, UI_FONT_ICON, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_bt);
    lv_label_set_text(lbl, T(STR_BT_TITLE));
    lv_obj_set_style_text_color(lbl, lv_color_hex(UI_COL_INK), 0);
    lv_obj_set_style_text_font(lbl, UI_FONT_TITLE, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_bt);
    lv_label_set_text(sub, T(bleEnabled() ? STR_ON : STR_OFF));
    lv_obj_set_style_text_color(sub, lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_set_style_text_font(sub, UI_FONT_SMALL, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(sub, HALF_SUB_W);
    lv_label_set_long_mode(sub, LV_LABEL_LONG_DOT);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_bt, [](lv_event_t *e){
    logSD("BTN: Conn -> Bluetooth");
    show_bluetooth_pending = true;
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_sp = lv_btn_create(scr_connection);
  lv_obj_set_size(btn_sp, BTN_W, BTN_H);
  lv_obj_set_pos(btn_sp, BTN_X, BTN_Y[1]);
  lv_obj_set_style_bg_color(btn_sp, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_sp, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_sp, 10, 0);
  lv_obj_set_style_shadow_width(btn_sp, 0, 0);
  lv_obj_set_style_border_width(btn_sp, 1, 0);
  lv_obj_set_style_border_color(btn_sp, lv_color_hex(0x1a3050), 0);
  { lv_obj_t *ico = lv_label_create(btn_sp);
    lv_label_set_text(ico, LV_SYMBOL_SETTINGS);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    char buf_backend[32];
    copyT(buf_backend, sizeof(buf_backend), STR_BACKEND_TITLE);
    lv_obj_t *lbl = lv_label_create(btn_sp);
    lv_label_set_text(lbl, buf_backend);
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    // Shows which backend is active and where it lives, so the user does
    // not have to open the screen to find out.
    char buf_sub[80];
    const char *host = backendHost();
    snprintf(buf_sub, sizeof(buf_sub), "%s  %s",
      backendName(),
      (host && host[0]) ? host : T(STR_BTN_WIFI_NONE));
    lv_obj_t *sub = lv_label_create(btn_sp);
    lv_label_set_text(sub, buf_sub);
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_sp, [](lv_event_t *e){
    logSD("BTN: Conn -> Backend");
    show_backend_pending = true;
  }, LV_EVENT_CLICKED, NULL);

  // Straight into the active filament manager's options. The same screen the
  // "More options" button on the backend screen opens, one tap earlier; the
  // tile says which backend's options those are.
  lv_obj_t *btn_opts = lv_btn_create(scr_connection);
  lv_obj_set_size(btn_opts, BTN_W, BTN_H);
  lv_obj_set_pos(btn_opts, BTN_X, BTN_Y[2]);
  lv_obj_set_style_bg_color(btn_opts, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(btn_opts, lv_color_hex(UI_COL_ROW_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_opts, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(btn_opts, 0, 0);
  lv_obj_set_style_border_width(btn_opts, 1, 0);
  lv_obj_set_style_border_color(btn_opts, lv_color_hex(UI_COL_ROW_PRESSED), 0);
  { lv_obj_t *ico = lv_label_create(btn_opts);
    lv_label_set_text(ico, LV_SYMBOL_LIST);
    lv_obj_set_style_text_color(ico, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_set_style_text_font(ico, UI_FONT_ICON, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    char buf_opts[40];
    copyT(buf_opts, sizeof(buf_opts), STR_BTN_MORE_OPTIONS);
    lv_obj_t *lbl = lv_label_create(btn_opts);
    lv_label_set_text(lbl, buf_opts);
    lv_obj_set_style_text_color(lbl, lv_color_hex(UI_COL_INK), 0);
    lv_obj_set_style_text_font(lbl, UI_FONT_TITLE, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_opts);
    lv_label_set_text(sub, backendName());
    lv_obj_set_style_text_color(sub, lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_set_style_text_font(sub, UI_FONT_SMALL, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_opts, [](lv_event_t *e){
    logSD("BTN: Conn -> Backend options");
    if (backendIsFilaMan())       show_filaman_options_pending  = true;
    else if (backendIsBamBuddy()) show_bambuddy_options_pending = true;
    else                          show_spoolman_options_pending = true;
  }, LV_EVENT_CLICKED, NULL);

  if (sd_verbose) logSD("[verbose] buildConnectionScreen: done");
}
