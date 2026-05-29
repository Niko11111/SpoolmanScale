#include "connection_screen.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui_common.h"

extern char cfg_wifi_ssid[33];
extern char cfg_spoolman_ip[64];
extern bool show_spoolman_pending;
extern lv_obj_t *scr_connection;

void showSettingsScreen();
void showWifiSetupScreen();
void showExtraFieldsScreen(bool is_setup_flow);

void buildConnectionScreen() {
  logSD("BUILD: ConnectionScreen");
  if (sd_verbose) logSD("[verbose] buildConnectionScreen: start");
  scr_connection = buildOverlayScreen();
  buildSubHeader(scr_connection, T(STR_TILE_CONNECTION),
    [](lv_event_t *e){ logSD("BTN: Back -> Settings"); showSettingsScreen(); });

  const int BTN_W = 456, BTN_H = 80, BTN_X = 12;
  const int BTN_Y[] = { 54, 142, 230 };

  lv_obj_t *btn_wifi = lv_btn_create(scr_connection);
  lv_obj_set_size(btn_wifi, BTN_W, BTN_H);
  lv_obj_set_pos(btn_wifi, BTN_X, BTN_Y[0]);
  lv_obj_set_style_bg_color(btn_wifi, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_wifi, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_wifi, 10, 0);
  lv_obj_set_style_shadow_width(btn_wifi, 0, 0);
  lv_obj_set_style_border_width(btn_wifi, 1, 0);
  lv_obj_set_style_border_color(btn_wifi, lv_color_hex(0x1a3050), 0);
  { lv_obj_t *ico = lv_label_create(btn_wifi);
    lv_label_set_text(ico, LV_SYMBOL_WIFI);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_wifi);
    lv_label_set_text(lbl, T(STR_BTN_WIFI_SETTINGS));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_wifi);
    lv_label_set_text(sub, cfg_wifi_ssid[0] ? cfg_wifi_ssid : T(STR_BTN_WIFI_NONE));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_wifi, [](lv_event_t *e){ logSD("BTN: Conn -> WifiSetup"); showWifiSetupScreen(); }, LV_EVENT_CLICKED, NULL);

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
    lv_obj_t *lbl = lv_label_create(btn_sp);
    lv_label_set_text(lbl, "Spoolman IP");
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_sp);
    lv_label_set_text(sub, cfg_spoolman_ip[0] ? cfg_spoolman_ip : T(STR_BTN_WIFI_NONE));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_sp, [](lv_event_t *e){
    logSD("BTN: Conn -> Spoolman IP");
    show_spoolman_pending = true;
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_ef = lv_btn_create(scr_connection);
  lv_obj_set_size(btn_ef, BTN_W, BTN_H);
  lv_obj_set_pos(btn_ef, BTN_X, BTN_Y[2]);
  lv_obj_set_style_bg_color(btn_ef, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_ef, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ef, 10, 0);
  lv_obj_set_style_shadow_width(btn_ef, 0, 0);
  lv_obj_set_style_border_width(btn_ef, 1, 0);
  lv_obj_set_style_border_color(btn_ef, lv_color_hex(0x1a3050), 0);
  { lv_obj_t *ico = lv_label_create(btn_ef);
    lv_label_set_text(ico, LV_SYMBOL_LIST);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_ef);
    lv_label_set_text(lbl, T(STR_EXTRA_FIELDS_TITLE));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_ef);
    lv_label_set_text(sub, "tag, last_dried");
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_ef, [](lv_event_t *e){
    logSD("BTN: Conn -> Extra Fields");
    showExtraFieldsScreen(false);
  }, LV_EVENT_CLICKED, NULL);
  if (sd_verbose) logSD("[verbose] buildConnectionScreen: done");
}
