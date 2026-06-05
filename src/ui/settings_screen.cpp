#include "settings_screen.h"

#include <Arduino.h>
#include <lvgl.h>

#include "connection_screen.h"
#include "display_screen.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "scale_menu.h"
#include "services/ota_state.h"
#include "system_screen.h"
#include "ui_common.h"

extern lv_obj_t *scr_settings;
extern lv_obj_t *scr_connection;
extern lv_obj_t *scr_scale_sub;
extern lv_obj_t *scr_display;
extern lv_obj_t *scr_system;
extern lv_obj_t *lbl_system_badge;

void showMainScreen();
void hideAllOverlays();
void resetActivityTimer();

void buildSettingsScreen() {
  logSD("BUILD: SettingsScreen");
  if (sd_verbose) logSD("[verbose] buildSettingsScreen: start");
  scr_settings = buildOverlayScreen();

  lv_obj_t *title = lv_label_create(scr_settings);
  lv_label_set_text(title, T(STR_SETTINGS_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 12);

  lv_obj_t *btn_x = lv_btn_create(scr_settings);
  lv_obj_set_size(btn_x, 44, 44);
  lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_x, 0, 0);
  lv_obj_set_style_border_width(btn_x, 0, 0);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e){ logSD("BTN: Close -> Main"); showMainScreen(); }, LV_EVENT_CLICKED, NULL);

  struct { const char *icon; const char *label; const char *sub; uint32_t col; } tiles[] = {
    { LV_SYMBOL_WIFI,     T(STR_TILE_CONNECTION), T(STR_TILE_CONN_SUB),    0x0a1e30 },
    { LV_SYMBOL_DRIVE,    T(STR_TILE_SCALE),      T(STR_TILE_SCALE_SUB),   0x0a1e30 },
    { LV_SYMBOL_IMAGE,    T(STR_TILE_DISPLAY),    T(STR_TILE_DISPLAY_SUB), 0x0a1e30 },
    { LV_SYMBOL_SETTINGS, T(STR_TILE_SYSTEM),     T(STR_TILE_SYSTEM_SUB),  0x0a1e30 },
  };
  int tx[] = { 8, 242, 8, 242 };
  int ty[] = { 60, 60, 186, 186 };

  for (int i = 0; i < 4; i++) {
    lv_obj_t *tile = lv_btn_create(scr_settings);
    lv_obj_set_size(tile, 226, 118);
    lv_obj_set_pos(tile, tx[i], ty[i]);
    lv_obj_set_style_bg_color(tile, lv_color_hex(tiles[i].col), 0);
    lv_obj_set_style_bg_color(tile, lv_color_hex(tiles[i].col + 0x101010), LV_STATE_PRESSED);
    lv_obj_set_style_radius(tile, 10, 0);
    lv_obj_set_style_shadow_width(tile, 0, 0);
    lv_obj_set_style_border_width(tile, 1, 0);
    lv_obj_set_style_border_color(tile, lv_color_hex(tiles[i].col + 0x181818), 0);

    lv_obj_t *ico = lv_label_create(tile);
    lv_label_set_text(ico, tiles[i].icon);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_24, 0);
    lv_obj_align(ico, LV_ALIGN_TOP_LEFT, 10, 8);

    lv_obj_t *lbl = lv_label_create(tile);
    lv_label_set_text(lbl, tiles[i].label);
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, -8);

    lv_obj_t *sub = lv_label_create(tile);
    lv_label_set_text(sub, tiles[i].sub);
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_12, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 16);

    lv_obj_add_event_cb(tile, [](lv_event_t *e) {
      intptr_t idx = (intptr_t)lv_event_get_user_data(e);
      switch (idx) {
        case 0:
          logSD("UI: Tile -> Connection");
          if (scr_connection) { lv_obj_del(scr_connection); scr_connection = nullptr; }
          buildConnectionScreen();
          if (!scr_connection) buildConnectionScreen();
          hideAllOverlays();
          lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
          break;
        case 1:
          logSD("UI: Tile -> Scale");
          if (!scr_scale_sub) buildScaleSubScreen();
          if (!scr_scale_sub) buildScaleSubScreen();
          hideAllOverlays();
          lv_obj_clear_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN);
          break;
        case 2:
          logSD("UI: Tile -> Display");
          if (!scr_display) buildDisplayScreen();
          hideAllOverlays();
          lv_obj_clear_flag(scr_display, LV_OBJ_FLAG_HIDDEN);
          break;
        case 3:
          logSD("UI: Tile -> System");
          if (!scr_system) buildSystemScreen();
          hideAllOverlays();
          lv_obj_clear_flag(scr_system, LV_OBJ_FLAG_HIDDEN);
          break;
      }
      resetActivityTimer();
    }, LV_EVENT_CLICKED, (void*)(intptr_t)i);
  }

  lbl_system_badge = lv_obj_create(scr_settings);
  lv_obj_set_size(lbl_system_badge, 14, 14);
  lv_obj_set_pos(lbl_system_badge, 456, 186);
  lv_obj_set_style_radius(lbl_system_badge, 7, 0);
  lv_obj_set_style_bg_color(lbl_system_badge, lv_color_hex(0xe03030), 0);
  lv_obj_set_style_border_color(lbl_system_badge, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(lbl_system_badge, 2, 0);
  lv_obj_set_style_pad_all(lbl_system_badge, 0, 0);
  lv_obj_clear_flag(lbl_system_badge, LV_OBJ_FLAG_SCROLLABLE);
  if (!update_available) lv_obj_add_flag(lbl_system_badge, LV_OBJ_FLAG_HIDDEN);

  if (sd_verbose) logSD("[verbose] buildSettingsScreen: done");
}
