#include "settings_screen.h"
#include "navigation.h"
#include "app/app_state.h"

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
#include "update_badges.h"
#include "services/backend.h"
#include "theme.h"


void resetActivityTimer();

void buildSettingsScreen() {
  logSD("BUILD: SettingsScreen");
  if (sd_verbose) logSD("[verbose] buildSettingsScreen: start");
  releaseScreen(&scr_settings);
  scr_settings = buildOverlayScreen();

  lv_obj_t *title = lv_label_create(scr_settings);
  lv_label_set_text(title, T(STR_SETTINGS_TITLE));
  lv_obj_set_style_text_color(title, tc(TH_ACCENT), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 12);

  lv_obj_t *btn_x = lv_btn_create(scr_settings);
  lv_obj_set_size(btn_x, 44, 44);
  lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
  lv_obj_set_style_bg_color(btn_x, tc(TH_DANGER_BG), 0);
  lv_obj_set_style_bg_color(btn_x, tc(TH_DANGER_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_x, 0, 0);
  lv_obj_set_style_border_width(btn_x, 0, 0);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, tc(TH_DANGER_TEXT), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e){ logSD("BTN: Close -> Main"); showMainScreen(); }, LV_EVENT_CLICKED, NULL);

  // Names the active backend, so it is copied through backendText first.
  char conn_sub[40];
  backendText(T(STR_TILE_CONN_SUB), conn_sub, sizeof(conn_sub));
  struct { const char *icon; const char *label; const char *sub; uint32_t col; } tiles[] = {
    { LV_SYMBOL_WIFI,     T(STR_TILE_CONNECTION), conn_sub,                g_theme[TH_TILE_BG] },
    { LV_SYMBOL_DRIVE,    T(STR_TILE_SCALE),      T(STR_TILE_SCALE_SUB),   g_theme[TH_TILE_BG] },
    { LV_SYMBOL_IMAGE,    T(STR_TILE_DISPLAY),    T(STR_TILE_DISPLAY_SUB), g_theme[TH_TILE_BG] },
    { LV_SYMBOL_SETTINGS, T(STR_TILE_SYSTEM),     T(STR_TILE_SYSTEM_SUB),  g_theme[TH_TILE_BG] },
  };
  int tx[] = { 8, 242, 8, 242 };
  int ty[] = { 60, 60, 186, 186 };

  // Kept so the update dot can be anchored to it after the loop.
  lv_obj_t *tile_system = nullptr;

  for (int i = 0; i < 4; i++) {
    lv_obj_t *tile = lv_btn_create(scr_settings);
    if (i == 3) tile_system = tile;
    lv_obj_set_size(tile, 226, 118);
    lv_obj_set_pos(tile, tx[i], ty[i]);
    lv_obj_set_style_bg_color(tile, lv_color_hex(tiles[i].col), 0);
    lv_obj_set_style_bg_color(tile, tc(TH_SURFACE_2), LV_STATE_PRESSED);
    lv_obj_set_style_radius(tile, 10, 0);
    lv_obj_set_style_shadow_width(tile, 0, 0);
    lv_obj_set_style_border_width(tile, 1, 0);
    lv_obj_set_style_border_color(tile, tc(TH_BORDER), 0);

    lv_obj_t *ico = lv_label_create(tile);
    lv_label_set_text(ico, tiles[i].icon);
    lv_obj_set_style_text_color(ico, tc(TH_ACCENT), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_24, 0);
    lv_obj_align(ico, LV_ALIGN_TOP_LEFT, 10, 8);

    lv_obj_t *lbl = lv_label_create(tile);
    lv_label_set_text(lbl, tiles[i].label);
    lv_obj_set_style_text_color(lbl, tc(TH_TEXT_BRIGHT), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, -8);

    lv_obj_t *sub = lv_label_create(tile);
    lv_label_set_text(sub, tiles[i].sub);
    lv_obj_set_style_text_color(sub, tc(TH_TEXT_MUTED), 0);
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

  lbl_system_badge = createUpdateBadge(scr_settings, tile_system);

  if (sd_verbose) logSD("[verbose] buildSettingsScreen: done");
}
