#include "last_used_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "scale_menu.h"
#include "services/prefs_store.h"
#include "services/user_options.h"
#include "ui_common.h"
#include "services/backend.h"



void updateLastUsedCapLabel() {
  if (!lbl_lu_cap) return;
  char buf[32];
  if (last_used_mode == 1)
    strncpy(buf, g_lang == LANG_DE ? "Zuletzt gewogen:" : "Last weighed:", sizeof(buf)-1);
  else
    strncpy(buf, T(STR_LBL_LAST_USED), sizeof(buf)-1);
  buf[sizeof(buf)-1] = 0;
  lv_label_set_text(lbl_lu_cap, buf);
}

void buildLastUsedScreen() {
  logSD("BUILD: LastUsedScreen");
  releaseScreen(&scr_lastused);
  scr_lastused = buildOverlayScreen();
  buildSubHeader(scr_lastused, T(STR_LASTUSED_TITLE),
    [](lv_event_t *e){
      hideAllOverlays();
      if (!scr_scale_sub) buildScaleSubScreen();
      lv_obj_clear_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN);
    });
  addCloseButton(scr_lastused);

  lv_obj_t *btn_osm = lv_btn_create(scr_lastused);
  lv_obj_set_size(btn_osm, 210, 50);
  lv_obj_set_pos(btn_osm, 12, 58);
  bool osm_active = (last_used_mode == 0);
  lv_obj_set_style_bg_color(btn_osm, lv_color_hex(osm_active ? 0x1a3020 : 0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_osm, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_osm, 1, 0);
  lv_obj_set_style_border_color(btn_osm, lv_color_hex(osm_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_set_style_radius(btn_osm, 8, 0);
  lv_obj_set_style_shadow_width(btn_osm, 0, 0);
  lv_obj_add_event_cb(btn_osm, [](lv_event_t *e) {
    logSD("BTN: LastUsed -> OSM mode");
    last_used_mode = 0;
    prefsPutUChar("lu_mode", 0);
    updateLastUsedCapLabel();
    show_lastused_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_osm = lv_label_create(btn_osm);
  lv_label_set_text(lbl_osm, T(STR_LASTUSED_OPT_OSM));
  lv_obj_set_style_text_color(lbl_osm, lv_color_hex(osm_active ? 0x40c080 : 0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_osm, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_osm, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_osm, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *btn_lw = lv_btn_create(scr_lastused);
  lv_obj_set_size(btn_lw, 210, 50);
  lv_obj_set_pos(btn_lw, 238, 58);
  bool lw_active = (last_used_mode == 1);
  lv_obj_set_style_bg_color(btn_lw, lv_color_hex(lw_active ? 0x1a3020 : 0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_lw, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_lw, 1, 0);
  lv_obj_set_style_border_color(btn_lw, lv_color_hex(lw_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_set_style_radius(btn_lw, 8, 0);
  lv_obj_set_style_shadow_width(btn_lw, 0, 0);
  lv_obj_add_event_cb(btn_lw, [](lv_event_t *e) {
    logSD("BTN: LastUsed -> Weighed mode");
    last_used_mode = 1;
    prefsPutUChar("lu_mode", 1);
    updateLastUsedCapLabel();
    show_lastused_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_lw = lv_label_create(btn_lw);
  lv_label_set_text(lbl_lw, T(STR_LASTUSED_OPT_WEIGHED));
  lv_obj_set_style_text_color(lbl_lw, lv_color_hex(lw_active ? 0x40c080 : 0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_lw, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_lw, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_lw, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *lbl_desc = lv_label_create(scr_lastused);
  const char *desc = backendIsFilaMan()
                       ? T(STR_LASTUSED_DESC_FILAMAN)
                       : ((last_used_mode == 0) ? T(STR_LASTUSED_DESC_OSM)
                                                : T(STR_LASTUSED_DESC_WEIGHED));
  char desc_buf[280];
  strncpy(desc_buf, desc, sizeof(desc_buf)-1); desc_buf[sizeof(desc_buf)-1] = 0;
  lv_label_set_text(lbl_desc, desc_buf);
  lv_obj_set_style_text_color(lbl_desc, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_desc, &lv_font_montserrat_ext_14, 0);
  lv_label_set_long_mode(lbl_desc, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_desc, 448);
  lv_obj_set_style_text_align(lbl_desc, LV_TEXT_ALIGN_LEFT, 0);
  lv_obj_set_pos(lbl_desc, 16, 128);
}
