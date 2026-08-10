#include "scale_menu.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/auto_weight_state.h"
#include "services/drying_config.h"
#include "services/prefs_store.h"
#include "ui_common.h"



static lv_obj_t* makeListBtn(lv_obj_t* list,
                              const char* ico_sym, const char* title, const char* sub,
                              bool toggle_active = false) {
  lv_obj_t *btn = lv_btn_create(list);
  lv_obj_set_size(btn, 456, 64);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 10, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 1, 0);
  lv_obj_set_style_border_color(btn, toggle_active ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a3050), 0);
  lv_obj_set_style_pad_all(btn, 0, 0);

  lv_obj_t *ico = lv_label_create(btn);
  lv_label_set_text(ico, ico_sym);
  lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_20, 0);
  lv_obj_align(ico, LV_ALIGN_LEFT_MID, 14, 0);

  lv_obj_t *lbl = lv_label_create(btn);
  lv_label_set_text(lbl, title);
  lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_width(lbl, 320);
  lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 52, sub && strlen(sub) > 0 ? -10 : 0);

  if (sub && strlen(sub) > 0) {
    lv_obj_t *slbl = lv_label_create(btn);
    lv_label_set_text(slbl, sub);
    lv_obj_set_style_text_color(slbl, toggle_active ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(slbl, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_width(slbl, 320);
    lv_obj_align(slbl, LV_ALIGN_LEFT_MID, 52, 12);
  }

  lv_obj_t *arr = lv_label_create(btn);
  lv_label_set_text(arr, LV_SYMBOL_RIGHT);
  lv_obj_set_style_text_color(arr, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(arr, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(arr, LV_ALIGN_RIGHT_MID, -14, 0);
  return btn;
}

void buildScaleSubScreen() {
  logSD("BUILD: ScaleSubScreen");
  if (sd_verbose) logSD("[verbose] buildScaleSubScreen: start");
  releaseScreen(&scr_scale_sub);
  scr_scale_sub = buildOverlayScreen();
  buildSubHeader(scr_scale_sub, T(STR_SCALE_TITLE),
    [](lv_event_t *e){ logSD("BTN: Back -> Settings"); showSettingsScreen(); });

  lv_obj_t *list = lv_obj_create(scr_scale_sub);
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

  { char bag_sub[32]; snprintf(bag_sub, sizeof(bag_sub), T(STR_BAG_CURRENT), bag_weight_g);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_DRIVE, T(STR_BTN_BAGWEIGHT), bag_sub);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Scale-Sub -> Bag Weight");
      show_bag_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  { char buf_t[40]; strncpy(buf_t, T(STR_BTN_DRYING_REMINDER), sizeof(buf_t)-1);
    char buf_s[24];
    const char* mode_lbl[] = { T(STR_DRY_MODE_OFF), T(STR_DRY_MODE_MATERIAL), T(STR_DRY_MODE_MANUAL) };
    strncpy(buf_s, mode_lbl[g_dry_mode < 3 ? g_dry_mode : 0], sizeof(buf_s)-1);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_WARNING, buf_t, buf_s);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Scale-Sub -> Drying Reminder");
      show_drying_reminder_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  { char buf_t[40]; strncpy(buf_t, T(STR_BTN_AUTO_LOC_POPUP), sizeof(buf_t)-1);
    char buf_s[8]; strncpy(buf_s, g_auto_loc_popup ? "ON" : "OFF", sizeof(buf_s)-1);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_GPS, buf_t, buf_s, g_auto_loc_popup);
    lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
    if (arr_lbl) {
      lv_label_set_text(arr_lbl, g_auto_loc_popup ? "ON" : "OFF");
      lv_obj_set_style_text_color(arr_lbl, g_auto_loc_popup ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
      lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_14, 0);
    }
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Scale-Sub -> Auto Location Popup Toggle");
      g_auto_loc_popup = !g_auto_loc_popup;
      prefsPutBool("auto_loc_popup", g_auto_loc_popup);
      if (scr_scale_sub) { lv_obj_del(scr_scale_sub); scr_scale_sub = nullptr; }
      buildScaleSubScreen();
      lv_obj_clear_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN);
    }, LV_EVENT_CLICKED, NULL); }

  { char buf_t[32]; strncpy(buf_t, T(STR_BTN_LASTUSED_MODE), sizeof(buf_t)-1);
    char buf_s[48]; strncpy(buf_s, T(STR_BTN_LASTUSED_MODE_SUB), sizeof(buf_s)-1);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_SAVE, buf_t, buf_s);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Scale-Sub -> Last Used Mode");
      show_lastused_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  { char cal_sub[32]; snprintf(cal_sub, sizeof(cal_sub), T(STR_CAL_FACTOR_SHORT), cal_factor);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_EDIT, T(STR_BTN_CALIBRATE), cal_sub);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Scale-Sub -> Calibration");
      show_factor_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  if (sd_verbose) logSD("[verbose] buildScaleSubScreen: done");
}
