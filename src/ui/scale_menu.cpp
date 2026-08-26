#include "scale_menu.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "confirm_popup.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/auto_weight_state.h"
#include "services/backend.h"
#include "services/drying_config.h"
#include "services/prefs_store.h"
#include "services/tag_write.h"
#include "services/user_options.h"
#include "info_popup.h"
#include "ui_common.h"




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
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_WARNING, buf_t, buf_s);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Scale-Sub -> Drying Reminder");
      show_drying_reminder_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  { char buf_t[40]; strncpy(buf_t, T(STR_BTN_AUTO_LOC_POPUP), sizeof(buf_t)-1);
    char buf_s[8]; strncpy(buf_s, T(g_auto_loc_popup ? STR_ON : STR_OFF), sizeof(buf_s)-1);
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_GPS, buf_t, buf_s, g_auto_loc_popup);
    lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
    if (arr_lbl) {
      lv_label_set_text(arr_lbl, buf_s);
      lv_obj_set_style_text_color(arr_lbl, g_auto_loc_popup ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
      lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_14, 0);
    }
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Scale-Sub -> Auto Location Popup Toggle");
      g_auto_loc_popup = !g_auto_loc_popup;
      prefsPutBool("auto_loc_popup", g_auto_loc_popup);
      // Through the flag like the two rows below, not deleting the screen this
      // button sits on from inside its own callback.
      scale_sub_rebuild_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  // Writing the tag after a link, and in which format. Backend independent, so
  // it sits here rather than in one of the three backend option screens: what
  // goes on a tag is an agreement between the tag and whoever reads it, and
  // none of the backends ever sees it.
  { char buf_t[40]; strncpy(buf_t, T(STR_TW_OPT_ASK), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    char buf_s[8]; strncpy(buf_s, T(g_tagwrite_ask ? STR_ON : STR_OFF), sizeof(buf_s)-1);
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_EDIT, buf_t, buf_s, g_tagwrite_ask, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_TW_OPT_ASK, STR_TW_OPT_ASK_INFO));
    lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
    if (arr_lbl) {
      lv_label_set_text(arr_lbl, buf_s);
      lv_obj_set_style_text_color(arr_lbl, g_tagwrite_ask ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
      lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_14, 0);
    }
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Scale-Sub -> Tag write ask toggle");
      g_tagwrite_ask = !g_tagwrite_ask;
      prefsPutBool("tagwrite_ask", g_tagwrite_ask);
      scale_sub_rebuild_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  // Cycled rather than opened as a screen of its own, like the IP bar mode in
  // wifi_info.cpp: three values, and the subtitle already says which one is
  // set. The info button carries what each format means.
  { char buf_t[32]; strncpy(buf_t, T(STR_TW_OPT_FMT), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    char buf_s[24]; strncpy(buf_s, tagFormatLabel(g_tagwrite_fmt), sizeof(buf_s)-1);
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_SD_CARD, buf_t, buf_s, false, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_TW_OPT_FMT, STR_TW_OPT_FMT_INFO));
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      // OpenSpool -> FilaMan -> ACE -> OpenSpool. TAG_FMT_ERASE is not in the
      // ring: erasing answers an unlink, never a link.
      g_tagwrite_fmt = (g_tagwrite_fmt == TAG_FMT_OPENSPOOL) ? TAG_FMT_FILAMAN
                     : (g_tagwrite_fmt == TAG_FMT_FILAMAN)   ? TAG_FMT_ACE
                                                             : TAG_FMT_OPENSPOOL;
      prefsPutUChar("tagwrite_fmt", g_tagwrite_fmt);
      logSDf("BTN: Scale-Sub -> Tag write format %s", tagFormatLabel(g_tagwrite_fmt));
      scale_sub_rebuild_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  { char buf_t[32]; strncpy(buf_t, T(STR_BTN_LASTUSED_MODE), sizeof(buf_t)-1);
    // The subtitle names the two sources, and they differ per backend.
    char buf_s[48];
    strncpy(buf_s, backendIsFilaMan()  ? T(STR_BTN_LASTUSED_MODE_SUB_FM)
                 : backendIsBamBuddy() ? T(STR_BTN_LASTUSED_MODE_SUB_BB)
                                       : T(STR_BTN_LASTUSED_MODE_SUB),
            sizeof(buf_s) - 1);
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

  // The way back from a calibration that was taken while the ADC was not on
  // the bus: every reading was -1 then, so the stored factor is arithmetic on
  // nonsense and no amount of re-tareing fixes it. Until now the only cure was
  // erasing NVS.
  { char rst_t[40]; strncpy(rst_t, T(STR_BTN_CAL_RESET), sizeof(rst_t)-1);
    rst_t[sizeof(rst_t)-1] = '\0';
    char rst_s[40]; strncpy(rst_s, T(STR_BTN_CAL_RESET_SUB), sizeof(rst_s)-1);
    rst_s[sizeof(rst_s)-1] = '\0';
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_REFRESH, rst_t, rst_s);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Scale-Sub -> Reset calibration");
      char ask[64]; strncpy(ask, T(STR_CAL_RESET_CONFIRM), sizeof(ask)-1);
      ask[sizeof(ask)-1] = '\0';
      showConfirmPopup(ask, 6);
    }, LV_EVENT_CLICKED, NULL); }

  if (sd_verbose) logSD("[verbose] buildScaleSubScreen: done");
}
