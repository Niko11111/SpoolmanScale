#include "filaman_options_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/ams_assign.h"
#include "services/prefs_store.h"
#include "services/user_options.h"
#include "ams_assign_screen.h"
#include "info_popup.h"
#include "ui_common.h"


void buildFilaManOptionsScreen() {
  logSD("BUILD: FilaManOptionsScreen");
  releaseScreen(&scr_filaman_options);
  scr_filaman_options = buildOverlayScreen();
  buildSubHeader(scr_filaman_options, T(STR_BTN_MORE_OPTIONS),
    [](lv_event_t *e){
      logSD("BTN: Back -> Backend");
      // Deferred: the backend screen must not be built from inside the
      // callback of the screen it replaces.
      show_backend_pending = true;
    });

  lv_obj_t *list = lv_obj_create(scr_filaman_options);
  lv_obj_set_size(list, 480, 263);
  lv_obj_set_pos(list, 0, 57);
  lv_obj_set_style_bg_opa(list, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_left(list, 12, 0);
  lv_obj_set_style_pad_right(list, 12, 0);
  lv_obj_set_style_pad_top(list, 6, 0);
  lv_obj_set_style_pad_bottom(list, 6, 0);
  lv_obj_set_style_pad_row(list, 6, 0);
  // makeListBtn() never positions its button, it relies on the parent's
  // layout. Without a flex flow every entry lands on the content origin and
  // only the last one added is visible - invisible with a single entry, which
  // is why it went unnoticed. Same four lines as scale_menu.cpp.
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(list, LV_OBJ_FLAG_SCROLL_ELASTIC);

  // Link without asking. The subtitle carries the condition, because the
  // setting only ever acts when the spool was already on the scale.
  { char buf_t[40]; strncpy(buf_t, T(STR_FLM_AUTOLINK), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    char buf_s[40]; strncpy(buf_s, T(STR_FLM_AUTOLINK_SUB), sizeof(buf_s)-1);
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_CHARGE, buf_t, buf_s, g_flm_autolink, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_FLM_AUTOLINK, STR_FLM_AUTOLINK_INFO));

    // Last child is the arrow, which a toggle turns into ON/OFF.
    lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
    if (arr_lbl) {
      char buf_v[8]; strncpy(buf_v, T(g_flm_autolink ? STR_ON : STR_OFF), sizeof(buf_v)-1);
      buf_v[sizeof(buf_v)-1] = '\0';
      lv_label_set_text(arr_lbl, buf_v);
      lv_obj_set_style_text_color(arr_lbl,
        g_flm_autolink ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
      lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_14, 0);
    }

    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      g_flm_autolink = !g_flm_autolink;
      prefsPutBool("flm_autolink", g_flm_autolink);
      logSDf("BTN: FilaMan Options -> auto link %s", g_flm_autolink ? "ON" : "OFF");
      // Rebuild rather than patch the labels, same as the scale menu toggles.
      if (scr_filaman_options) { lv_obj_del(scr_filaman_options); scr_filaman_options = nullptr; }
      buildFilaManOptionsScreen();
      lv_obj_clear_flag(scr_filaman_options, LV_OBJ_FLAG_HIDDEN);
    }, LV_EVENT_CLICKED, NULL); }

  // Weigh without a tag. Sits under auto link because both decide what happens
  // when a remote link arrives; this one covers the case where no tag exists.
  { char buf_t[40]; strncpy(buf_t, T(STR_FLM_TAGLESS), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    char buf_s[40]; strncpy(buf_s, T(STR_FLM_TAGLESS_SUB), sizeof(buf_s)-1);
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_DRIVE, buf_t, buf_s, g_flm_tagless, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_FLM_TAGLESS, STR_FLM_TAGLESS_INFO));

    lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
    if (arr_lbl) {
      char buf_v[8]; strncpy(buf_v, T(g_flm_tagless ? STR_ON : STR_OFF), sizeof(buf_v)-1);
      buf_v[sizeof(buf_v)-1] = '\0';
      lv_label_set_text(arr_lbl, buf_v);
      lv_obj_set_style_text_color(arr_lbl,
        g_flm_tagless ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
      lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_14, 0);
    }

    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      g_flm_tagless = !g_flm_tagless;
      prefsPutBool("flm_tagless", g_flm_tagless);
      logSDf("BTN: FilaMan Options -> weigh without tag %s", g_flm_tagless ? "ON" : "OFF");
      if (scr_filaman_options) { lv_obj_del(scr_filaman_options); scr_filaman_options = nullptr; }
      buildFilaManOptionsScreen();
      lv_obj_clear_flag(scr_filaman_options, LV_OBJ_FLAG_HIDDEN);
    }, LV_EVENT_CLICKED, NULL); }

  // Write the tag on a remote trigger. Third in the row because all three
  // answer the same question - what happens when a link arrives from the web -
  // and this one only ever acts where the first one skipped the question.
  { char buf_t[40]; strncpy(buf_t, T(STR_FLM_REMOTE_WRITE), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    char buf_s[40]; strncpy(buf_s, T(STR_FLM_REMOTE_WRITE_SUB), sizeof(buf_s)-1);
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_EDIT, buf_t, buf_s, g_flm_remote_write, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_FLM_REMOTE_WRITE, STR_FLM_REMOTE_WRITE_INFO));

    lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
    if (arr_lbl) {
      char buf_v[8]; strncpy(buf_v, T(g_flm_remote_write ? STR_ON : STR_OFF), sizeof(buf_v)-1);
      buf_v[sizeof(buf_v)-1] = '\0';
      lv_label_set_text(arr_lbl, buf_v);
      lv_obj_set_style_text_color(arr_lbl,
        g_flm_remote_write ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
      lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_14, 0);
    }

    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      g_flm_remote_write = !g_flm_remote_write;
      prefsPutBool("flm_write", g_flm_remote_write);
      logSDf("BTN: FilaMan Options -> write tag on trigger %s",
             g_flm_remote_write ? "ON" : "OFF");
      if (scr_filaman_options) { lv_obj_del(scr_filaman_options); scr_filaman_options = nullptr; }
      buildFilaManOptionsScreen();
      lv_obj_clear_flag(scr_filaman_options, LV_OBJ_FLAG_HIDDEN);
    }, LV_EVENT_CLICKED, NULL); }


  // Which fields the scale writes, and what it leaves to the Bambu Lab
  // plugin. Its own screen because three rows do not fit here, and because
  // the two switches in it need room for what they cost.
  { char buf_t[40]; strncpy(buf_t, T(STR_FLM_FIELDS), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    char buf_s[48]; strncpy(buf_s, T(STR_FLM_FIELDS_SUB), sizeof(buf_s)-1);
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_GPS, buf_t, buf_s, false, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_FLM_FIELDS, STR_FLM_FIELDS_INFO));

    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: FilaMan Options -> Fields");
      // Deferred like every other screen change: this callback belongs to the
      // screen that is about to be replaced.
      show_filaman_fields_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  // Auto AMS assignment. Not a toggle but a mode, so the arrow carries the
  // mode name and the row opens a screen of its own instead of flipping a
  // bool. The window length and the timeout behaviour live in there too.
  { char buf_t[40]; strncpy(buf_t, T(STR_AMS_TITLE), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    // The mode name goes in the subtitle, not in the arrow. A whole word
    // there runs through the help circle - "Nachfragen" is 85 px and the gap
    // is 42. Same solution the BamBuddy dried row uses for driedTargetName().
    char buf_s[64];
    snprintf(buf_s, sizeof(buf_s), "%s - %s", T(STR_AMS_SUB), amsModeName());
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_LOOP, buf_t, buf_s,
                                g_ams_mode != AMS_OFF, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_AMS_TITLE, STR_AMS_INFO));

    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: FilaMan Options -> Auto AMS assign");
      // The screen reads the server when it opens, so it cannot be built
      // from in here.
      show_ams_assign_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

}
