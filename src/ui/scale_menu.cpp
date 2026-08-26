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




// The list of this screen, kept so the scroll position can be put back after a
// rebuild. A toggle row rebuilds the whole screen, and a freshly built flex
// container starts at the top - which threw the user back to the first row
// every time they changed something further down.
static lv_obj_t *s_scale_list = nullptr;
static lv_coord_t s_scale_scroll = 0;

// Taken before the screen is deleted, put back after it is built. The layout
// has to have run first, otherwise the content height is still zero and LVGL
// clamps the offset away.
void scaleSubScrollRemember() {
  s_scale_scroll = (s_scale_list && scr_scale_sub) ? lv_obj_get_scroll_y(s_scale_list) : 0;
  // Dropped straight away: the caller deletes the screen next, and a pointer
  // to a freed list is worth nothing and dangerous to keep.
  s_scale_list = nullptr;
}

void scaleSubScrollForget() {
  s_scale_list   = nullptr;
  s_scale_scroll = 0;
}

static void scaleSubScrollRestore() {
  if (!s_scale_list || s_scale_scroll <= 0) return;
  lv_obj_update_layout(s_scale_list);
  lv_obj_scroll_to_y(s_scale_list, s_scale_scroll, LV_ANIM_OFF);
}

void buildScaleSubScreen() {
  logSD("BUILD: ScaleSubScreen");
  if (sd_verbose) logSD("[verbose] buildScaleSubScreen: start");
  s_scale_list = nullptr;            // the old list goes with the old screen
  releaseScreen(&scr_scale_sub);
  scr_scale_sub = buildOverlayScreen();
  buildSubHeader(scr_scale_sub, T(STR_SCALE_TITLE),
    [](lv_event_t *e){ logSD("BTN: Back -> Settings"); showSettingsScreen(); });

  // The shared list, not fourteen hand-copied lines of the same thing - this
  // screen was the one the de-duplication in beta.106 missed.
  lv_obj_t *list = buildOptionList(scr_scale_sub);
  s_scale_list = list;

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
  // none of the backends ever sees it. One row, because two of them were two
  // rebuilds of this list and it jumped back to the top on every tap.
  { char buf_t[40]; strncpy(buf_t, T(STR_TW_OPT_ASK), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    // The subtitle carries the state, so the sub screen does not have to be
    // opened to see it: off, or the format that would be written.
    char buf_s[40];
    if (g_tagwrite_ask) snprintf(buf_s, sizeof(buf_s), "%s", tagFormatLabel(g_tagwrite_fmt));
    else                strncpy(buf_s, T(STR_OFF), sizeof(buf_s)-1);
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_EDIT, buf_t, buf_s, g_tagwrite_ask);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Scale-Sub -> Tag write");
      show_tagwrite_pending = true;
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

  // No reset row here any more: the same action sits as a red button on the
  // calibration screen itself, which is where somebody is standing when they
  // find out they need it.

  scaleSubScrollRestore();

  if (sd_verbose) logSD("[verbose] buildScaleSubScreen: done");
}

// ============================================================
//  WRITING A TAG AFTER A LINK
//
//  One switch and a three way choice on one screen, because
//  they only make sense together: the format answers a question
//  that the switch has to have asked first.
//
//  Backend independent, unlike the option screens next door -
//  what a tag holds is an agreement between the tag and
//  whoever reads it later, and no backend ever sees it.
// ============================================================

// Indexed the way the rows are ordered, not by TagFormat value: OpenSpool
// first because it is what the filament managers read, ACE last because it
// only ever talks to the printer.
static const uint8_t TW_FMT_ORDER[3] = {
  TAG_FMT_OPENSPOOL, TAG_FMT_FILAMAN, TAG_FMT_ACE
};
static const StringID TW_FMT_NAME[3] = {
  STR_TW_FMT_OPENSPOOL, STR_TW_FMT_FILAMAN, STR_TW_FMT_ACE
};

static void addTagFormatRow(lv_obj_t *list, uint8_t idx) {
  const uint8_t value  = TW_FMT_ORDER[idx];
  const bool    active = (g_tagwrite_fmt == value);

  char buf_t[40];
  strncpy(buf_t, T(TW_FMT_NAME[idx]), sizeof(buf_t) - 1);
  buf_t[sizeof(buf_t) - 1] = '\0';

  lv_obj_t *btn = makeListBtn(list, "", buf_t, "", active);

  // Last child is the arrow, which here marks the chosen entry.
  lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
  if (arr_lbl) {
    lv_label_set_text(arr_lbl, active ? LV_SYMBOL_OK : "");
    lv_obj_set_style_text_color(arr_lbl, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_16, 0);
  }

  lv_obj_set_user_data(btn, (void *)(intptr_t)value);
  lv_obj_add_event_cb(btn, [](lv_event_t *e) {
    const uint8_t v = (uint8_t)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
    if (v == g_tagwrite_fmt) return;
    g_tagwrite_fmt = v;
    prefsPutUChar("tagwrite_fmt", g_tagwrite_fmt);
    logSDf("BTN: Tag write -> format %s", tagFormatLabel(g_tagwrite_fmt));
    // Through the flag, never deleting the screen this button sits on.
    show_tagwrite_pending = true;
  }, LV_EVENT_CLICKED, NULL);
}

void buildTagWriteScreen() {
  logSD("BUILD: TagWriteScreen");
  releaseScreen(&scr_tagwrite);
  scr_tagwrite = buildOverlayScreen();
  buildSubHeader(scr_tagwrite, T(STR_TW_OPT_ASK),
    [](lv_event_t *e){
      logSD("BTN: Back -> Scale");
      // Rebuilt rather than just unhidden: the row that leads here carries the
      // format in its subtitle, and a kept screen would still show the old
      // one. The scroll position is remembered across that rebuild, so the row
      // stays where the finger left it.
      hideAllOverlays();
      scale_sub_rebuild_pending = true;
    });

  lv_obj_t *list = buildOptionList(scr_tagwrite);

  // The switch first: without it the format below decides nothing.
  { char buf_t[40]; strncpy(buf_t, T(STR_TW_OPT_ASK), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    char buf_s[48]; strncpy(buf_s, T(STR_TW_OPT_ASK_SUB), sizeof(buf_s)-1);
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_EDIT, buf_t, buf_s, g_tagwrite_ask, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_TW_OPT_ASK, STR_TW_OPT_ASK_INFO));
    lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
    if (arr_lbl) {
      char on_off[8]; strncpy(on_off, T(g_tagwrite_ask ? STR_ON : STR_OFF), sizeof(on_off)-1);
      on_off[sizeof(on_off)-1] = '\0';
      lv_label_set_text(arr_lbl, on_off);
      lv_obj_set_style_text_color(arr_lbl, g_tagwrite_ask ? lv_color_hex(0x28d49a)
                                                          : lv_color_hex(0x4a6fa0), 0);
      lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_14, 0);
    }
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      g_tagwrite_ask = !g_tagwrite_ask;
      prefsPutBool("tagwrite_ask", g_tagwrite_ask);
      logSDf("BTN: Tag write -> ask %s", g_tagwrite_ask ? "on" : "off");
      show_tagwrite_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  // The format, with its own help. Shown even while the switch is off: it is
  // also what the tag page in the browser writes when nothing else is chosen,
  // and hiding it would make that setting unreachable from the device.
  { char buf_t[32]; strncpy(buf_t, T(STR_TW_OPT_FMT), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_SD_CARD, buf_t, "", false, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_TW_OPT_FMT, STR_TW_OPT_FMT_INFO));
    lv_obj_clear_flag(btn, LV_OBJ_FLAG_CLICKABLE);   // a heading, not a choice
    lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
    if (arr_lbl) lv_label_set_text(arr_lbl, ""); }

  for (uint8_t i = 0; i < 3; i++) addTagFormatRow(list, i);
}
