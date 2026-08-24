#include "timezone_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/time_service.h"
#include "ui_common.h"

// The list body every screen of this kind uses. makeListBtn() never positions
// its button and relies on the parent's flex flow.
static lv_obj_t* buildList(lv_obj_t *parent) {
  lv_obj_t *list = lv_obj_create(parent);
  lv_obj_set_size(list, 480, 220);
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
  return list;
}

// One zone. No icon: a tick in front of every entry would read as "all of
// them are on". The chosen one is marked on the right and by its border, the
// way the other pickers in this project do it.
static void addZoneRow(lv_obj_t *list, size_t idx, int active_idx) {
  const bool active = ((int)idx == active_idx);

  lv_obj_t *btn = makeListBtn(list, "", TZ_LIST[idx].name, TZ_LIST[idx].offset,
                              active);

  // Last child is the arrow, which here shows which entry is the chosen one.
  lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
  if (arr_lbl) {
    lv_label_set_text(arr_lbl, active ? LV_SYMBOL_OK : "");
    lv_obj_set_style_text_color(arr_lbl, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_16, 0);
  }

  lv_obj_set_user_data(btn, (void *)(intptr_t)idx);
  lv_obj_add_event_cb(btn, [](lv_event_t *e) {
    const size_t i = (size_t)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
    if (i >= TZ_COUNT) return;
    if ((int)i == timeZoneIndex()) return;
    timeZoneSet(TZ_LIST[i].tz);
    logSDf("Time zone set to %s (%s)", TZ_LIST[i].name, TZ_LIST[i].tz);
    // Rebuild rather than patch the ticks, same as the other option screens.
    // releaseScreen() deletes asynchronously, so doing this from the row's own
    // callback is safe.
    buildTimeZoneScreen();
    lv_obj_clear_flag(scr_timezone, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
}

// ============================================================
//  TIME ZONE
//
//  No reboot popup, unlike the language and date format next
//  door. Those two need one because the T() strings are pulled
//  as a screen is built; a zone takes effect on the next
//  localtime_r() and the line below it is already in it.
// ============================================================
void buildTimeZoneScreen() {
  logSD("BUILD: TimeZoneScreen");
  releaseScreen(&scr_timezone);
  scr_timezone = buildOverlayScreen();

  char title[32];
  strncpy(title, T(STR_TZ_TITLE), sizeof(title) - 1);
  title[sizeof(title) - 1] = '\0';
  buildSubHeader(scr_timezone, title, [](lv_event_t *e){
    logSD("BTN: Back -> Language");
    show_language_pending = true;
  });

  lv_obj_t *list = buildList(scr_timezone);

  const int active_idx = timeZoneIndex();
  for (size_t i = 0; i < TZ_COUNT; i++) addZoneRow(list, i, active_idx);

  char hint_buf[160];
  strncpy(hint_buf, T(STR_TZ_HINT), sizeof(hint_buf) - 1);
  hint_buf[sizeof(hint_buf) - 1] = '\0';
  lv_obj_t *hint = lv_label_create(scr_timezone);
  lv_label_set_text(hint, hint_buf);
  lv_obj_set_style_text_color(hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(hint, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(hint, 440);
  lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -6);
}
