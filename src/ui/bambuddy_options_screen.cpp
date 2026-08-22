#include "bambuddy_options_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

// bambuddy_api.h pulls in ArduinoJson, which must be parsed before lang.h
// defines the T() macro - ArduinoJson uses T as a template parameter and the
// macro turns its headers into nonsense. Same ordering rule as everywhere
// else in this project that needs both.
#include "services/bambuddy_api.h"

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "services/user_options.h"
#include "info_popup.h"
#include "ui_common.h"

// The list body every screen in here uses. makeListBtn() never positions its
// button and relies on the parent's flex flow - without these four lines
// every row lands on the content origin and only the last one is visible.
static lv_obj_t* buildList(lv_obj_t *parent) {
  lv_obj_t *list = lv_obj_create(parent);
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
  return list;
}

// Name of the destination currently chosen, for the row that leads into the
// sub screen. Same job as the address under "Address" on the backend screen.
static StringID driedTargetName() {
  switch (g_bb_dried_target) {
    case BB_DRIED_SPOOLMAN: return STR_BB_DRIED_SPOOLMAN;
    case BB_DRIED_NOTE:     return STR_BB_DRIED_NOTE;
    default:                return STR_BB_DRIED_OFF;
  }
}

// ============================================================
//  MORE OPTIONS
//
//  A list of settings, not the settings themselves. One entry
//  today, more are expected - which is exactly why each one
//  gets its own screen rather than being unfolded here.
// ============================================================
void buildBamBuddyOptionsScreen() {
  logSD("BUILD: BamBuddyOptionsScreen");
  releaseScreen(&scr_bambuddy_options);
  scr_bambuddy_options = buildOverlayScreen();
  buildSubHeader(scr_bambuddy_options, T(STR_BTN_MORE_OPTIONS),
    [](lv_event_t *e){
      logSD("BTN: Back -> Backend");
      // Deferred: the backend screen must not be built from inside the
      // callback of the screen it replaces.
      show_backend_pending = true;
    });

  lv_obj_t *list = buildList(scr_bambuddy_options);

  { char buf_t[40];
    strncpy(buf_t, T(STR_BB_DRIED_TITLE), sizeof(buf_t) - 1);
    buf_t[sizeof(buf_t) - 1] = '\0';
    // The subtitle carries the current choice, so the setting can be read
    // without opening it.
    char buf_s[48];
    strncpy(buf_s, T(driedTargetName()), sizeof(buf_s) - 1);
    buf_s[sizeof(buf_s) - 1] = '\0';

    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_WARNING, buf_t, buf_s, false, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_BB_DRIED_TITLE, STR_BB_DRIED_INFO));
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: BamBuddy Options -> Drying date");
      show_bambuddy_dried_pending = true;
    }, LV_EVENT_CLICKED, NULL); }
}

// ============================================================
//  DRYING DATE
//
//  Where the scale puts a drying date, given that BamBuddy has
//  no field for one. A three way choice, so the rows carry no
//  icon of their own: a tick in front of every entry reads as
//  "all three are on". The active one is marked on the right
//  and by its border, the way the other pickers do it.
// ============================================================
static void addDriedRow(lv_obj_t *list, uint8_t value, StringID title,
                        StringID sub, bool enabled) {
  const bool active = (g_bb_dried_target == value);

  char buf_t[40];
  strncpy(buf_t, T(title), sizeof(buf_t) - 1);
  buf_t[sizeof(buf_t) - 1] = '\0';
  char buf_s[48];
  strncpy(buf_s, T(sub), sizeof(buf_s) - 1);
  buf_s[sizeof(buf_s) - 1] = '\0';

  lv_obj_t *btn = makeListBtn(list, "", buf_t, buf_s, active);

  // Last child is the arrow, which here shows which entry is the chosen one.
  lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
  if (arr_lbl) {
    lv_label_set_text(arr_lbl, active ? LV_SYMBOL_OK : "");
    lv_obj_set_style_text_color(arr_lbl, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_16, 0);
  }

  if (!enabled) {
    // Left visible but inert: the reason it cannot be picked is the more
    // useful information, and hiding the entry would only raise the question.
    lv_obj_add_state(btn, LV_STATE_DISABLED);
    lv_obj_set_style_opa(btn, LV_OPA_50, 0);
    return;
  }

  lv_obj_set_user_data(btn, (void *)(intptr_t)value);
  lv_obj_add_event_cb(btn, [](lv_event_t *e) {
    uint8_t v = (uint8_t)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
    if (v == g_bb_dried_target) return;
    g_bb_dried_target = v;
    prefsPutUChar("bb_dried", v);
    logSDf("BTN: Drying date -> target %u", (unsigned)v);
    // Rebuild rather than patch the ticks, same as the other option screens.
    if (scr_bambuddy_dried) { lv_obj_del(scr_bambuddy_dried); scr_bambuddy_dried = nullptr; }
    buildBamBuddyDriedScreen();
    lv_obj_clear_flag(scr_bambuddy_dried, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
}

void buildBamBuddyDriedScreen() {
  logSD("BUILD: BamBuddyDriedScreen");
  releaseScreen(&scr_bambuddy_dried);
  scr_bambuddy_dried = buildOverlayScreen();
  buildSubHeader(scr_bambuddy_dried, T(STR_BB_DRIED_TITLE),
    [](lv_event_t *e){
      logSD("BTN: Back -> BamBuddy options");
      show_bambuddy_options_pending = true;
    });

  lv_obj_t *list = buildList(scr_bambuddy_dried);

  // The Spoolman route only exists while BamBuddy proxies to one. Shown
  // regardless, with the condition in its subtitle.
  const bool spoolman_ok = (bbInventoryMode() == BB_INV_SPOOLMAN) && bbSpoolmanUrl()[0];

  addDriedRow(list, BB_DRIED_OFF, STR_BB_DRIED_OFF, STR_BB_DRIED_OFF_SUB, true);
  addDriedRow(list, BB_DRIED_SPOOLMAN, STR_BB_DRIED_SPOOLMAN,
              spoolman_ok ? STR_BB_DRIED_SPOOLMAN_SUB : STR_BB_DRIED_SPOOLMAN_NA,
              spoolman_ok);
  addDriedRow(list, BB_DRIED_NOTE, STR_BB_DRIED_NOTE, STR_BB_DRIED_NOTE_SUB, true);
}
