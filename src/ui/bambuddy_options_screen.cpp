#include "bambuddy_options_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

// backend_api.h brings ArduinoJson; lang.h after it, which defines T().
#include "services/backend_api.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/settings_registry.h"
#include "services/user_options.h"
#include "ui_common.h"
#include "theme.h"

// ============================================================
//  MORE OPTIONS
//
//  Every row comes from the one table in
//  services/settings_registry.h - which one belongs here is the
//  scope on the descriptor, not a list kept in this file.
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

  addSettingRows(buildOptionList(scr_bambuddy_options));
}

// ============================================================
//  DRYING DATE
//
//  Where the scale puts a drying date on a BamBuddy without a
//  field for one. A newer BamBuddy has its own (#2863) and the
//  date always goes there: that row then stands on top, chosen,
//  and the three below are inert. A three way choice, so the rows carry no
//  icon of their own: a tick in front of every entry reads as
//  "all three are on". The active one is marked on the right
//  and by its border, the way the other pickers do it.
//
//  The values, their names and whether each can be picked come
//  from the descriptor, so the web renders the same three from
//  the same source. What stays here is why: a line per choice
//  explaining what it costs, which is a screen's job and not a
//  table's.
// ============================================================

// Indexed by value, alongside OPT_BB_DRIED in the registry.
static const StringID DRIED_SUB[BB_DRIED_COUNT] = {
  STR_BB_DRIED_OFF_SUB, STR_BB_DRIED_SPOOLMAN_SUB, STR_BB_DRIED_NOTE_SUB
};

// Last child is the arrow, which here shows which entry is the chosen one.
static void markChosen(lv_obj_t *btn, bool active) {
  lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
  if (!arr_lbl) return;
  lv_label_set_text(arr_lbl, active ? LV_SYMBOL_OK : "");
  lv_obj_set_style_text_color(arr_lbl, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_16, 0);
}

// BamBuddy's own field: shown as the choice in force, not something to tap.
static void addNativeRow(lv_obj_t *list) {
  char buf_t[40], buf_s[48];
  copyT(buf_t, sizeof(buf_t), STR_BB_DRIED_NATIVE);
  copyT(buf_s, sizeof(buf_s), STR_BB_DRIED_NATIVE_SUB);
  lv_obj_t *btn = makeListBtn(list, "", buf_t, buf_s, true);
  markChosen(btn, true);
  lv_obj_clear_flag(btn, LV_OBJ_FLAG_CLICKABLE);
}

static void addDriedRow(lv_obj_t *list, const SettingDesc &s, uint8_t value, bool native) {
  const bool active  = !native && settingGet(s) == value;
  const bool enabled = !s.opt_ok || s.opt_ok(value);

  char buf_t[40];
  copyT(buf_t, sizeof(buf_t), (StringID)s.opt_str[value]);

  // An unavailable choice says why in place of what it does - that is the more
  // useful line, and it is the only one the user can act on.
  StringID sub = DRIED_SUB[value];
  if (native)                                    sub = STR_BB_DRIED_OLDER_ONLY;
  else if (!enabled && value == BB_DRIED_SPOOLMAN) sub = STR_BB_DRIED_SPOOLMAN_NA;
  char buf_s[64];
  copyT(buf_s, sizeof(buf_s), sub);

  lv_obj_t *btn = makeListBtn(list, "", buf_t, buf_s, active);
  markChosen(btn, active);

  if (!enabled) {
    // Left visible but inert: the reason it cannot be picked is the more
    // useful information, and hiding the entry would only raise the question.
    lv_obj_add_state(btn, LV_STATE_DISABLED);
    lv_obj_set_style_opa(btn, LV_OPA_50, 0);
    return;
  }

  lv_obj_set_user_data(btn, (void *)(intptr_t)value);
  lv_obj_add_event_cb(btn, [](lv_event_t *e) {
    const uint8_t v = (uint8_t)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
    const SettingDesc *d = settingById("bb_dried");
    if (!d || v == settingGet(*d)) return;
    settingSet(*d, v);
    logSDf("BTN: Drying date -> target %u", (unsigned)v);
    // Through the flag rather than deleting from inside this button's own
    // callback: that path goes through releaseScreen() and lv_obj_del_async().
    show_bambuddy_dried_pending = true;
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

  lv_obj_t *list = buildOptionList(scr_bambuddy_dried);

  const SettingDesc *s = settingById("bb_dried");
  if (!s || !s->opt_str) return;
  // Known once a spool was read from this server; until then the rows look
  // as they do for an older BamBuddy.
  const bool native = backendHasNativeLastDried();
  if (native) addNativeRow(list);
  for (uint8_t v = 0; v < s->opt_count; v++) addDriedRow(list, *s, v, native);
}
