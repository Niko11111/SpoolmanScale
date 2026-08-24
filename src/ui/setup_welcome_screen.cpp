#include "setup_welcome_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "ui_common.h"
#include "wifi_setup_screen.h"
#include "services/backend.h"
#include "services/time_service.h"
#include "timezone_screen.h"



// The choice, held across rebuilds of the screen: picking a language restyles
// the buttons, and coming back from the time zone picker rebuilds it whole.
// -1 means "not worked out yet".
static int  wel_lang_sel   = -1;   // 0 = DE, 1 = EN, same values as the "lang" key
static int  wel_tz_sel     = -1;   // index into TZ_LIST
static bool wel_tz_touched = false;

static lv_obj_t *wel_btn_en = nullptr, *wel_lbl_en = nullptr;
static lv_obj_t *wel_btn_de = nullptr, *wel_lbl_de = nullptr;
static lv_obj_t *wel_lbl_tz = nullptr;

static void welStyleLangBtn(lv_obj_t *btn, lv_obj_t *lbl, bool active) {
  if (!btn || !lbl) return;
  lv_obj_set_style_bg_color(btn, lv_color_hex(active ? 0x0a2a40 : 0x0a1828), 0);
  lv_obj_set_style_border_color(btn, lv_color_hex(active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_set_style_text_color(lbl, lv_color_hex(active ? 0x28d49a : 0x4a6fa0), 0);
}

// Restyles in place rather than rebuilding: a rebuild from a button's own
// callback is avoidable here, and the screen has nothing else to re-read.
static void welRefresh() {
  welStyleLangBtn(wel_btn_en, wel_lbl_en, wel_lang_sel == 1);
  welStyleLangBtn(wel_btn_de, wel_lbl_de, wel_lang_sel == 0);
  if (wel_lbl_tz && wel_tz_sel >= 0 && (size_t)wel_tz_sel < TZ_COUNT) {
    char buf[48];
    strncpy(buf, TZ_LIST[wel_tz_sel].name, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    lv_label_set_text(wel_lbl_tz, buf);
  }
}

void showWelcomeScreen() {
  logSD("SHOW: WelcomeScreen");
  logSD("UI: Screen -> Welcome");
  hideAllOverlays();
  if (!scr_welcome) buildWelcomeScreen();
  lv_obj_clear_flag(scr_welcome, LV_OBJ_FLAG_HIDDEN);
}

void buildWelcomeScreen() {
  logSD("BUILD: WelcomeScreen");
  releaseScreen(&scr_welcome);
  scr_welcome = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_welcome, 480, 320);
  lv_obj_set_pos(scr_welcome, 0, 0);
  lv_obj_add_flag(scr_welcome, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_welcome, 0, 0);
  lv_obj_set_style_border_width(scr_welcome, 0, 0);
  lv_obj_set_style_pad_all(scr_welcome, 0, 0);
  lv_obj_clear_flag(scr_welcome, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_welcome, lv_color_hex(0x0a1020), 0);

  // First time through: start from whatever the device already believes.
  if (wel_lang_sel < 0) wel_lang_sel = (g_lang == LANG_DE) ? 0 : 1;
  if (wel_tz_sel < 0) {
    const int stored = timeZoneIndex();
    wel_tz_sel = (stored >= 0) ? stored
                               : timeZoneDefaultIndexForLang((uint8_t)wel_lang_sel);
  }
  // Coming back from the picker, which writes its choice straight to storage.
  if (wel_tz_touched) {
    const int stored = timeZoneIndex();
    if (stored >= 0) wel_tz_sel = stored;
  }

  lv_obj_t *lbl_logo = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_logo, "SpoolmanScale");
  lv_obj_set_style_text_color(lbl_logo, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_logo, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(lbl_logo, LV_ALIGN_TOP_MID, 0, 12);

  lv_obj_t *lbl_sub = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_sub, T(STR_WELCOME_LANG_TITLE));
  lv_obj_set_style_text_color(lbl_sub, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_sub, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_sub, LV_ALIGN_TOP_MID, 0, 46);

  if (cfg_lang_set) {
    lv_obj_t *btn_x = lv_btn_create(scr_welcome);
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
  }

  // ---- language, a choice now rather than an action ------------------
  const int LB_W = 218, LB_H = 52, LB_Y = 76;

  wel_btn_en = lv_btn_create(scr_welcome);
  lv_obj_set_size(wel_btn_en, LB_W, LB_H);
  lv_obj_set_pos(wel_btn_en, 8, LB_Y);
  lv_obj_set_style_bg_color(wel_btn_en, lv_color_hex(0x1a4060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(wel_btn_en, 10, 0);
  lv_obj_set_style_shadow_width(wel_btn_en, 0, 0);
  lv_obj_set_style_border_width(wel_btn_en, 2, 0);
  wel_lbl_en = lv_label_create(wel_btn_en);
  lv_label_set_text(wel_lbl_en, "EN   English");
  lv_obj_set_style_text_font(wel_lbl_en, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(wel_lbl_en);
  lv_obj_add_event_cb(wel_btn_en, [](lv_event_t *e){
    wel_lang_sel = 1;
    // Only until the owner says otherwise. After that the language stops
    // moving the zone, or picking one would be undone by a second thought
    // about the language.
    if (!wel_tz_touched) wel_tz_sel = timeZoneDefaultIndexForLang(1);
    welRefresh();
  }, LV_EVENT_CLICKED, NULL);

  wel_btn_de = lv_btn_create(scr_welcome);
  lv_obj_set_size(wel_btn_de, LB_W, LB_H);
  lv_obj_set_pos(wel_btn_de, 254, LB_Y);
  lv_obj_set_style_bg_color(wel_btn_de, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(wel_btn_de, 10, 0);
  lv_obj_set_style_shadow_width(wel_btn_de, 0, 0);
  lv_obj_set_style_border_width(wel_btn_de, 2, 0);
  wel_lbl_de = lv_label_create(wel_btn_de);
  lv_label_set_text(wel_lbl_de, "DE   Deutsch");
  lv_obj_set_style_text_font(wel_lbl_de, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(wel_lbl_de);
  lv_obj_add_event_cb(wel_btn_de, [](lv_event_t *e){
    wel_lang_sel = 0;
    if (!wel_tz_touched) wel_tz_sel = timeZoneDefaultIndexForLang(0);
    welRefresh();
  }, LV_EVENT_CLICKED, NULL);

  // ---- time zone, asked here so the clock is right from the first boot ----
  lv_obj_t *lbl_tzc = lv_label_create(scr_welcome);
  { char buf[32]; strncpy(buf, T(STR_TZ_TITLE), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    lv_label_set_text(lbl_tzc, buf); }
  lv_obj_set_style_text_color(lbl_tzc, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_tzc, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(lbl_tzc, 12, 140);

  lv_obj_t *btn_tz = lv_btn_create(scr_welcome);
  lv_obj_set_size(btn_tz, 464, 44);
  lv_obj_set_pos(btn_tz, 8, 160);
  lv_obj_set_style_bg_color(btn_tz, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_tz, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_tz, 10, 0);
  lv_obj_set_style_shadow_width(btn_tz, 0, 0);
  lv_obj_set_style_border_width(btn_tz, 1, 0);
  lv_obj_set_style_border_color(btn_tz, lv_color_hex(0x1a3050), 0);

  wel_lbl_tz = lv_label_create(btn_tz);
  lv_label_set_text(wel_lbl_tz, "");
  lv_obj_set_style_text_color(wel_lbl_tz, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(wel_lbl_tz, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(wel_lbl_tz, LV_ALIGN_LEFT_MID, 14, 0);

  lv_obj_t *lbl_tz_arr = lv_label_create(btn_tz);
  lv_label_set_text(lbl_tz_arr, LV_SYMBOL_RIGHT);
  lv_obj_set_style_text_color(lbl_tz_arr, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_tz_arr, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_tz_arr, LV_ALIGN_RIGHT_MID, -14, 0);

  lv_obj_add_event_cb(btn_tz, [](lv_event_t *e){
    logSD("BTN: Welcome -> Time zone");
    // The picker reads and writes storage, and the language is not saved yet,
    // so the pre-selection has to be put there first or the picker would show
    // the zone of the language being replaced.
    if (wel_tz_sel >= 0 && (size_t)wel_tz_sel < TZ_COUNT) {
      timeZoneSet(TZ_LIST[wel_tz_sel].tz);
    }
    wel_tz_touched = true;
    setTimeZoneReturnToWelcome(true);
    show_timezone_pending = true;
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_hint = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_hint, T(STR_WELCOME_LANG_HINT));
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint, 440);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 214);

  // ---- one commit point for both answers -----------------------------
  lv_obj_t *btn_next = lv_btn_create(scr_welcome);
  lv_obj_set_size(btn_next, 200, 50);
  lv_obj_align(btn_next, LV_ALIGN_BOTTOM_MID, 0, -10);
  lv_obj_set_style_bg_color(btn_next, lv_color_hex(0x0a2a40), 0);
  lv_obj_set_style_bg_color(btn_next, lv_color_hex(0x1a4060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_next, 10, 0);
  lv_obj_set_style_shadow_width(btn_next, 0, 0);
  lv_obj_set_style_border_width(btn_next, 2, 0);
  lv_obj_set_style_border_color(btn_next, lv_color_hex(0x28d49a), 0);
  lv_obj_t *lbl_next = lv_label_create(btn_next);
  { char buf[24]; strncpy(buf, T(STR_BTN_NEXT), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    lv_label_set_text(lbl_next, buf); }
  lv_obj_set_style_text_color(lbl_next, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_next, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_next);
  lv_obj_add_event_cb(btn_next, [](lv_event_t *e){
    // Both answers land together and the device restarts once. Picking German
    // used to restart on the spot, which meant the zone could only ever be
    // asked afterwards, on a device already running on the wrong clock.
    const bool de = (wel_lang_sel == 0);
    if (wel_tz_sel >= 0 && (size_t)wel_tz_sel < TZ_COUNT) {
      timeZoneSet(TZ_LIST[wel_tz_sel].tz);
    }
    prefsPutUChar("lang", de ? 0 : 1);
    prefsPutBool("lang_set", true);
    prefsPutBool("first_boot", true);
    logSDf("Setup: language=%s zone=%s -> restart",
           de ? "DE" : "EN",
           (wel_tz_sel >= 0 && (size_t)wel_tz_sel < TZ_COUNT) ? TZ_LIST[wel_tz_sel].name : "?");
    ESP.restart();
  }, LV_EVENT_CLICKED, NULL);

  welRefresh();
}

void showFirstBootScreen() {
  logSD("SHOW: FirstBootScreen");
  logSD("UI: Screen -> FirstBoot");
  hideAllOverlays();
  if (!scr_first_boot) buildFirstBootScreen();
  lv_obj_clear_flag(scr_first_boot, LV_OBJ_FLAG_HIDDEN);
}

void buildFirstBootScreen() {
  logSD("BUILD: FirstBootScreen");
  releaseScreen(&scr_first_boot);
  scr_first_boot = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_first_boot, 480, 320);
  lv_obj_set_pos(scr_first_boot, 0, 0);
  lv_obj_add_flag(scr_first_boot, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_first_boot, 0, 0);
  lv_obj_set_style_border_width(scr_first_boot, 0, 0);
  lv_obj_set_style_pad_all(scr_first_boot, 0, 0);
  lv_obj_clear_flag(scr_first_boot, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_first_boot, lv_color_hex(0x0a1020), 0);

  lv_obj_t *lbl_logo = lv_label_create(scr_first_boot);
  lv_label_set_text(lbl_logo, "SpoolmanScale");
  lv_obj_set_style_text_color(lbl_logo, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_logo, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(lbl_logo, LV_ALIGN_TOP_MID, 0, 32);

  lv_obj_t *lbl_title = lv_label_create(scr_first_boot);
  lv_label_set_text(lbl_title, T(STR_FIRSTBOOT_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_20, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 72);

  lv_obj_t *lbl_sub = lv_label_create(scr_first_boot);
  lv_label_set_text(lbl_sub, T(STR_FIRSTBOOT_SUB));
  lv_obj_set_style_text_color(lbl_sub, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_sub, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_sub, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_sub, LV_ALIGN_TOP_MID, 0, 104);

  lv_obj_t *lbl_hint = lv_label_create(scr_first_boot);
  // No backendText() here: at this point no backend has been chosen, and the
  // text deliberately names both. Substituting would turn it into
  // "FilaMan/FilaMan" once a mode is stored.
  { char hb[128]; strncpy(hb, T(STR_FIRSTBOOT_HINT), sizeof(hb) - 1); hb[sizeof(hb) - 1] = '\0';
    lv_label_set_text(lbl_hint, hb); }
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint, 420);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 138);

  if (strlen(cfg_wifi_ssid) > 0) {
    lv_obj_t *btn_cx = lv_btn_create(scr_first_boot);
    lv_obj_set_size(btn_cx, 44, 44);
    lv_obj_align(btn_cx, LV_ALIGN_TOP_RIGHT, -4, 2);
    lv_obj_set_style_bg_color(btn_cx, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_cx, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_cx, 8, 0);
    lv_obj_set_style_shadow_width(btn_cx, 0, 0);
    lv_obj_set_style_border_width(btn_cx, 0, 0);
    lv_obj_add_event_cb(btn_cx, [](lv_event_t *e){ logSD("BTN: Close -> Main"); showMainScreen(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_cx = lv_label_create(btn_cx);
    lv_label_set_text(lbl_cx, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(lbl_cx, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_cx, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(lbl_cx);
  }

  lv_obj_t *btn_start = lv_btn_create(scr_first_boot);
  lv_obj_set_size(btn_start, 226, 48);
  lv_obj_set_pos(btn_start, 12, 252);
  lv_obj_set_style_bg_color(btn_start, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_start, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_start, 10, 0);
  lv_obj_set_style_shadow_width(btn_start, 0, 0);
  lv_obj_set_style_border_width(btn_start, 1, 0);
  lv_obj_set_style_border_color(btn_start, lv_color_hex(0x2a5030), 0);
  lv_obj_add_event_cb(btn_start, [](lv_event_t *e) {
    prefsPutBool("first_boot", false);
    cfg_first_boot = false;
    showWifiSetupScreen();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_start = lv_label_create(btn_start);
  lv_label_set_text(lbl_start, T(STR_FIRSTBOOT_BTN));
  lv_obj_set_style_text_color(lbl_start, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_start, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_start, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_start, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *btn_skip = lv_btn_create(scr_first_boot);
  lv_obj_set_size(btn_skip, 226, 48);
  lv_obj_set_pos(btn_skip, 242, 252);
  lv_obj_set_style_bg_color(btn_skip, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_skip, lv_color_hex(0x1a2840), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_skip, 10, 0);
  lv_obj_set_style_shadow_width(btn_skip, 0, 0);
  lv_obj_set_style_border_width(btn_skip, 1, 0);
  lv_obj_set_style_border_color(btn_skip, lv_color_hex(0x1a2840), 0);
  lv_obj_add_event_cb(btn_skip, [](lv_event_t *e) {
    skip_setup_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_skip = lv_label_create(btn_skip);
  char skip_buf[32];
  strncpy(skip_buf, T(STR_BTN_SKIP_SETUP), sizeof(skip_buf)-1);
  lv_label_set_text(lbl_skip, skip_buf);
  lv_obj_set_style_text_color(lbl_skip, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_skip, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_skip, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_skip, LV_ALIGN_CENTER, 0, 0);
}
