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
#include "setup_frame.h"
#include "wifi_setup_screen.h"
#include "services/time_service.h"
#include "services/wifi_manager.h"
#include "timezone_screen.h"
#include "theme.h"

// ============================================================
//  LANGUAGE - the very first screen
// ============================================================

// Shown before anything else, so it cannot assume a language: the line under
// the logo greets in all three, and each language names itself.
struct LangRow { const char *name; uint8_t lang; };
static const LangRow LANG_ROWS[] = {
  { "English",  LANG_EN },
  { "Deutsch",  LANG_DE },
  { "Français", LANG_FR },
  { "中文",     LANG_ZH },
};
static_assert(sizeof(LANG_ROWS) / sizeof(LANG_ROWS[0]) == LANG_COUNT,
              "LANG_ROWS is out of step with enum Lang");

#define LANG_ROW_X        24
#define LANG_ROW_W       432
#define LANG_ROW_H        52
#define LANG_ROW_Y0       72
#define LANG_ROW_STEP     60
#define LANG_LOGO_Y       12
#define LANG_GREETING_Y   44
#define LANG_TEXT_INSET   18

static void onLanguagePicked(lv_event_t *e) {
  static const char *const LANG_TAG[] = { "DE", "EN", "FR", "ZH" };
  static_assert(sizeof(LANG_TAG) / sizeof(LANG_TAG[0]) == LANG_COUNT,
                "LANG_TAG is out of step with enum Lang");
  const uint8_t lang = (uint8_t)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
  if (lang >= LANG_COUNT) return;
  prefsPutUChar("lang", lang);
  prefsPutBool("lang_set", true);
  prefsPutBool("first_boot", true);
  prefsFlush();      // parked while LVGL dispatches; the restart comes next
  logSDf("Setup: language=%s -> restart", LANG_TAG[lang]);
  ESP.restart();
}

static void addLanguageRow(lv_obj_t *scr, size_t i) {
  // Marked only when the language was chosen before and the screen was
  // reached by going back; on a new device nothing is chosen yet.
  const bool active = cfg_lang_set && LANG_ROWS[i].lang == (uint8_t)g_lang;

  lv_obj_t *b = lv_btn_create(scr);
  lv_obj_set_size(b, LANG_ROW_W, LANG_ROW_H);
  lv_obj_set_pos(b, LANG_ROW_X, LANG_ROW_Y0 + (int)i * LANG_ROW_STEP);
  lv_obj_set_style_radius(b, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(active ? UI_COL_PICKED_BG : UI_COL_SURFACE), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(b, active ? 2 : 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(active ? UI_COL_ACCENT : UI_COL_LINE_SOFT), 0);
  lv_obj_set_user_data(b, (void *)(intptr_t)LANG_ROWS[i].lang);
  lv_obj_add_event_cb(b, onLanguagePicked, LV_EVENT_CLICKED, NULL);

  lv_obj_t *l = lv_label_create(b);
  lv_label_set_text(l, LANG_ROWS[i].name);
  lv_obj_set_style_text_font(l, UI_FONT_HEADLINE, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK), 0);
  lv_obj_align(l, LV_ALIGN_LEFT_MID, LANG_TEXT_INSET, 0);

  lv_obj_t *a = lv_label_create(b);
  lv_label_set_text(a, active ? LV_SYMBOL_OK : LV_SYMBOL_RIGHT);
  lv_obj_set_style_text_font(a, UI_FONT_BODY, 0);
  lv_obj_set_style_text_color(a, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_align(a, LV_ALIGN_RIGHT_MID, -LANG_TEXT_INSET, 0);
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
  scr_welcome = buildOverlayScreen();

  // Back to the welcome screen once a language is set: that is where going
  // back from the WiFi step leads, one step further back lands here.
  if (cfg_lang_set) {
    addBackButton(scr_welcome, [](lv_event_t *e){
      logSD("BTN: Language -> Welcome");
      showFirstBootScreen();
    });
  }

  lv_obj_t *logo = lv_label_create(scr_welcome);
  lv_label_set_text(logo, "SpoolmanScale");
  lv_obj_set_style_text_color(logo, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(logo, UI_FONT_ICON, 0);
  lv_obj_align(logo, LV_ALIGN_TOP_MID, 0, LANG_LOGO_Y);

  lv_obj_t *greet = lv_label_create(scr_welcome);
  lv_label_set_text(greet, T(STR_WELCOME_TRILINGUAL));
  lv_obj_set_style_text_color(greet, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_style_text_font(greet, UI_FONT_BODY, 0);
  lv_obj_align(greet, LV_ALIGN_TOP_MID, 0, LANG_GREETING_Y);

  for (size_t i = 0; i < LANG_COUNT; i++) addLanguageRow(scr_welcome, i);
}

// ============================================================
//  WELCOME - after the language restart
// ============================================================

#define FB_STEPS_Y        56
#define FB_TILE_X0        12
#define FB_TILE_Y         78
#define FB_TILE_W        109
#define FB_TILE_H         56
#define FB_TILE_GAP        6
#define FB_TILE_DISC      22
#define FB_TILE_PAD        8
#define FB_TZ_CAPTION_X   14
#define FB_TZ_CAPTION_Y  148
#define FB_TZ_ROW_X       12
#define FB_TZ_ROW_Y      166
#define FB_TZ_ROW_W      456
#define FB_TZ_ROW_H       50
#define FB_TZ_INSET       14
#define FB_TZ_LINE_INSET   7   // name and offset, from the row's top and bottom

// One step of the setup as a tile: its number over its name. Shows what is
// ahead; it is not a button.
static void addStepTile(lv_obj_t *scr, int i, int str_id) {
  lv_obj_t *tile = lv_obj_create(scr);
  lv_obj_set_size(tile, FB_TILE_W, FB_TILE_H);
  lv_obj_set_pos(tile, FB_TILE_X0 + i * (FB_TILE_W + FB_TILE_GAP), FB_TILE_Y);
  lv_obj_set_style_pad_all(tile, 0, 0);
  lv_obj_set_style_radius(tile, UI_RADIUS_ROW, 0);
  lv_obj_set_style_bg_color(tile, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_width(tile, 1, 0);
  lv_obj_set_style_border_color(tile, lv_color_hex(UI_COL_LINE_SOFT), 0);
  lv_obj_clear_flag(tile, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *disc = lv_obj_create(tile);
  lv_obj_remove_style_all(disc);
  lv_obj_set_size(disc, FB_TILE_DISC, FB_TILE_DISC);
  lv_obj_set_style_radius(disc, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_opa(disc, LV_OPA_COVER, 0);
  lv_obj_set_style_bg_color(disc, lv_color_hex(UI_COL_PICKED_BG), 0);
  lv_obj_align(disc, LV_ALIGN_TOP_MID, 0, FB_TILE_PAD - 2);
  char num[4];
  snprintf(num, sizeof(num), "%d", i + 1);
  lv_obj_t *n = lv_label_create(disc);
  lv_label_set_text(n, num);
  lv_obj_set_style_text_font(n, UI_FONT_CAPTION, 0);
  lv_obj_set_style_text_color(n, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_center(n);

  lv_obj_t *l = setupCenteredLabel(tile, T(str_id), UI_FONT_SMALL, FB_TILE_W - 2 * FB_TILE_PAD);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK), 0);
  lv_obj_align(l, LV_ALIGN_BOTTOM_MID, 0, -FB_TILE_PAD);
}

static void addZoneRow(lv_obj_t *scr) {
  lv_obj_t *cap = lv_label_create(scr);
  lv_label_set_text(cap, T(STR_TZ_TITLE));
  lv_obj_set_style_text_font(cap, UI_FONT_CAPTION, 0);
  lv_obj_set_style_text_color(cap, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_pos(cap, FB_TZ_CAPTION_X, FB_TZ_CAPTION_Y);

  lv_obj_t *b = lv_btn_create(scr);
  lv_obj_set_size(b, FB_TZ_ROW_W, FB_TZ_ROW_H);
  lv_obj_set_pos(b, FB_TZ_ROW_X, FB_TZ_ROW_Y);
  lv_obj_set_style_radius(b, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(b, 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_LINE_SOFT), 0);
  lv_obj_set_style_pad_all(b, 0, 0);
  lv_obj_add_event_cb(b, [](lv_event_t *e){
    logSD("BTN: Welcome -> Time zone");
    setTimeZoneReturnToWelcome(true);
    show_timezone_pending = true;
  }, LV_EVENT_CLICKED, NULL);

  const int idx = timeZoneIndex();
  const bool known = idx >= 0 && (size_t)idx < TZ_COUNT;
  lv_obj_t *name = lv_label_create(b);
  lv_label_set_text(name, known ? TZ_LIST[idx].name : "");
  lv_obj_set_style_text_font(name, UI_FONT_BODY, 0);
  lv_obj_set_style_text_color(name, lv_color_hex(UI_COL_INK), 0);
  lv_obj_align(name, LV_ALIGN_TOP_LEFT, FB_TZ_INSET, FB_TZ_LINE_INSET);

  lv_obj_t *off = lv_label_create(b);
  lv_label_set_text(off, known ? TZ_LIST[idx].offset : "");
  lv_obj_set_style_text_font(off, UI_FONT_CAPTION, 0);
  lv_obj_set_style_text_color(off, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_align(off, LV_ALIGN_BOTTOM_LEFT, FB_TZ_INSET, -FB_TZ_LINE_INSET);

  lv_obj_t *arr = lv_label_create(b);
  lv_label_set_text(arr, LV_SYMBOL_RIGHT);
  lv_obj_set_style_text_font(arr, UI_FONT_BODY, 0);
  lv_obj_set_style_text_color(arr, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_align(arr, LV_ALIGN_RIGHT_MID, -FB_TZ_INSET, 0);
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

  // The zone the language suggests, stored now: the row shows it, the picker
  // marks it, and skipping the setup keeps it. A zone picked earlier stays.
  if (timeZoneIndex() < 0) {
    const int def = timeZoneDefaultIndexForLang((uint8_t)g_lang);
    if (def >= 0 && (size_t)def < TZ_COUNT) {
      timeZoneSet(TZ_LIST[def].tz);
      logSDf("Setup: time zone %s from the language", TZ_LIST[def].name);
    }
  }

  scr_first_boot = buildOverlayScreen();
  setupHeader(scr_first_boot, T(STR_FIRSTBOOT_TITLE), SETUP_STEP_NONE, [](lv_event_t *e){
    logSD("BTN: Welcome -> Language");
    showWelcomeScreen();
  });

  lv_obj_t *ahead = lv_label_create(scr_first_boot);
  lv_label_set_text(ahead, T(STR_WELCOME_STEPS_AHEAD));
  lv_obj_set_style_text_font(ahead, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_color(ahead, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_align(ahead, LV_ALIGN_TOP_MID, 0, FB_STEPS_Y);

  static const int TILE_STR[] = {
    STR_SETUP_TILE_WIFI, STR_SETUP_TILE_BACKEND, STR_SETUP_TILE_SERVER, STR_SETUP_TILE_SCALE
  };
  for (int i = 0; i < (int)(sizeof(TILE_STR) / sizeof(TILE_STR[0])); i++) {
    addStepTile(scr_first_boot, i, TILE_STR[i]);
  }

  addZoneRow(scr_first_boot);

  setupActionBar(scr_first_boot,
    T(STR_SETUP_SKIP), [](lv_event_t *e){
      logSD("BTN: Welcome -> Skip setup");
      skip_setup_pending = true;
    },
    T(STR_SETUP_START), [](lv_event_t *e){
      logSD("BTN: Welcome -> Start");
      prefsPutBool("first_boot", false);
      cfg_first_boot = false;
      // A link the web flasher already brought up is shown with the choice to
      // keep or change it. A scan would drop it before the user decided.
      if (wifiManagerIsConnected()) showWifiConnectedScreen();
      else                          showWifiSetupScreen();
    });
}
