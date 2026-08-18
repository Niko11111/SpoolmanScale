#include "theme_screen.h"
#include "navigation.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>

#include "display_screen.h"
#include "hardware/display.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "services/wifi_manager.h"
#include "theme.h"
#include "ui_common.h"

// The one screen that repaints live while a colour is being dragged in the web
// editor. It can do that safely because every object on it is created here, so
// tearing it down and rebuilding it frees nothing another module is holding.
// The main screen cannot do the same -- see themeInvalidateScreens().

lv_obj_t *scr_theme = nullptr;

static const uint16_t GAIN_STEPS[] = { 100, 140, 180, 220 };
static const int GAIN_STEP_COUNT = (int)(sizeof(GAIN_STEPS) / sizeof(GAIN_STEPS[0]));

static lv_obj_t* patch(lv_obj_t *parent, int x, int y, int w, int h, ThemeColor col) {
  lv_obj_t *o = lv_obj_create(parent);
  lv_obj_set_size(o, w, h);
  lv_obj_set_pos(o, x, y);
  lv_obj_set_style_radius(o, 0, 0);
  lv_obj_set_style_border_width(o, 0, 0);
  lv_obj_set_style_pad_all(o, 0, 0);
  lv_obj_clear_flag(o, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(o, tc(col), 0);
  lv_obj_set_style_bg_opa(o, LV_OPA_COVER, 0);
  return o;
}

static void text(lv_obj_t *parent, int x, int y, const char *s,
                 ThemeColor col, const lv_font_t *font) {
  lv_obj_t *l = lv_label_create(parent);
  lv_label_set_text(l, s);
  lv_obj_set_style_text_color(l, tc(col), 0);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_pos(l, x, y);
}

static lv_obj_t* smallBtn(lv_obj_t *parent, int x, int y, int w, int h,
                          const char *label, bool active,
                          lv_event_cb_t cb, void *ud) {
  lv_obj_t *b = lv_btn_create(parent);
  lv_obj_set_size(b, w, h);
  lv_obj_set_pos(b, x, y);
  lv_obj_set_style_bg_color(b, active ? tc(TH_ACCENT) : tc(TH_SURFACE_2), 0);
  lv_obj_set_style_radius(b, 6, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_border_width(b, 0, 0);
  lv_obj_add_event_cb(b, cb, LV_EVENT_CLICKED, ud);
  lv_obj_t *l = lv_label_create(b);
  lv_label_set_text(l, label);
  lv_obj_set_style_text_color(l, active ? tc(TH_ON_ACCENT) : tc(TH_TEXT), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(l);
  return b;
}

// A miniature of the real UI, drawn from the live palette, so every token that
// matters is visible at once while it is being edited.
static void buildSample(lv_obj_t *parent, int x, int y, int w, int h) {
  lv_obj_t *card = patch(parent, x, y, w, h, TH_BG);
  lv_obj_set_style_border_width(card, 1, 0);
  lv_obj_set_style_border_color(card, tc(TH_BORDER), 0);

  patch(card, 0, 0, w, 24, TH_SURFACE);
  text(card, 8, 4, "SpoolmanScale", TH_ACCENT, &lv_font_montserrat_ext_16);

  lv_obj_t *row = patch(card, 8, 28, 196, 44, TH_SURFACE_2);
  text(row, 8, 4,  "PLA Matte", TH_TEXT, &lv_font_montserrat_ext_14);
  text(row, 8, 24, "742 g left", TH_TEXT_MUTED, &lv_font_montserrat_ext_12);

  lv_obj_t *ok = patch(card, 214, 28, 100, 44, TH_ACCENT);
  text(ok, 20, 13, "CONFIRM", TH_ON_ACCENT, &lv_font_montserrat_ext_14);

  lv_obj_t *no = patch(card, 322, 28, 100, 44, TH_DANGER_BG);
  text(no, 26, 13, "CANCEL", TH_DANGER_TEXT, &lv_font_montserrat_ext_14);

  text(card, 8,   78, "Bright",  TH_TEXT_BRIGHT,   &lv_font_montserrat_ext_12);
  text(card, 62,  78, "Body",    TH_TEXT,          &lv_font_montserrat_ext_12);
  text(card, 108, 78, "Muted",   TH_TEXT_MUTED,    &lv_font_montserrat_ext_12);
  text(card, 160, 78, "Hint",    TH_TEXT_DIM,      &lv_font_montserrat_ext_12);
  text(card, 204, 78, "Warning", TH_WARNING,       &lv_font_montserrat_ext_12);
  text(card, 262, 78, "Success", TH_SUCCESS_TEXT,  &lv_font_montserrat_ext_12);
  text(card, 320, 78, "Danger",  TH_DANGER_TEXT,   &lv_font_montserrat_ext_12);
}

void buildThemeScreen() {
  logSD("BUILD: ThemeScreen");
  releaseScreen(&scr_theme);
  scr_theme = buildOverlayScreen(&scr_theme);
  buildSubHeader(scr_theme, T(STR_THEME_TITLE),
    [](lv_event_t *e){ logSD("BTN: Back -> Display"); buildDisplayScreen();
                       hideAllOverlays();
                       lv_obj_clear_flag(scr_display, LV_OBJ_FLAG_HIDDEN); });

  buildSample(scr_theme, 12, 46, 456, 100);

  const int X0 = 12;

  // Five choices, not four: a palette edited in the web UI matches no preset,
  // so without a Custom slot the highlight would show nothing selected and
  // tapping a preset would throw the edit away with no way back.
  const int PW = 88, PGAP = 4;
  text(scr_theme, X0, 150, T(STR_THEME_PRESET), TH_TEXT_MUTED, &lv_font_montserrat_ext_12);
  const int cur_preset = themeCurrentPreset();
  for (int i = 0; i < THEME_PRESET_COUNT; i++) {
    smallBtn(scr_theme, X0 + i * (PW + PGAP), 164, PW, 28,
             themePresetName(i), i == cur_preset,
             [](lv_event_t *e) {
               int idx = (int)(intptr_t)lv_event_get_user_data(e);
               themeApplyPreset(idx);
               themeSave();
               themeInvalidateScreens();
               buildThemeScreen();
               lv_obj_clear_flag(scr_theme, LV_OBJ_FLAG_HIDDEN);
             }, (void*)(intptr_t)i);
  }
  {
    const bool has = themeHasCustom();
    lv_obj_t *b = smallBtn(scr_theme, X0 + THEME_PRESET_COUNT * (PW + PGAP), 164,
                           PW, 28, T(STR_THEME_CUSTOM), has && cur_preset < 0,
                           [](lv_event_t *e) {
                             if (!themeHasCustom()) return;
                             themeApplyCustom();
                             themeSave();
                             themeInvalidateScreens();
                             buildThemeScreen();
                             lv_obj_clear_flag(scr_theme, LV_OBJ_FLAG_HIDDEN);
                           }, nullptr);
    // Nothing saved yet: leave it visible but obviously inert rather than
    // hiding it, so the slot is discoverable before it is populated.
    if (!has) lv_obj_set_style_bg_opa(b, LV_OPA_40, 0);
  }

  const int BW = 110, GAP = 5;
  text(scr_theme, X0, 196, T(STR_THEME_GAIN), TH_TEXT_MUTED,
       &lv_font_montserrat_ext_12);
  const uint16_t cur_gain = displayGetUiGain();
  for (int i = 0; i < GAIN_STEP_COUNT; i++) {
    char buf[12];
    snprintf(buf, sizeof(buf), "%u.%u", GAIN_STEPS[i] / 100, (GAIN_STEPS[i] / 10) % 10);
    smallBtn(scr_theme, X0 + i * (BW + GAP), 210, BW, 28,
             buf, GAIN_STEPS[i] == cur_gain,
             [](lv_event_t *e) {
               uint16_t g = (uint16_t)(intptr_t)lv_event_get_user_data(e);
               displaySetUiGain(g);
               prefsPutUInt("ui_gain", g);
               buildThemeScreen();
               lv_obj_clear_flag(scr_theme, LV_OBJ_FLAG_HIDDEN);
             }, (void*)(intptr_t)GAIN_STEPS[i]);
  }

  // The bottom row is either the hint or, once a palette has been applied,
  // the way to finish applying it. Sharing the space keeps the screen from
  // growing a permanently half-relevant line, and the offer only appears when
  // there is something to restart for.
  if (themeRestartPending()) {
    lv_obj_t *b = lv_btn_create(scr_theme);
    lv_obj_set_size(b, 456, 34);
    lv_obj_set_pos(b, X0, 250);
    lv_obj_set_style_bg_color(b, tc(TH_OK_BG), 0);
    lv_obj_set_style_bg_color(b, tc(TH_SUCCESS_BG), LV_STATE_PRESSED);
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_border_width(b, 1, 0);
    lv_obj_set_style_border_color(b, tc(TH_ACCENT), 0);
    lv_obj_t *l = lv_label_create(b);
    lv_label_set_text(l, T(STR_THEME_RESTART));
    lv_obj_set_style_text_color(l, tc(TH_SUCCESS_TEXT), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_12, 0);
    lv_obj_center(l);
    lv_obj_add_event_cb(b, [](lv_event_t *e) {
      // The palette is already stored; this only restarts so the main screen
      // is rebuilt with it.
      logSD("Reboot: user (theme applied)");
      ESP.restart();
    }, LV_EVENT_CLICKED, NULL);
  } else {
    lv_obj_t *l = lv_label_create(scr_theme);
    lv_label_set_text(l, T(STR_THEME_HINT));
    lv_obj_set_style_text_color(l, tc(TH_TEXT_DIM), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_12, 0);
    lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(l, 456);
    lv_obj_set_pos(l, X0, 250);
  }
}

void showThemeScreen() {
  buildThemeScreen();
  hideAllOverlays();
  lv_obj_clear_flag(scr_theme, LV_OBJ_FLAG_HIDDEN);
}

bool themeScreenVisible() {
  return scr_theme && !lv_obj_has_flag(scr_theme, LV_OBJ_FLAG_HIDDEN);
}

void themeScreenRepaint() {
  if (!themeScreenVisible()) return;
  buildThemeScreen();
  lv_obj_clear_flag(scr_theme, LV_OBJ_FLAG_HIDDEN);
}
