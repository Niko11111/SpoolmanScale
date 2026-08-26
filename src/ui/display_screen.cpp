#include "display_screen.h"
#include "navigation.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <stdint.h>

#include "hardware/display.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "ui_common.h"
#include "theme.h"



static void rebuildDisplayScreen() {
  if (scr_display) {
    lv_obj_del(scr_display);
    scr_display = nullptr;
  }
  buildDisplayScreen();
  lv_obj_clear_flag(scr_display, LV_OBJ_FLAG_HIDDEN);
}

void buildDisplayScreen() {
  logSD("BUILD: DisplayScreen");
  if (sd_verbose) logSD("[verbose] buildDisplayScreen: start");
  releaseScreen(&scr_display);
  scr_display = buildOverlayScreen();
  buildSubHeader(scr_display, T(STR_DISPLAY_TITLE),
    [](lv_event_t *e){ logSD("BTN: Back -> Settings"); showSettingsScreen(); });

  lv_obj_t *lbl_bright = lv_label_create(scr_display);
  lv_label_set_text(lbl_bright, T(STR_BRIGHT_LABEL));
  lv_obj_set_style_text_color(lbl_bright, tc(TH_TEXT), 0);
  lv_obj_set_style_text_font(lbl_bright, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_bright, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_bright, LV_ALIGN_TOP_MID, 0, 54);

  lv_obj_t *slider = lv_slider_create(scr_display);
  lv_obj_set_size(slider, 456, 20);
  lv_obj_set_pos(slider, 12, 76);
  lv_slider_set_range(slider, BRIGHT_MIN, BRIGHT_MAX);
  lv_slider_set_value(slider, bright_normal, LV_ANIM_OFF);
  lv_obj_set_style_bg_color(slider, tc(TH_SURFACE_2), LV_PART_MAIN);
  lv_obj_set_style_bg_color(slider, tc(TH_ACCENT), LV_PART_INDICATOR);
  lv_obj_set_style_bg_color(slider, tc(TH_ACCENT), LV_PART_KNOB);

  lv_obj_add_event_cb(slider, [](lv_event_t *e) {
    lv_obj_t *s = lv_event_get_target(e);
    int val = lv_slider_get_value(s);
    bright_normal = val;
    displaySetBrightness((uint8_t)val);
  }, LV_EVENT_VALUE_CHANGED, NULL);
  lv_obj_add_event_cb(slider, [](lv_event_t *e) {
    int val = lv_slider_get_value(lv_event_get_target(e));
    prefsPutUChar("bright", (uint8_t)val);
    Serial.printf("Brightness saved: %d\n", val);
  }, LV_EVENT_RELEASED, NULL);

  lv_obj_t *lbl_dim = lv_label_create(scr_display);
  lv_label_set_text(lbl_dim, T(STR_DIM_LABEL));
  lv_obj_set_style_text_color(lbl_dim, tc(TH_TEXT), 0);
  lv_obj_set_style_text_font(lbl_dim, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_dim, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_dim, LV_ALIGN_TOP_MID, 0, 108);

  int dim_vals[] = {1, 2, 5, 10};
  int cur_dim = dim_timeout_ms / 60000;
  const int BTN_W = 88, BTN_H = 36, BTN_GAP = 8;
  const int BTN_START_X = (480 - 4*BTN_W - 3*BTN_GAP) / 2;
  for (int i = 0; i < 4; i++) {
    lv_obj_t *b = lv_btn_create(scr_display);
    lv_obj_set_size(b, BTN_W, BTN_H);
    lv_obj_set_pos(b, BTN_START_X + i * (BTN_W + BTN_GAP), 130);
    bool active = (cur_dim == dim_vals[i]);
    lv_obj_set_style_bg_color(b, active ? tc(TH_ACCENT) : tc(TH_SURFACE_2), 0);
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_border_width(b, 0, 0);
    char buf[8]; snprintf(buf, sizeof(buf), "%d Min", dim_vals[i]);
    lv_obj_t *l = lv_label_create(b);
    lv_label_set_text(l, buf);
    lv_obj_set_style_text_color(l, active ? tc(TH_BG) : tc(TH_TEXT), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_14, 0);
    lv_obj_center(l);
    lv_obj_add_event_cb(b, [](lv_event_t *e) {
      int val = (intptr_t)lv_event_get_user_data(e);
      dim_timeout_ms = val * 60000;
      prefsPutUInt("dim_min", val);
      rebuildDisplayScreen();
      Serial.printf("Dim timeout: %d min\n", val);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)dim_vals[i]);
  }

  lv_obj_t *lbl_sleep = lv_label_create(scr_display);
  lv_label_set_text(lbl_sleep, T(STR_SLEEP_LABEL));
  lv_obj_set_style_text_color(lbl_sleep, tc(TH_TEXT), 0);
  lv_obj_set_style_text_font(lbl_sleep, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_sleep, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_sleep, LV_ALIGN_TOP_MID, 0, 178);

  // 0 means never sleep. Needed for the FilaMan remote link: in deep sleep
  // the ESP32 is off, so the scale drops out of FilaMan after 180 seconds and
  // the write-tag trigger cannot reach it at all.
  int sleep_vals[] = {10, 20, 30, 60, 0};
  const int SLEEP_BTN_GAP = 4;   // five buttons need a tighter gap than four
  const int SLEEP_START_X = (480 - 5*BTN_W - 4*SLEEP_BTN_GAP) / 2;
  int cur_sleep = sleep_timeout_ms / 60000;
  for (int i = 0; i < 5; i++) {
    lv_obj_t *b = lv_btn_create(scr_display);
    lv_obj_set_size(b, BTN_W, BTN_H);
    lv_obj_set_pos(b, SLEEP_START_X + i * (BTN_W + SLEEP_BTN_GAP), 200);
    bool active = (cur_sleep == sleep_vals[i]);
    lv_obj_set_style_bg_color(b, active ? tc(TH_ACCENT) : tc(TH_SURFACE_2), 0);
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_border_width(b, 0, 0);
    char buf[16];
    if (sleep_vals[i] == 0) {
      strncpy(buf, T(STR_SLEEP_OFF), sizeof(buf) - 1);
      buf[sizeof(buf) - 1] = '\0';
    } else {
      snprintf(buf, sizeof(buf), "%d Min", sleep_vals[i]);
    }
    lv_obj_t *l = lv_label_create(b);
    lv_label_set_text(l, buf);
    lv_obj_set_style_text_color(l, active ? tc(TH_BG) : tc(TH_TEXT), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_14, 0);
    lv_obj_center(l);
    lv_obj_add_event_cb(b, [](lv_event_t *e) {
      int val = (intptr_t)lv_event_get_user_data(e);
      sleep_timeout_ms = val * 60000;
      prefsPutUInt("sleep_min", val);
      rebuildDisplayScreen();
      Serial.printf("Sleep timeout: %d min\n", val);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)sleep_vals[i]);
  }

  lv_obj_t *hint = lv_label_create(scr_display);
  lv_label_set_text(hint, T(STR_DISPLAY_HINT));
  lv_obj_set_style_text_color(hint, tc(TH_TEXT_DIM), 0);
  lv_obj_set_style_text_font(hint, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(hint, 440);
  lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -8);
  if (sd_verbose) logSD("[verbose] buildDisplayScreen: done");
}
