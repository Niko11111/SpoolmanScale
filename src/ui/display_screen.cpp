#include "display_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "services/user_options.h"

#include <Arduino.h>
#include <lvgl.h>
#include <stdint.h>

#include "hardware/display.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "ui_common.h"



// Called from the click callback of a button that lives inside the screen it
// replaces. buildDisplayScreen() opens with releaseScreen(), which frees the
// old one through lv_obj_del_async() at the end of the current
// lv_timer_handler() pass - so the object under the running callback stays
// alive until the callback has returned. The synchronous lv_obj_del() that
// used to stand here freed it mid-dispatch and only survived because nothing
// touched the target afterwards.
static void rebuildDisplayScreen() {
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

  // Everything below the header lives in a scrolling body. The screen itself
  // is 320 px and buildOverlayScreen() clears SCROLLABLE on it, so content
  // that outgrows the panel is clipped rather than reachable - and the idle
  // stages alone want more rows than fit. Positions stay absolute inside the
  // body; LVGL derives the scroll extent from the children.
  lv_obj_t *body = lv_obj_create(scr_display);
  lv_obj_set_size(body, 480, 270);
  lv_obj_set_pos(body, 0, 50);
  lv_obj_set_style_bg_opa(body, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(body, 0, 0);
  lv_obj_set_style_radius(body, 0, 0);
  lv_obj_set_style_pad_all(body, 0, 0);
  lv_obj_set_scroll_dir(body, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(body, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(body, LV_OBJ_FLAG_SCROLL_ELASTIC);

  // Row coordinates in one place: a stage is a label plus a button row 22 px
  // under it. Collected here so adding a stage does not mean re-deriving every
  // offset below it by hand.
  const int Y_BRIGHT_LBL = 4,   Y_BRIGHT_SLIDER = 26;
  const int Y_DIM_LBL    = 58,  Y_DIM_ROW       = 80;
  const int Y_OFF_LBL    = 128, Y_OFF_ROW       = 150;
  const int Y_SLEEP_LBL  = 198, Y_SLEEP_ROW     = 220;
  const int Y_WAKE_ROW   = 268;
  const int Y_HINT       = 314;

  lv_obj_t *lbl_bright = lv_label_create(body);
  lv_label_set_text(lbl_bright, T(STR_BRIGHT_LABEL));
  lv_obj_set_style_text_color(lbl_bright, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_bright, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_bright, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_bright, LV_ALIGN_TOP_MID, 0, Y_BRIGHT_LBL);

  lv_obj_t *slider = lv_slider_create(body);
  lv_obj_set_size(slider, 456, 20);
  lv_obj_set_pos(slider, 12, Y_BRIGHT_SLIDER);
  lv_slider_set_range(slider, BRIGHT_MIN, BRIGHT_MAX);
  lv_slider_set_value(slider, bright_normal, LV_ANIM_OFF);
  lv_obj_set_style_bg_color(slider, lv_color_hex(0x1a3060), LV_PART_MAIN);
  lv_obj_set_style_bg_color(slider, lv_color_hex(0x28d49a), LV_PART_INDICATOR);
  lv_obj_set_style_bg_color(slider, lv_color_hex(0x28d49a), LV_PART_KNOB);

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

  // Stages must stay in order: dim, screen off, sleep. Values that would
  // break it are drawn disabled below. 0 = never, so it never conflicts.
  const int cur_dim   = dim_timeout_ms / 60000;
  const int cur_off   = off_timeout_ms / 60000;
  const int cur_sleep = sleep_timeout_ms / 60000;

  lv_obj_t *lbl_dim = lv_label_create(body);
  lv_label_set_text(lbl_dim, T(STR_DIM_LABEL));
  lv_obj_set_style_text_color(lbl_dim, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_dim, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_dim, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_dim, LV_ALIGN_TOP_MID, 0, Y_DIM_LBL);

  int dim_vals[] = {1, 2, 5, 10, 0};
  const int BTN_W = 88, BTN_H = 36, BTN_GAP = 4;   // five buttons now, same spacing as the other rows
  const int BTN_START_X = (480 - 5*BTN_W - 4*BTN_GAP) / 2;
  for (int i = 0; i < 5; i++) {
    lv_obj_t *b = lv_btn_create(body);
    lv_obj_set_size(b, BTN_W, BTN_H);
    lv_obj_set_pos(b, BTN_START_X + i * (BTN_W + BTN_GAP), Y_DIM_ROW);
    bool active = (cur_dim == dim_vals[i]);
    const bool allowed = dim_vals[i] == 0 ||
                         ((cur_off == 0 || dim_vals[i] < cur_off) &&
                          (cur_sleep == 0 || dim_vals[i] < cur_sleep));
    lv_obj_set_style_bg_color(b, active ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a3060), 0);
    if (!allowed) {
      lv_obj_set_style_bg_opa(b, LV_OPA_40, 0);
      lv_obj_clear_flag(b, LV_OBJ_FLAG_CLICKABLE);
    }
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_border_width(b, 0, 0);
    char buf[16];
    if (dim_vals[i] == 0) {
      strncpy(buf, T(STR_SCREENOFF_NEVER), sizeof(buf) - 1);
      buf[sizeof(buf) - 1] = '\0';
    } else {
      snprintf(buf, sizeof(buf), "%d Min", dim_vals[i]);
    }
    lv_obj_t *l = lv_label_create(b);
    lv_label_set_text(l, buf);
    lv_obj_set_style_text_color(l, active ? lv_color_hex(0x0a1020)
                                 : (allowed ? lv_color_hex(0xc8d8f0)
                                            : lv_color_hex(0x2a4060)), 0);
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

  lv_obj_t *lbl_off = lv_label_create(body);
  lv_label_set_text(lbl_off, T(STR_SCREENOFF_LABEL));
  lv_obj_set_style_text_color(lbl_off, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_off, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_off, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_off, LV_ALIGN_TOP_MID, 0, Y_OFF_LBL);

  int off_vals[] = {2, 5, 10, 15, 0};
  const int OFF_BTN_GAP = 4;   // five buttons, same tighter gap as sleep
  const int OFF_START_X = (480 - 5*BTN_W - 4*OFF_BTN_GAP) / 2;
  for (int i = 0; i < 5; i++) {
    lv_obj_t *b = lv_btn_create(body);
    lv_obj_set_size(b, BTN_W, BTN_H);
    lv_obj_set_pos(b, OFF_START_X + i * (BTN_W + OFF_BTN_GAP), Y_OFF_ROW);
    bool active = (cur_off == off_vals[i]);
    const bool allowed = off_vals[i] == 0 ||
                         ((cur_dim == 0 || off_vals[i] > cur_dim) &&
                          (cur_sleep == 0 || off_vals[i] < cur_sleep));
    lv_obj_set_style_bg_color(b, active ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a3060), 0);
    if (!allowed) {
      lv_obj_set_style_bg_opa(b, LV_OPA_40, 0);
      lv_obj_clear_flag(b, LV_OBJ_FLAG_CLICKABLE);
    }
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_border_width(b, 0, 0);
    char buf[16];
    if (off_vals[i] == 0) {
      strncpy(buf, T(STR_SCREENOFF_NEVER), sizeof(buf) - 1);
      buf[sizeof(buf) - 1] = '\0';
    } else {
      snprintf(buf, sizeof(buf), "%d Min", off_vals[i]);
    }
    lv_obj_t *l = lv_label_create(b);
    lv_label_set_text(l, buf);
    lv_obj_set_style_text_color(l, active ? lv_color_hex(0x0a1020)
                                 : (allowed ? lv_color_hex(0xc8d8f0)
                                            : lv_color_hex(0x2a4060)), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_14, 0);
    lv_obj_center(l);
    lv_obj_add_event_cb(b, [](lv_event_t *e) {
      int val = (intptr_t)lv_event_get_user_data(e);
      off_timeout_ms = val * 60000;
      prefsPutUInt("off_min", val);
      rebuildDisplayScreen();
      Serial.printf("Screen-off timeout: %d min\n", val);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)off_vals[i]);
  }

  lv_obj_t *lbl_sleep = lv_label_create(body);
  lv_label_set_text(lbl_sleep, T(STR_SLEEP_LABEL));
  lv_obj_set_style_text_color(lbl_sleep, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_sleep, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_sleep, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_sleep, LV_ALIGN_TOP_MID, 0, Y_SLEEP_LBL);

  // 0 means never sleep. Needed for the FilaMan remote link: in deep sleep
  // the ESP32 is off, so the scale drops out of FilaMan after 180 seconds and
  // the write-tag trigger cannot reach it at all.
  int sleep_vals[] = {10, 20, 30, 60, 0};
  const int SLEEP_BTN_GAP = 4;   // five buttons need a tighter gap than four
  const int SLEEP_START_X = (480 - 5*BTN_W - 4*SLEEP_BTN_GAP) / 2;
  for (int i = 0; i < 5; i++) {
    lv_obj_t *b = lv_btn_create(body);
    lv_obj_set_size(b, BTN_W, BTN_H);
    lv_obj_set_pos(b, SLEEP_START_X + i * (BTN_W + SLEEP_BTN_GAP), Y_SLEEP_ROW);
    bool active = (cur_sleep == sleep_vals[i]);
    const bool allowed = sleep_vals[i] == 0 ||
                         ((cur_dim == 0 || sleep_vals[i] > cur_dim) &&
                          (cur_off == 0 || sleep_vals[i] > cur_off));
    lv_obj_set_style_bg_color(b, active ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a3060), 0);
    if (!allowed) {
      lv_obj_set_style_bg_opa(b, LV_OPA_40, 0);
      lv_obj_clear_flag(b, LV_OBJ_FLAG_CLICKABLE);
    }
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
    lv_obj_set_style_text_color(l, active ? lv_color_hex(0x0a1020)
                                 : (allowed ? lv_color_hex(0xc8d8f0)
                                            : lv_color_hex(0x2a4060)), 0);
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

  // Sits under the sleep row because it decides what may end the idle period,
  // which is the same subject as the timers above it. Full width: the upstream
  // PR made it half to pair with a theme button from another branch that is
  // not in this tree, and a lone half-width button reads as a missing one.
  {
    lv_obj_t *b = lv_btn_create(body);
    lv_obj_set_size(b, 456, 34);
    lv_obj_set_pos(b, 12, Y_WAKE_ROW);
    lv_obj_set_style_bg_color(b, g_wake_on_load ? lv_color_hex(0x28d49a)
                                                : lv_color_hex(0x1a3060), 0);
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_border_width(b, 0, 0);
    lv_obj_t *l = lv_label_create(b);
    char wbuf[40];
    snprintf(wbuf, sizeof(wbuf), "%s: %s", T(STR_WAKE_ON_LOAD),
             T(g_wake_on_load ? STR_ON : STR_OFF));
    lv_label_set_text(l, wbuf);
    lv_obj_set_style_text_color(l, g_wake_on_load ? lv_color_hex(0x0a1020)
                                                  : lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_14, 0);
    lv_obj_center(l);
    lv_obj_add_event_cb(b, [](lv_event_t *e) {
      g_wake_on_load = !g_wake_on_load;
      prefsPutBool("wake_load", g_wake_on_load);
      rebuildDisplayScreen();
      Serial.printf("Wake on load: %s\n", g_wake_on_load ? "on" : "off");
    }, LV_EVENT_CLICKED, NULL);
  }

  lv_obj_t *hint = lv_label_create(body);
  lv_label_set_text(hint, T(STR_DISPLAY_HINT));
  lv_obj_set_style_text_color(hint, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(hint, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(hint, 440);
  lv_obj_align(hint, LV_ALIGN_TOP_MID, 0, Y_HINT);
  if (sd_verbose) logSD("[verbose] buildDisplayScreen: done");
}
