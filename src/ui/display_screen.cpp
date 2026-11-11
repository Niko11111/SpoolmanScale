#include "display_screen.h"
#include "navigation.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <stdint.h>

#include "hardware/display.h"
#include "hardware/sound.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "ui_common.h"
#include "theme.h"



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

// Which half of the Display/Sound screen is showing. The two share one tile in
// Settings because there was no room for a fifth one, and the display half
// already fills its page. Kept across visits, like any other screen state.
enum { TAB_DISPLAY = 0, TAB_SOUND = 1 };
static int s_tab = TAB_DISPLAY;

static void buildDisplayTab(lv_obj_t *body);
static void buildSoundTab(lv_obj_t *scr);

// The two tabs sit in the header between back and close, where the title used
// to be, so neither half loses a pixel of its page to them.
static void buildTabs(lv_obj_t *scr) {
  const int TAB_W = 176, TAB_H = 40, TAB_Y = 4, TAB_GAP = 8;
  const int x0 = (LV_HOR_RES - 2 * TAB_W - TAB_GAP) / 2;
  const int ids[2] = { STR_DISPLAY_TITLE, STR_SOUND_TITLE };
  for (int i = 0; i < 2; i++) {
    const bool active = (s_tab == i);
    lv_obj_t *b = lv_btn_create(scr);
    lv_obj_set_size(b, TAB_W, TAB_H);
    lv_obj_set_pos(b, x0 + i * (TAB_W + TAB_GAP), TAB_Y);
    lv_obj_set_style_bg_color(b, lv_color_hex(active ? UI_COL_ACCENT : UI_COL_LINE), 0);
    lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_border_width(b, 0, 0);
    if (!active) uiSecondaryFill(b);
    lv_obj_t *l = lv_label_create(b);
    lv_label_set_text(l, T((StringID)ids[i]));
    lv_obj_set_style_text_color(l, lv_color_hex(active ? UI_COL_ON_ACCENT : UI_COL_INK_2), 0);
    lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
    lv_obj_center(l);
    lv_obj_add_event_cb(b, [](lv_event_t *e) {
      const int tab = (int)(intptr_t)lv_event_get_user_data(e);
      if (tab == s_tab) return;
      s_tab = tab;
      logSDf("UI: Display/Sound tab -> %s", tab == TAB_SOUND ? "Sound" : "Display");
      rebuildDisplayScreen();
    }, LV_EVENT_CLICKED, (void *)(intptr_t)i);
  }
}

void buildDisplayScreen() {
  logSD("BUILD: DisplayScreen");
  if (sd_verbose) logSD("[verbose] buildDisplayScreen: start");
  releaseScreen(&scr_display);
  scr_display = buildOverlayScreen();
  addBackButton(scr_display,
    [](lv_event_t *e){ logSD("BTN: Back -> Settings"); showSettingsScreen(); });
  addCloseButton(scr_display);
  buildTabs(scr_display);

  // The sound half is a plain option list, the way every settings screen
  // draws its switches.
  if (s_tab == TAB_SOUND) {
    buildSoundTab(scr_display);
    if (sd_verbose) logSD("[verbose] buildDisplayScreen: done");
    return;
  }

  // Everything below the header sits in one frame, purely so the row
  // coordinates below can be read against a common origin instead of against
  // the header. It does NOT scroll: "no scrollbars outside lists, everything
  // fits on one page" is the first rule in the design guide, and the four rows
  // end at 256 of the 270 px this frame has. A row added later that does not
  // fit will be visibly clipped, which forces a real decision rather than
  // quietly reintroducing a scrolling settings page.
  lv_obj_t *body = lv_obj_create(scr_display);
  lv_obj_set_size(body, 480, 270);
  lv_obj_set_pos(body, 0, 50);
  lv_obj_set_style_bg_opa(body, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(body, 0, 0);
  lv_obj_set_style_radius(body, 0, 0);
  lv_obj_set_style_pad_all(body, 0, 0);
  lv_obj_clear_flag(body, LV_OBJ_FLAG_SCROLLABLE);

  buildDisplayTab(body);

  if (sd_verbose) logSD("[verbose] buildDisplayScreen: done");
}

static void buildDisplayTab(lv_obj_t *body) {
  // Row coordinates in one place: a stage is a label plus a button row 22 px
  // under it. Collected here so adding a stage does not mean re-deriving every
  // offset below it by hand.
  const int Y_BRIGHT_LBL = 4,   Y_BRIGHT_SLIDER = 26;
  const int Y_DIM_LBL    = 58,  Y_DIM_ROW       = 80;
  const int Y_OFF_LBL    = 128, Y_OFF_ROW       = 150;
  const int Y_SLEEP_LBL  = 198, Y_SLEEP_ROW     = 220;

  lv_obj_t *lbl_bright = lv_label_create(body);
  lv_label_set_text(lbl_bright, T(STR_BRIGHT_LABEL));
  lv_obj_set_style_text_color(lbl_bright, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(lbl_bright, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_bright, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_bright, LV_ALIGN_TOP_MID, 0, Y_BRIGHT_LBL);

  lv_obj_t *slider = lv_slider_create(body);
  // 20 px in from either edge: the knob is drawn centred on the track's end
  // and overhung the screen at 255.
  lv_obj_set_size(slider, 440, 20);
  lv_obj_set_pos(slider, 20, Y_BRIGHT_SLIDER);
  lv_slider_set_range(slider, BRIGHT_MIN, BRIGHT_MAX);
  lv_slider_set_value(slider, bright_normal, LV_ANIM_OFF);
  lv_obj_set_style_bg_color(slider, lv_color_hex(UI_COL_LINE), LV_PART_MAIN);
  lv_obj_set_style_bg_color(slider, lv_color_hex(UI_COL_ACCENT), LV_PART_INDICATOR);
  lv_obj_set_style_bg_color(slider, lv_color_hex(UI_COL_ACCENT), LV_PART_KNOB);

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
  lv_obj_set_style_text_color(lbl_dim, lv_color_hex(UI_COL_INK_2), 0);
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
    lv_obj_set_style_bg_color(b, active ? lv_color_hex(UI_COL_ACCENT) : lv_color_hex(UI_COL_LINE), 0);
    if (!allowed) {
      lv_obj_set_style_bg_opa(b, LV_OPA_60, 0);
      lv_obj_clear_flag(b, LV_OBJ_FLAG_CLICKABLE);
    }
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_border_width(b, 0, 0);
    if (!active) uiSecondaryFill(b);
    char buf[16];
    if (dim_vals[i] == 0) {
      copyT(buf, sizeof(buf), STR_SCREENOFF_NEVER);
    } else {
      snprintf(buf, sizeof(buf), T(STR_MINUTES_FMT), dim_vals[i]);
    }
    lv_obj_t *l = lv_label_create(b);
    lv_label_set_text(l, buf);
    lv_obj_set_style_text_color(l, active ? lv_color_hex(UI_COL_ON_ACCENT)
                                 : (allowed ? lv_color_hex(UI_COL_INK_2)
                                            : lv_color_hex(UI_COL_UNAVAILABLE)), 0);
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
  lv_obj_set_style_text_color(lbl_off, lv_color_hex(UI_COL_INK_2), 0);
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
    lv_obj_set_style_bg_color(b, active ? lv_color_hex(UI_COL_ACCENT) : lv_color_hex(UI_COL_LINE), 0);
    if (!allowed) {
      lv_obj_set_style_bg_opa(b, LV_OPA_60, 0);
      lv_obj_clear_flag(b, LV_OBJ_FLAG_CLICKABLE);
    }
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_border_width(b, 0, 0);
    if (!active) uiSecondaryFill(b);
    char buf[16];
    if (off_vals[i] == 0) {
      copyT(buf, sizeof(buf), STR_SCREENOFF_NEVER);
    } else {
      snprintf(buf, sizeof(buf), T(STR_MINUTES_FMT), off_vals[i]);
    }
    lv_obj_t *l = lv_label_create(b);
    lv_label_set_text(l, buf);
    lv_obj_set_style_text_color(l, active ? lv_color_hex(UI_COL_ON_ACCENT)
                                 : (allowed ? lv_color_hex(UI_COL_INK_2)
                                            : lv_color_hex(UI_COL_UNAVAILABLE)), 0);
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
  lv_obj_set_style_text_color(lbl_sleep, lv_color_hex(UI_COL_INK_2), 0);
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
    lv_obj_set_style_bg_color(b, active ? lv_color_hex(UI_COL_ACCENT) : lv_color_hex(UI_COL_LINE), 0);
    if (!allowed) {
      lv_obj_set_style_bg_opa(b, LV_OPA_60, 0);
      lv_obj_clear_flag(b, LV_OBJ_FLAG_CLICKABLE);
    }
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_border_width(b, 0, 0);
    if (!active) uiSecondaryFill(b);
    char buf[16];
    if (sleep_vals[i] == 0) {
      copyT(buf, sizeof(buf), STR_SCREENOFF_NEVER);
    } else {
      snprintf(buf, sizeof(buf), T(STR_MINUTES_FMT), sleep_vals[i]);
    }
    lv_obj_t *l = lv_label_create(b);
    lv_label_set_text(l, buf);
    lv_obj_set_style_text_color(l, active ? lv_color_hex(UI_COL_ON_ACCENT)
                                 : (allowed ? lv_color_hex(UI_COL_INK_2)
                                            : lv_color_hex(UI_COL_UNAVAILABLE)), 0);
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
}

// ---------------------------------------------------------------------------
//  Sound tab
// ---------------------------------------------------------------------------

// Remembered across the rebuild a switch causes, so the list does not jump
// back to the top under the finger that just used it.
static lv_obj_t *s_sound_list = nullptr;
static lv_coord_t s_sound_scroll = 0;

// Every switch on this tab rebuilds the screen through releaseScreen(), which
// frees the old one asynchronously - never under the running callback.
static void rebuildSoundTab() {
  s_sound_scroll = s_sound_list ? lv_obj_get_scroll_y(s_sound_list) : 0;
  rebuildDisplayScreen();
}

// The NVS write can fail; the switch then still holds for this session.
static void saveBool(const char *key, bool v) {
  if (!prefsPutBool(key, v)) logSDf("Sound: saving %s failed, lost on restart", key);
}

// ON/OFF where the arrow would be, the way addSettingRow() shows a switch.
static void showOnOff(lv_obj_t *btn, bool on) {
  lv_obj_t *arr = lv_obj_get_child(btn, -1);
  if (!arr) return;
  char buf_v[8];
  copyT(buf_v, sizeof(buf_v), on ? STR_ON : STR_OFF);
  lv_label_set_text(arr, buf_v);
  lv_obj_set_style_text_color(arr, lv_color_hex(on ? UI_COL_ACCENT : UI_COL_CAPTION), 0);
  lv_obj_set_style_text_font(arr, UI_FONT_SMALL, 0);
}

static void soundToggleRow(lv_obj_t *list, StringID title, bool on, lv_event_cb_t cb) {
  char buf_t[48];
  copyT(buf_t, sizeof(buf_t), title);
  lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_BELL, buf_t, nullptr, on);
  showOnOff(btn, on);
  lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, NULL);
}

static void toggleAndSave(bool *value, const char *key) {
  *value = !*value;
  saveBool(key, *value);
  rebuildSoundTab();
}

// The rows behind the master switch only appear while it is on: with sound
// off they would be switches that do nothing.
static void buildSoundEventRows(lv_obj_t *list) {
  soundToggleRow(list, STR_SND_NFC, g_snd_nfc,
    [](lv_event_t *e) { toggleAndSave(&g_snd_nfc, "snd_nfc"); });
  soundToggleRow(list, STR_SND_WRITE, g_snd_write,
    [](lv_event_t *e) { toggleAndSave(&g_snd_write, "snd_write"); });
  soundToggleRow(list, STR_SND_WEIGHT, g_snd_weight,
    [](lv_event_t *e) { toggleAndSave(&g_snd_weight, "snd_weight"); });

  // Volume steps through its four values on each tap and plays the new one,
  // which doubles as the speaker test.
  static const StringID VOL_NAMES[SND_VOL_COUNT] = {
    STR_SND_VOL_LOW, STR_SND_VOL_MED, STR_SND_VOL_HIGH, STR_SND_VOL_MAX
  };
  char buf_t[32], buf_s[32];
  copyT(buf_t, sizeof(buf_t), STR_SND_VOLUME_LABEL);
  copyT(buf_s, sizeof(buf_s), VOL_NAMES[g_snd_volume < SND_VOL_COUNT ? g_snd_volume : SND_VOL_MED]);
  lv_obj_t *vol = makeListBtn(list, LV_SYMBOL_VOLUME_MID, buf_t, buf_s);
  lv_obj_add_event_cb(vol, [](lv_event_t *e) {
    g_snd_volume = (uint8_t)((g_snd_volume + 1) % SND_VOL_COUNT);
    if (!prefsPutUChar("snd_vol", g_snd_volume))
      logSD("Sound: saving the volume failed, lost on restart");
    soundPlay(SND_TEST);
    rebuildSoundTab();
  }, LV_EVENT_CLICKED, NULL);
}

static void buildSoundTab(lv_obj_t *scr) {
  lv_obj_t *list = buildOptionList(scr);
  s_sound_list = list;
  char buf_t[32], buf_s[48];
  copyT(buf_t, sizeof(buf_t), STR_SOUND_TITLE);
  copyT(buf_s, sizeof(buf_s), STR_SOUND_SUB);
  lv_obj_t *master = makeListBtn(list, LV_SYMBOL_VOLUME_MAX, buf_t, buf_s, g_sound_on);
  showOnOff(master, g_sound_on);
  lv_obj_add_event_cb(master, [](lv_event_t *e) {
    g_sound_on = !g_sound_on;
    saveBool("snd_on", g_sound_on);
    logSDf("Sound: %s", g_sound_on ? "on" : "off");
    if (g_sound_on) soundPlay(SND_TEST);
    rebuildSoundTab();
  }, LV_EVENT_CLICKED, NULL);

  if (g_sound_on) buildSoundEventRows(list);

  if (s_sound_scroll > 0) {
    lv_obj_update_layout(list);
    lv_obj_scroll_to_y(list, s_sound_scroll, LV_ANIM_OFF);
    s_sound_scroll = 0;
  }
}
