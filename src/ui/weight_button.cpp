#include "weight_button.h"

#include <Arduino.h>
#include <climits>
#include <cmath>
#include <cstdio>

#include "app/app_state.h"
#include "app/id_spool.h"
#include "hardware/sd_logger.h"
#include "services/auto_weight_state.h"
#include "services/backend_api.h"
#include "services/prefs_store.h"
#include "services/spoolman_actions.h"
#include "lang.h"
#include "theme.h"
#include "ui_common.h"

// Null whenever the main screen has no weight button: without a load cell
// the slot holds the location button instead.
static lv_obj_t  *s_btn  = nullptr;
static lv_obj_t  *s_lbl  = nullptr;
static lv_obj_t  *s_fill = nullptr;
static lv_coord_t s_fill_w = -1;
static WeightLook s_look   = WL_MANUAL;
// What the caption shows, so a loop pass with nothing new draws nothing.
static int        s_shown_g = INT32_MIN;

struct LookColours { uint32_t bg, line, ink; };

static LookColours coloursFor(WeightLook look) {
  switch (look) {
    case WL_AUTO:      return { UI_COL_WEIGHT_BG, UI_COL_WEIGHT_BG_PRESSED, UI_COL_WEIGHT_AUTO };
    case WL_COUNTING:  return { UI_COL_WEIGHT_BG, UI_COL_WEIGHT_BG_PRESSED, UI_COL_WEIGHT_COUNT };
    case WL_SENT:      return { UI_COL_WEIGHT_BG, UI_COL_WEIGHT_SENT,       UI_COL_WEIGHT_SENT };
    case WL_RISE:
    case WL_NO_SPOOL:  return { UI_COL_AMBER_BG,  UI_COL_WARN,              UI_COL_WARN };
    case WL_UNCHANGED:
    case WL_MANUAL:
    default:           return { UI_COL_WEIGHT_BG, UI_COL_WEIGHT_BG_PRESSED, UI_COL_WEIGHT_TEXT };
  }
}

static void captionFor(WeightLook look, float grams, char *buf, size_t len) {
  char num[32];
  switch (look) {
    case WL_AUTO:
      snprintf(buf, len, LV_SYMBOL_REFRESH "  %s", T(STR_BTN_WEIGHT));
      return;
    case WL_COUNTING:
      snprintf(buf, len, LV_SYMBOL_REFRESH "  %.0f g", grams);
      return;
    case WL_SENT:
      snprintf(num, sizeof(num), T(STR_WB_SENT), grams);
      snprintf(buf, len, LV_SYMBOL_OK "  %s", num);
      return;
    case WL_UNCHANGED:
      snprintf(num, sizeof(num), T(STR_WB_UNCHANGED), grams);
      snprintf(buf, len, LV_SYMBOL_OK "  %s", num);
      return;
    case WL_RISE:
      snprintf(num, sizeof(num), T(STR_WB_RISE), grams);
      snprintf(buf, len, LV_SYMBOL_WARNING "  %s", num);
      return;
    case WL_NO_SPOOL:
      snprintf(buf, len, LV_SYMBOL_WARNING "  %s", T(STR_WB_NO_SPOOL));
      return;
    case WL_MANUAL:
    default:
      copyT(buf, len, STR_BTN_WEIGHT);
      return;
  }
}

void weightButtonAttach(lv_obj_t *btn, lv_obj_t *lbl) {
  s_btn = btn;
  s_lbl = lbl;
  // Behind the caption and not clickable, so a tap anywhere still lands on
  // the button - the same as the AMS button's fill. No padding on the
  // button, so the fill starts at its edge.
  lv_obj_set_style_pad_all(btn, 0, 0);
  s_fill = lv_obj_create(btn);
  lv_obj_remove_style_all(s_fill);
  lv_obj_set_size(s_fill, 0, lv_pct(100));
  lv_obj_set_style_bg_color(s_fill, lv_color_hex(UI_COL_WEIGHT_BG_PRESSED), 0);
  lv_obj_set_style_bg_opa(s_fill, LV_OPA_COVER, 0);
  lv_obj_set_style_radius(s_fill, UI_RADIUS_BTN, 0);
  lv_obj_clear_flag(s_fill, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_flag(s_fill, LV_OBJ_FLAG_HIDDEN);
  lv_obj_move_to_index(s_fill, 0);
  s_fill_w = -1;
  // No look yet, so the first paint sets the colours as well as the caption.
  s_look = (WeightLook)UINT8_MAX;
  s_shown_g = INT32_MIN;
  weightButtonIdle();
}

void weightButtonShow(WeightLook look, float grams) {
  if (!s_btn || !s_lbl) return;
  const int rounded = (int)lroundf(grams);
  if (look == s_look && rounded == s_shown_g) return;
  const bool look_changed = look != s_look;
  s_look = look;
  s_shown_g = rounded;

  char buf[48];
  captionFor(look, grams, buf, sizeof(buf));
  lv_label_set_text(s_lbl, buf);
  if (!look_changed) return;

  const LookColours c = coloursFor(look);
  lv_obj_set_style_text_color(s_lbl, lv_color_hex(c.ink), 0);
  lv_obj_set_style_bg_color(s_btn, lv_color_hex(c.bg), 0);
  lv_obj_set_style_border_color(s_btn, lv_color_hex(c.line), 0);
  if (look == WL_COUNTING) {
    s_fill_w = -1;
    lv_obj_clear_flag(s_fill, LV_OBJ_FLAG_HIDDEN);
  } else {
    lv_obj_add_flag(s_fill, LV_OBJ_FLAG_HIDDEN);
  }
}

void weightButtonFill(uint32_t remaining_ms) {
  if (!s_btn || s_look != WL_COUNTING) return;
  uiCountdownFillSet(s_fill, lv_obj_get_content_width(s_btn), &s_fill_w,
                     remaining_ms, AUTO_WEIGHT_STABLE_MS);
}

void weightButtonIdle() {
  weightButtonShow((g_auto_weight && !idSpoolActive()) ? WL_AUTO : WL_MANUAL);
}

WeightLook weightButtonLook() { return s_look; }

void weightButtonAfterWrite(int code, float grams) {
  if (backendWriteOk(code) || code == PATCH_WEIGHT_ASKING) {
    weightButtonShow(WL_SENT, grams);
    return;
  }
  logSDf("Auto-Weight: %.0f g not taken (HTTP %d), button back to idle", grams, code);
  weightButtonIdle();
}

void weightButtonIdleIfWaiting() {
  if (s_look == WL_COUNTING || s_look == WL_NO_SPOOL) weightButtonIdle();
}

void autoWeightSwitch(bool on) {
  g_auto_weight = on;
  auto_weight_stable_ms = 0;
  auto_weight_last_val = -9999.0f;
  prefsPutBool("auto_weight", on);
  logSDf("Auto-Weight: switched %s", on ? "on" : "off");
  weightButtonIdle();
}
