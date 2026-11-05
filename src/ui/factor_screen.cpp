#include "factor_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cmath>
#include <cstdlib>
#include <cstring>

#include "app_config.h"
#include "hardware/scale.h"
#include "hardware/scale_state.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "ota_browser.h"
#include "scale_menu.h"
#include "services/backend.h"
#include "services/cal_factor_rules.h"
#include "setup_frame.h"
#include "ui_common.h"
#include "theme.h"
#include "weight_format.h"

// The calibration, led through in three steps on one screen: empty the
// scale and zero it, put a known weight on and enter it, then check what the
// scale reads. The same screen for the setup and for the settings; only the
// header and the quiet answers differ. The arithmetic is the old screen's,
// unchanged.

void resetActivityTimer();

#define CAL_CHIPS_Y       54
#define CAL_CHIP_DISC     20
#define CAL_CHIP_GAP      18
#define CAL_BODY_Y        88
#define CAL_TEXT_X        12
#define CAL_TEXT_W       270
#define CAL_CARD_X       298
#define CAL_CARD_W       170
#define CAL_CARD_H       120
#define CAL_WIDE_CARD_H  128
#define CAL_LINE_Y       226
#define CAL_LINE_W       456
#define CAL_FIELD_Y      156
#define CAL_FIELD_W      200
#define CAL_FIELD_H       48
#define CAL_LIVE_Y       210   // step 2: the reading under the field
#define CAL_LIVE_H        18
#define CAL_PAD_X        226
#define CAL_PAD_W        242
#define CAL_KEY_H         38
#define CAL_KEY_GAP        5
#define CAL_PAD_COLS       3
#define CAL_WEIGHT_FONT  (&lv_font_montserrat_ext_28)

enum CalStep : uint8_t { CAL_STEP_EMPTY = 1, CAL_STEP_PLACE, CAL_STEP_CHECK };

static CalStep   cal_step = CAL_STEP_EMPTY;
static char      factor_input[16] = "";
static lv_obj_t *lbl_factor_display = nullptr;
// Everything below the header, rebuilt per step: released asynchronously, so
// a button may change the step from its own callback.
static lv_obj_t *cal_body = nullptr;

static void buildCalStep();

static void dropStepPointers() {
  lbl_factor_display    = nullptr;
  lbl_factor_result     = nullptr;
  lbl_factor_cal_weight = nullptr;
}

static void goToStep(CalStep s) {
  logSDf("Calibration: step %d", (int)s);
  // Starting over starts with an empty weight, not one the next digit
  // would be appended to.
  if (s == CAL_STEP_EMPTY) factor_input[0] = '\0';
  cal_step = s;
  dropStepPointers();
  releaseScreen(&cal_body);
  buildCalStep();
}

// ---- leaving ----------------------------------------------------
static void backToScaleMenu() {
  hideAllOverlays();
  if (!scr_scale_sub) buildScaleSubScreen();
  lv_obj_clear_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN);
  // The factor is stored at Calculate already, and the menu row shows it.
  scale_sub_rebuild_pending = true;
}

void factorBackToSetupStep() {
  closeFactorScreen();
  if (backendAuthInBrowser()) showOtaBrowserScreen(WEB_CTX_SETUP);
  else                                            show_spoolman_pending = true;
}

static void onCalBack(lv_event_t *e) {
  logSD("BTN: Calibration -> Back");
  if (cal_step > CAL_STEP_EMPTY) { goToStep((CalStep)(cal_step - 1)); return; }
  if (setup_active) cal_setup_back_pending = true;
  else              backToScaleMenu();
}

// Done, or skipped in the setup: the setup goes on, the settings go back to
// the scale menu, which shows the new factor in its row.
static void finishCalibration(bool skipped) {
  logSDf("Calibration: %s", skipped ? "later" : "done");
  if (setup_active) {
    setup_done_pending = true;   // the closing screen, built on the loop
    return;
  }
  backToScaleMenu();
  scale_sub_rebuild_pending = true;
}

// ---- pieces -----------------------------------------------------
static lv_obj_t *calLabel(lv_obj_t *parent, const char *text, const lv_font_t *font,
                          uint32_t col) {
  lv_obj_t *l = lv_label_create(parent);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(col), 0);
  return l;
}

// The status line over the bar: a result, an error, or the factor. Across
// the screen, or in the left column where the pad takes the right.
static void addStatusLine(lv_obj_t *body, const char *text, bool left_column) {
  lbl_factor_result = calLabel(body, text, UI_FONT_CAPTION, UI_COL_INK_SOFT);
  lv_label_set_long_mode(lbl_factor_result, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_factor_result, left_column ? CAL_FIELD_W : CAL_LINE_W);
  lv_obj_set_style_text_align(lbl_factor_result,
                              left_column ? LV_TEXT_ALIGN_LEFT : LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_pos(lbl_factor_result, CAL_TEXT_X,
                 left_column ? CAL_LIVE_Y + CAL_LIVE_H : CAL_LINE_Y);
}

static void addChip(lv_obj_t *row, int n, int str_id) {
  const bool done = n < (int)cal_step, now = n == (int)cal_step;
  lv_obj_t *chip = lv_obj_create(row);
  lv_obj_remove_style_all(chip);
  lv_obj_set_size(chip, LV_SIZE_CONTENT, CAL_CHIP_DISC);
  lv_obj_set_flex_flow(chip, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(chip, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(chip, 6, 0);

  lv_obj_t *disc = lv_obj_create(chip);
  lv_obj_remove_style_all(disc);
  lv_obj_set_size(disc, CAL_CHIP_DISC, CAL_CHIP_DISC);
  lv_obj_set_style_radius(disc, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_opa(disc, (done || now) ? LV_OPA_COVER : LV_OPA_TRANSP, 0);
  lv_obj_set_style_bg_color(disc, lv_color_hex(now ? UI_COL_ACCENT : UI_COL_PICKED_BG), 0);
  lv_obj_set_style_border_width(disc, (done || now) ? 0 : 1, 0);
  lv_obj_set_style_border_color(disc, lv_color_hex(UI_COL_LINE), 0);
  char num[4];
  snprintf(num, sizeof(num), "%d", n);
  lv_obj_t *d = calLabel(disc, done ? LV_SYMBOL_OK : num, UI_FONT_CAPTION,
                         now ? UI_COL_ON_ACCENT : (done ? UI_COL_ACCENT : UI_COL_INK_SOFT));
  lv_obj_center(d);
  calLabel(chip, T(str_id), UI_FONT_SMALL, now ? UI_COL_INK : UI_COL_INK_SOFT);
}

static void addChips(lv_obj_t *body) {
  lv_obj_t *row = lv_obj_create(body);
  lv_obj_remove_style_all(row);
  lv_obj_set_size(row, LV_SIZE_CONTENT, CAL_CHIP_DISC);
  lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
  lv_obj_set_style_pad_column(row, CAL_CHIP_GAP, 0);
  lv_obj_align(row, LV_ALIGN_TOP_MID, 0, CAL_CHIPS_Y);
  addChip(row, CAL_STEP_EMPTY, STR_CAL_STEP_EMPTY);
  addChip(row, CAL_STEP_PLACE, STR_CAL_STEP_PLACE);
  addChip(row, CAL_STEP_CHECK, STR_CAL_STEP_CHECK);
}

// A box with a caption over the live weight; the loop writes the weight
// into lbl_factor_cal_weight while this screen is up.
static lv_obj_t *addWeightCard(lv_obj_t *body, int x, int w, int h, int caption_id) {
  lv_obj_t *card = lv_obj_create(body);
  lv_obj_set_size(card, w, h);
  lv_obj_set_pos(card, x, CAL_BODY_Y);
  lv_obj_set_style_pad_all(card, 0, 0);
  lv_obj_set_style_radius(card, UI_RADIUS_ROW, 0);
  lv_obj_set_style_bg_color(card, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_width(card, 1, 0);
  lv_obj_set_style_border_color(card, lv_color_hex(UI_COL_LINE_SOFT), 0);
  lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(card, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_align(calLabel(card, T(caption_id), UI_FONT_CAPTION, UI_COL_INK_SOFT), LV_ALIGN_TOP_MID, 0, 14);
  lbl_factor_cal_weight = calLabel(card, "-- g", CAL_WEIGHT_FONT, UI_COL_INK);
  lv_obj_align(lbl_factor_cal_weight, LV_ALIGN_CENTER, 0, 4);
  return card;
}

// ---- step 1: empty and zero ------------------------------------
static void onZero(lv_event_t *e) {
  // Presence asked as well as scale_ready: an ADC that left the bus reads
  // back as all ones, and tare would store -1 as the zero point.
  if (!scale_ready || !scaleHardwarePresent()) {
    if (lbl_factor_result) lv_label_set_text(lbl_factor_result, T(STR_TARE_NOT_READY));
    return;
  }
  int32_t raw = scaleHardwareReadRaw();
  saveTareOffset(raw);
  scale_weight_g = 0.0f;
  resetScaleFilter();
  if (lbl_scale_weight) lv_label_set_text(lbl_scale_weight, "0 g");
  Serial.println("Tare (calibration screen) executed");
  goToStep(CAL_STEP_PLACE);
}

static void buildStepEmpty(lv_obj_t *body) {
  lv_obj_t *t = calLabel(body, T(STR_CAL_EMPTY_PAN), UI_FONT_BODY, UI_COL_INK);
  lv_label_set_long_mode(t, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(t, CAL_TEXT_W);
  lv_obj_set_pos(t, CAL_TEXT_X, CAL_BODY_Y + CAL_CARD_H / 2 - 10);
  addWeightCard(body, CAL_CARD_X, CAL_CARD_W, CAL_CARD_H, STR_CAL_SCALE_NOW);

  // In the setup: where to find this later. In the settings: the factor
  // that stands until the new one is calculated.
  char line[160];
  if (setup_active) {
    snprintf(line, sizeof(line), T(STR_CAL_LATER_WHERE),
             T(STR_SETTINGS_TITLE), T(STR_SCALE_TITLE), T(STR_BTN_CALIBRATE));
  } else {
    snprintf(line, sizeof(line), T(STR_CAL_CUR_FACTOR), cal_factor);
  }
  addStatusLine(body, line, false);

  setupActionBar(body,
    setup_active ? T(STR_SETUP_LATER) : nullptr,
    [](lv_event_t *e) { finishCalibration(true); },
    T(STR_CAL_ZERO_BTN), onZero);
}

// ---- step 2: a known weight ------------------------------------
static void showFactorInput() {
  if (lbl_factor_display) lv_label_set_text(lbl_factor_display, factor_input[0] ? factor_input : "_");
}

static void onCalKey(lv_event_t *e) {
  const char *ch = lv_label_get_text(lv_obj_get_child(lv_event_get_target(e), 0));
  if (ch[0] == '.' && strchr(factor_input, '.')) return;
  const int len = strlen(factor_input);
  if (len < (int)sizeof(factor_input) - 1) { factor_input[len] = ch[0]; factor_input[len + 1] = '\0'; }
  showFactorInput();
}

static void onCalDelete(lv_event_t *e) {
  const int len = strlen(factor_input);
  if (len > 0) factor_input[len - 1] = '\0';
  showFactorInput();
}

static void onCalculate(lv_event_t *e) {
  if (!lbl_factor_result) return;
  float known_g = atof(factor_input);
  if (!scale_ready || !scaleHardwarePresent()) {
    lv_label_set_text(lbl_factor_result, T(STR_TARE_NOT_READY));
  } else if (known_g <= 0) {
    lv_label_set_text(lbl_factor_result, T(STR_CAL_ZERO_ERR));
  } else if (known_g < CAL_KNOWN_MIN_G || known_g > CAL_KNOWN_MAX_G) {
    lv_label_set_text(lbl_factor_result, T(STR_CAL_RANGE_ERR));
  } else {
    int32_t raw = scaleHardwareReadRaw();
    float factor = (float)(raw - zero_offset) / known_g;
    // The last line of defence. A reading the bus never delivered is -1, and
    // if tare stored -1 too the difference is zero: the factor collapses and
    // every later weight explodes. Refusing here costs a retry; storing it
    // costs a device that has to be re-flashed to be usable again.
    if (!isfinite(factor) ||
        fabsf(factor) < CAL_FACTOR_MIN || fabsf(factor) > CAL_FACTOR_MAX) {
      Serial.printf("Calibration refused: raw=%d zero=%d known=%.1f factor=%.6f\n",
                    raw, zero_offset, known_g, factor);
      lv_label_set_text(lbl_factor_result, T(STR_CAL_IMPLAUSIBLE));
    } else {
      saveCalFactor(calFactorFromMeasured(factor));
      // The filter still holds readings in the old factor's units; step 3
      // would show them settling for a second and a half, on the one screen
      // whose job is to check the reading.
      resetScaleFilter();
      scale_weight_g = 0.0f;
      goToStep(CAL_STEP_CHECK);
    }
  }
}

// 1 2 3 / 4 5 6 / 7 8 9 / . 0 delete
static void buildCalPad(lv_obj_t *body) {
  static const char *const KEYS[] = { "1","2","3","4","5","6","7","8","9",".","0","" };
  const int key_w = (CAL_PAD_W - (CAL_PAD_COLS - 1) * CAL_KEY_GAP) / CAL_PAD_COLS;
  for (int i = 0; i < 12; i++) {
    const int col = i % CAL_PAD_COLS, row = i / CAL_PAD_COLS;
    const bool del = (i == 11);
    lv_obj_t *b = padButton(body, CAL_PAD_X + col * (key_w + CAL_KEY_GAP),
                            CAL_CHIPS_Y + 30 + row * (CAL_KEY_H + CAL_KEY_GAP), key_w, CAL_KEY_H,
                            del ? UI_COL_ROW : UI_COL_SURFACE, UI_COL_PRESS_FILL);
    padLabel(b, del ? LV_SYMBOL_BACKSPACE : KEYS[i], del ? UI_COL_INK_2 : UI_COL_INK,
             del ? UI_FONT_BODY : UI_FONT_TITLE);
    lv_obj_add_event_cb(b, del ? onCalDelete : onCalKey, LV_EVENT_CLICKED, NULL);
  }
}

static void buildStepPlace(lv_obj_t *body) {
  lv_obj_t *t = calLabel(body, T(STR_CAL_PLACE_KNOWN), UI_FONT_BODY, UI_COL_INK);
  lv_label_set_long_mode(t, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(t, CAL_FIELD_W);
  lv_obj_set_pos(t, CAL_TEXT_X, CAL_BODY_Y - 2);
  lv_obj_t *hint = calLabel(body, T(STR_CAL_ABOUT_1KG), UI_FONT_SMALL, UI_COL_INK_SOFT);
  lv_obj_set_pos(hint, CAL_TEXT_X, CAL_BODY_Y + 42);

  lv_obj_t *field = lv_obj_create(body);
  lv_obj_set_size(field, CAL_FIELD_W, CAL_FIELD_H);
  lv_obj_set_pos(field, CAL_TEXT_X, CAL_FIELD_Y);
  lv_obj_set_style_bg_color(field, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(field, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_border_width(field, 2, 0);
  lv_obj_set_style_radius(field, UI_RADIUS_ROW, 0);
  lv_obj_set_style_pad_hor(field, 12, 0);
  lv_obj_clear_flag(field, LV_OBJ_FLAG_SCROLLABLE);
  lbl_factor_display = calLabel(field, "_", UI_FONT_HEADLINE, UI_COL_INK);
  lv_obj_align(lbl_factor_display, LV_ALIGN_RIGHT_MID, -28, 0);
  lv_obj_align(calLabel(field, "g", UI_FONT_HEADLINE, UI_COL_INK_SOFT), LV_ALIGN_RIGHT_MID, 0, 0);
  showFactorInput();

  // The reading while the weight settles, so the factor is not computed from
  // a number still on its way up. The loop writes it (factorLiveText).
  lbl_factor_cal_weight = calLabel(body, "", UI_FONT_CAPTION, UI_COL_INK_SOFT);
  lv_obj_set_pos(lbl_factor_cal_weight, CAL_TEXT_X, CAL_LIVE_Y);

  buildCalPad(body);
  addStatusLine(body, "", true);

  setupActionBar(body,
    setup_active ? T(STR_SETUP_LATER) : nullptr,
    [](lv_event_t *e) { finishCalibration(true); },
    T(STR_BTN_CALCULATE), onCalculate);
}

// ---- step 3: check ---------------------------------------------
static void buildStepCheck(lv_obj_t *body) {
  lv_obj_t *card = addWeightCard(body, CAL_TEXT_X, CAL_LINE_W, CAL_WIDE_CARD_H, STR_CAL_SHOWS_NOW);
  lv_obj_set_style_text_color(lbl_factor_cal_weight, lv_color_hex(UI_COL_ACCENT), 0);
  char entered[48];
  snprintf(entered, sizeof(entered), T(STR_CAL_ENTERED), factor_input);
  lv_obj_align(calLabel(card, entered, UI_FONT_SMALL, UI_COL_INK_2), LV_ALIGN_BOTTOM_MID, 0, -12);

  char line[48];
  snprintf(line, sizeof(line), T(STR_CAL_NEW_FACTOR), cal_factor);
  addStatusLine(body, line, false);

  char ok_buf[40];
  if (setup_active) snprintf(ok_buf, sizeof(ok_buf), "%s  " LV_SYMBOL_RIGHT, T(STR_CAL_LOOKS_RIGHT));
  else              copyT(ok_buf, sizeof(ok_buf), STR_CAL_LOOKS_RIGHT);
  setupActionBar(body,
    T(STR_CAL_AGAIN), [](lv_event_t *e) { goToStep(CAL_STEP_EMPTY); },
    ok_buf, [](lv_event_t *e) { finishCalibration(false); });
}

// ---- the screen ------------------------------------------------
static void buildCalStep() {
  // The whole screen, behind the header: its own buttons stay on top and
  // keep their taps, the body's buttons get theirs.
  cal_body = lv_obj_create(scr_factor);
  lv_obj_remove_style_all(cal_body);
  lv_obj_set_size(cal_body, 480, 320);
  lv_obj_clear_flag(cal_body, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_clear_flag(cal_body, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_move_background(cal_body);

  addChips(cal_body);
  switch (cal_step) {
    case CAL_STEP_PLACE: buildStepPlace(cal_body); break;
    case CAL_STEP_CHECK: buildStepCheck(cal_body); break;
    default:             buildStepEmpty(cal_body); break;
  }
}

void factorLiveText(char *buf, size_t len, float grams) {
  if (cal_step != CAL_STEP_PLACE) { fmtG(buf, len, grams); return; }
  // Before the first calibration the factor is only a guess, so the "grams"
  // are not grams: shown as a bare number, still good enough to watch settle.
  if (cal_factor == CAL_FACTOR_DEFAULT) {
    snprintf(buf, len, T(STR_CAL_LIVE_RAW), grams);
    return;
  }
  char g[16];
  fmtG(g, sizeof(g), grams);
  snprintf(buf, len, T(STR_CAL_LIVE_G), g);
}

void closeFactorScreen() {
  dropStepPointers();
  cal_body = nullptr;
  if (scr_factor) { lv_obj_del(scr_factor); scr_factor = nullptr; }
}

void showFactorScreen() {
  logSD("SHOW: FactorScreen");
  logSD("UI: Screen -> Calibration");
  // Null all loop-update pointers BEFORE deleting scr_factor
  // Loop checks these pointers - must be null before del to avoid dangling access
  dropStepPointers();
  cal_body = nullptr;
  if (scr_factor) { lv_obj_del(scr_factor); scr_factor = nullptr; }
  buildFactorScreen();
  // hideAllOverlays() is the authoritative list. Order matters - it also
  // hides scr_factor, which buildFactorScreen() created hidden anyway, so the
  // screen is shown right afterwards.
  hideAllOverlays();
  lv_obj_clear_flag(scr_factor, LV_OBJ_FLAG_HIDDEN);
  resetActivityTimer();
}

void buildFactorScreen() {
  logSD("BUILD: FactorScreen");
  releaseScreen(&scr_factor);
  dropStepPointers();
  cal_body = nullptr;
  factor_input[0] = '\0';
  cal_step = CAL_STEP_EMPTY;
  scr_factor = buildOverlayScreen();

  // In the settings the help keeps its place beside the title: the steps
  // say what to do, the help says why.
  if (setup_active) {
    setupHeader(scr_factor, T(STR_CAL_REMINDER_TITLE), SETUP_STEP_SCALE, onCalBack);
  } else {
    buildSubHeader(scr_factor, T(STR_CAL_TITLE), onCalBack);
    addHeaderHelp(scr_factor, STR_CAL_HELP_TITLE, STR_CAL_HELP_TEXT);
  }
  buildCalStep();
}
