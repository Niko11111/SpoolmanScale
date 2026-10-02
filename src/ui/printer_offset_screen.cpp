#include "printer_offset_screen.h"

#include <Arduino.h>
#include <lvgl.h>
#include <stdint.h>
#include <stdio.h>

#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/label_printer.h"
#include "ui/info_popup.h"
#include "ui/theme.h"
#include "ui_common.h"

LV_FONT_DECLARE(lv_font_montserrat_ext_28);

// The screen, 480 x 320, under the sub header: the head as a strip with the
// label on it, the offset between - and +, one line of what to do, and the
// calibration page as the one green button.
#define PO_X               20
#define PO_W              440
#define PO_STRIP_Y         60
#define PO_STRIP_H         40
#define PO_STRIP_PAD        4    // around the label block inside the strip
#define PO_SCALE_Y        104    // "0" and "72 mm" under the strip
#define PO_STEP_Y         130
#define PO_STEP_H          60
#define PO_STEP_W          76
#define PO_STEP_GAP        10
#define PO_CAPTION_DY       6    // the caption's top inside the value box
#define PO_HINT_Y         202
#define PO_BTN_Y          246
#define PO_BTN_H           56
// How long - and + rest before the offset is written.
#define PO_SAVE_AFTER_MS  700

static lv_obj_t* s_scr = nullptr;
static lv_obj_t* s_block = nullptr;      // the label on the strip
static lv_obj_t* s_block_lbl = nullptr;
static lv_obj_t* s_caption = nullptr;
static lv_obj_t* s_value = nullptr;
static lv_obj_t* s_minus = nullptr;
static lv_obj_t* s_plus = nullptr;

// The config as shown, its offset the one in effect. Kept past the screen:
// the loop saves it after a close as well.
static LabelPrinterConfig s_cfg{};
static bool     s_dirty = false;
static uint32_t s_changed_ms = 0;
static bool     s_leave = false;

static int perMm() { return labelPrinterDotsForMm(1); }

static int roundMm(int dots) {
  const int per = perMm();
  return (dots + (dots < 0 ? -per / 2 : per / 2)) / per;
}

static void updateView() {
  if (!s_scr) return;
  int16_t lo, hi;
  labelPrinterOffsetRange(s_cfg, &lo, &hi);
  const int row = labelPrinterRasterWidth(s_cfg.model, s_cfg.media_width_mm);
  const int cw = labelPrinterDotsForMm(s_cfg.media_width_mm);
  const int cx = labelPrinterContentX(s_cfg);
  const int off = s_cfg.x_offset;

  // The label on the strip, in proportion to the head.
  const lv_coord_t inner = PO_W - 2 * PO_STRIP_PAD;
  if (row > 0) {
    lv_obj_set_x(s_block, (lv_coord_t)((long)cx * inner / row));
    lv_obj_set_width(s_block, (lv_coord_t)((long)cw * inner / row));
  }
  char buf[40];
  snprintf(buf, sizeof(buf), "%u mm", (unsigned)s_cfg.media_width_mm);
  lv_label_set_text(s_block_lbl, buf);

  // "Offset" and, where it stands at one, the edge or the middle, in the
  // words of the browser's buttons.
  int where = -1;
  if (off == 0) where = STR_W_P_CAL_CENTER;
  else if (off == hi && hi > 0) where = STR_W_P_CAL_RIGHT;
  else if (off == lo && lo < 0) where = STR_W_P_CAL_LEFT;
  if (where < 0) lv_label_set_text(s_caption, T(STR_W_P_CAL_OFFSET));
  else {
    char cap[64];
    snprintf(cap, sizeof(cap), "%s  \xE2\x80\xA2  %s", T(STR_W_P_CAL_OFFSET), T(where));
    lv_label_set_text(s_caption, cap);
  }
  const int mm = roundMm(off);
  snprintf(buf, sizeof(buf), "%s%d mm", mm > 0 ? "+" : "", mm);
  lv_label_set_text(s_value, buf);

  if (off <= lo) lv_obj_add_state(s_minus, LV_STATE_DISABLED);
  else           lv_obj_clear_state(s_minus, LV_STATE_DISABLED);
  if (off >= hi) lv_obj_add_state(s_plus, LV_STATE_DISABLED);
  else           lv_obj_clear_state(s_plus, LV_STATE_DISABLED);
}

// One millimetre, from where the offset stands rounded to whole ones, so an
// edge in odd dots (a roll against the wall) steps back onto the grid.
static void step(int dir) {
  int16_t lo, hi;
  labelPrinterOffsetRange(s_cfg, &lo, &hi);
  int v = (roundMm(s_cfg.x_offset) + dir) * perMm();
  if (v < lo) v = lo;
  if (v > hi) v = hi;
  if (v == s_cfg.x_offset) return;
  s_cfg.x_offset = (int16_t)v;
  s_dirty = true;
  s_changed_ms = millis();
  updateView();
}

// A tap is one step; held, the button repeats at LVGL's long-press rate.
static void stepCb(lv_event_t* e) {
  const int dir = (int)(intptr_t)lv_event_get_user_data(e);
  if (lv_event_get_code(e) == LV_EVENT_SHORT_CLICKED)
    logSD(dir > 0 ? "BTN: Print position -> +" : "BTN: Print position -> -");
  step(dir);
}

static lv_obj_t* makeStepButton(lv_obj_t* parent, lv_coord_t x, const char* sym, int dir) {
  lv_obj_t* b = lv_btn_create(parent);
  lv_obj_set_size(b, PO_STEP_W, PO_STEP_H);
  lv_obj_set_pos(b, x, PO_STEP_Y);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_SURFACE), LV_STATE_DISABLED);
  lv_obj_set_style_border_width(b, 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_ROW_PRESSED), 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_LINE_SOFT), LV_STATE_DISABLED);
  lv_obj_set_style_radius(b, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  // The theme greys a disabled button out with a colour filter, a light
  // grey block on this dark screen; the colours below say it instead.
  lv_obj_set_style_color_filter_opa(b, LV_OPA_TRANSP, LV_STATE_DISABLED);
  // On the button, so the symbol inherits it in both states.
  lv_obj_set_style_text_color(b, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_color(b, lv_color_hex(UI_COL_RULE), LV_STATE_DISABLED);
  lv_obj_t* l = lv_label_create(b);
  lv_label_set_text(l, sym);
  lv_obj_set_style_text_font(l, UI_FONT_ICON, 0);
  lv_obj_center(l);
  void* ud = (void*)(intptr_t)dir;
  lv_obj_add_event_cb(b, stepCb, LV_EVENT_SHORT_CLICKED, ud);
  lv_obj_add_event_cb(b, stepCb, LV_EVENT_LONG_PRESSED, ud);
  lv_obj_add_event_cb(b, stepCb, LV_EVENT_LONG_PRESSED_REPEAT, ud);
  return b;
}

void printerOffsetFlush() {
  if (!s_dirty) return;
  s_dirty = false;
  LabelPrinterConfig c = labelPrinterLoadConfig();
  c.x_offset = s_cfg.x_offset;
  if (!labelPrinterSaveConfig(c)) showInfoPopup(STR_PRN_TITLE, STR_ERR_SAVE, INFO_WARN);
}

void printerOffsetTick() {
  if (s_dirty && millis() - s_changed_ms >= PO_SAVE_AFTER_MS) printerOffsetFlush();
  if (s_leave) {
    s_leave = false;
    // Saved first: the printer screen's row shows the offset.
    printerOffsetFlush();
    show_printer_pending = true;
  }
}

void hidePrinterOffsetScreen() {
  if (s_scr) lv_obj_add_flag(s_scr, LV_OBJ_FLAG_HIDDEN);
}

void showPrinterOffsetScreen() {
  if (s_scr) lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_HIDDEN);
}

void closePrinterOffsetScreen() {
  if (!s_scr) return;
  lv_obj_del(s_scr);
  s_scr = nullptr;
  s_block = s_block_lbl = s_caption = s_value = s_minus = s_plus = nullptr;
}

void buildPrinterOffsetScreen() {
  logSD("BUILD: PrinterOffsetScreen");
  // A change still waiting from the last visit is written before it is
  // read back.
  printerOffsetFlush();
  releaseScreen(&s_scr);
  s_scr = buildOverlayScreen();
  buildSubHeader(s_scr, T(STR_W_P_CAL_TITLE), [](lv_event_t* e) {
    (void)e;
    logSD("BTN: Back -> Printer");
    s_leave = true;
  });
  addHeaderHelp(s_scr, STR_W_P_CAL_TITLE, STR_PRN_OFFSET_HELP);

  s_cfg = labelPrinterLoadConfig();
  s_cfg.x_offset = labelPrinterOffset(s_cfg);

  // The head, and the label on it.
  lv_obj_t* strip = lv_obj_create(s_scr);
  lv_obj_set_size(strip, PO_W, PO_STRIP_H);
  lv_obj_set_pos(strip, PO_X, PO_STRIP_Y);
  lv_obj_set_style_bg_color(strip, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_width(strip, 1, 0);
  lv_obj_set_style_border_color(strip, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_radius(strip, UI_RADIUS_BTN, 0);
  lv_obj_set_style_pad_all(strip, PO_STRIP_PAD, 0);
  lv_obj_clear_flag(strip, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(strip, LV_OBJ_FLAG_CLICKABLE);
  s_block = lv_obj_create(strip);
  lv_obj_set_size(s_block, PO_W / 2, PO_STRIP_H - 2 * PO_STRIP_PAD - 2);
  lv_obj_set_y(s_block, 0);
  lv_obj_set_style_bg_color(s_block, lv_color_hex(UI_COL_GO_BG), 0);
  lv_obj_set_style_border_width(s_block, 1, 0);
  lv_obj_set_style_border_color(s_block, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_radius(s_block, UI_RADIUS_INPUT, 0);
  lv_obj_set_style_pad_all(s_block, 0, 0);
  lv_obj_clear_flag(s_block, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(s_block, LV_OBJ_FLAG_CLICKABLE);
  s_block_lbl = lv_label_create(s_block);
  lv_obj_set_style_text_font(s_block_lbl, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_color(s_block_lbl, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_center(s_block_lbl);

  { lv_obj_t* l = lv_label_create(s_scr);
    lv_label_set_text(l, "0");
    lv_obj_set_style_text_font(l, UI_FONT_CAPTION, 0);
    lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_set_pos(l, PO_X, PO_SCALE_Y);
    char head[16];
    snprintf(head, sizeof(head), "%u mm",
             (unsigned)(labelPrinterRasterWidth(s_cfg.model, s_cfg.media_width_mm) / perMm()));
    lv_obj_t* r = lv_label_create(s_scr);
    lv_label_set_text(r, head);
    lv_obj_set_style_text_font(r, UI_FONT_CAPTION, 0);
    lv_obj_set_style_text_color(r, lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_align(r, LV_ALIGN_TOP_RIGHT, -PO_X, PO_SCALE_Y); }

  // The offset between its two buttons.
  s_minus = makeStepButton(s_scr, PO_X, LV_SYMBOL_MINUS, -1);
  s_plus = makeStepButton(s_scr, PO_X + PO_W - PO_STEP_W, LV_SYMBOL_PLUS, +1);
  lv_obj_t* box = lv_obj_create(s_scr);
  lv_obj_set_size(box, PO_W - 2 * (PO_STEP_W + PO_STEP_GAP), PO_STEP_H);
  lv_obj_set_pos(box, PO_X + PO_STEP_W + PO_STEP_GAP, PO_STEP_Y);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_LINE_SOFT), 0);
  lv_obj_set_style_radius(box, UI_RADIUS_ROW, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_CLICKABLE);
  s_caption = lv_label_create(box);
  lv_obj_set_style_text_font(s_caption, UI_FONT_CAPTION, 0);
  lv_obj_set_style_text_color(s_caption, lv_color_hex(UI_COL_CAPTION), 0);
  lv_obj_align(s_caption, LV_ALIGN_TOP_MID, 0, PO_CAPTION_DY);
  s_value = lv_label_create(box);
  lv_obj_set_style_text_font(s_value, &lv_font_montserrat_ext_28, 0);
  lv_obj_set_style_text_color(s_value, lv_color_hex(UI_COL_INK), 0);
  lv_obj_align(s_value, LV_ALIGN_BOTTOM_MID, 0, -PO_CAPTION_DY);

  // What to do, in one sentence.
  lv_obj_t* hint = lv_label_create(s_scr);
  lv_label_set_text(hint, T(STR_PRN_OFFSET_HINT));
  lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(hint, PO_W);
  lv_obj_set_style_text_font(hint, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_color(hint, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_pos(hint, PO_X, PO_HINT_Y);

  // The calibration page, printed from the loop like the test print.
  lv_obj_t* btn = lv_btn_create(s_scr);
  lv_obj_set_size(btn, PO_W, PO_BTN_H);
  lv_obj_set_pos(btn, PO_X, PO_BTN_Y);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_OK_BG), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_OK_BG_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, [](lv_event_t* e) {
    (void)e;
    logSD("BTN: Print position -> calibration page");
    printer_calib_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t* bl = lv_label_create(btn);
  lv_label_set_text(bl, T(STR_W_P_CAL_PRINT));
  lv_obj_set_style_text_font(bl, UI_FONT_TITLE, 0);
  lv_obj_set_style_text_color(bl, lv_color_hex(UI_COL_OK_TEXT), 0);
  lv_obj_center(bl);

  updateView();
}
