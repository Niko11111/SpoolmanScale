#include "setup_frame.h"

#include <Arduino.h>
#include <cstdio>

#include "app/app_state.h"
#include "lang.h"
#include "theme.h"
#include "ui_common.h"

// The title stays clear of the back button on the left and the count on the
// right: 480 less 90 on each side.
#define SETUP_TITLE_W      300
#define SETUP_TITLE_Y       12
#define SETUP_COUNT_X     (-12)
#define SETUP_COUNT_Y       16
#define SETUP_BTN_LABEL_PAD 16   // what a button's label keeps clear of its edges

void setupHeader(lv_obj_t* scr, const char* title, SetupStep step, lv_event_cb_t back_cb) {
  if (back_cb) addBackButton(scr, back_cb);

  // A set height, or LV_LABEL_LONG_DOT has nothing to be too long for.
  lv_obj_t* t = lv_label_create(scr);
  lv_label_set_long_mode(t, LV_LABEL_LONG_DOT);
  lv_obj_set_size(t, SETUP_TITLE_W, lv_font_get_line_height(UI_FONT_TITLE));
  lv_obj_set_style_text_align(t, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_font(t, UI_FONT_TITLE, 0);
  lv_obj_set_style_text_color(t, lv_color_hex(UI_COL_ACCENT), 0);
  lv_label_set_text(t, title);
  lv_obj_align(t, LV_ALIGN_TOP_MID, 0, SETUP_TITLE_Y);

  const int n = setupStepNumber(step);
  if (n <= 0) return;
  char buf[24];
  snprintf(buf, sizeof(buf), T(STR_SETUP_STEP_OF), n, setupStepTotal(step));
  lv_obj_t* c = lv_label_create(scr);
  lv_label_set_text(c, buf);
  lv_obj_set_style_text_font(c, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_color(c, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_align(c, LV_ALIGN_TOP_RIGHT, SETUP_COUNT_X, SETUP_COUNT_Y);
}

void setupOrSettingsHeader(lv_obj_t* scr, const char* title, SetupStep step,
                           lv_event_cb_t back_cb) {
  if (setup_active) setupHeader(scr, title, step, back_cb);
  else              buildSubHeader(scr, title, back_cb);
}

lv_obj_t* setupCenteredLabel(lv_obj_t* parent, const char* text, const lv_font_t* font, int w) {
  lv_obj_t* l = lv_label_create(parent);
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
  lv_obj_set_size(l, w, lv_font_get_line_height(font));
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_font(l, font, 0);
  lv_label_set_text(l, text);
  return l;
}

static lv_obj_t* barButton(lv_obj_t* scr, int x, int w, bool main) {
  lv_obj_t* b = lv_btn_create(scr);
  lv_obj_set_size(b, w, UI_SETUP_BAR_H);
  lv_obj_set_pos(b, x, UI_SETUP_BAR_Y);
  lv_obj_set_style_radius(b, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(main ? UI_COL_ACCENT : UI_COL_SURFACE), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(main ? UI_COL_GO_BG_PRESSED : UI_COL_PRESS_FILL),
                            LV_STATE_PRESSED);
  lv_obj_set_style_border_width(b, main ? 0 : 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_LINE_SOFT), 0);
  return b;
}

static lv_obj_t* barLabel(lv_obj_t* b, const char* text, int w, bool main) {
  lv_obj_t* l = setupCenteredLabel(b, text, UI_FONT_BODY, w - SETUP_BTN_LABEL_PAD);
  lv_obj_set_style_text_color(l, lv_color_hex(main ? UI_COL_ON_ACCENT : UI_COL_INK_SOFT), 0);
  lv_obj_center(l);
  return l;
}

SetupBar setupActionBar(lv_obj_t* scr, const char* quiet_text, lv_event_cb_t quiet_cb,
                        const char* main_text, lv_event_cb_t main_cb) {
  SetupBar bar = { nullptr, nullptr, nullptr };
  int main_x = UI_SETUP_BAR_X;
  if (quiet_text) {
    bar.quiet = barButton(scr, UI_SETUP_BAR_X, UI_SETUP_QUIET_W, false);
    if (quiet_cb) lv_obj_add_event_cb(bar.quiet, quiet_cb, LV_EVENT_CLICKED, NULL);
    barLabel(bar.quiet, quiet_text, UI_SETUP_QUIET_W, false);
    main_x += UI_SETUP_QUIET_W + UI_SETUP_BAR_GAP;
  }
  const int main_w = 480 - UI_SETUP_BAR_X - main_x;
  bar.main = barButton(scr, main_x, main_w, true);
  if (main_cb) lv_obj_add_event_cb(bar.main, main_cb, LV_EVENT_CLICKED, NULL);
  bar.main_label = barLabel(bar.main, main_text, main_w, true);
  return bar;
}

void setupBarMainOutline(const SetupBar& bar) {
  if (!bar.main) return;
  lv_obj_set_style_bg_color(bar.main, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_bg_color(bar.main, lv_color_hex(UI_COL_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(bar.main, 1, 0);
  lv_obj_set_style_border_color(bar.main, lv_color_hex(UI_COL_LINE), 0);
  if (bar.main_label) lv_obj_set_style_text_color(bar.main_label, lv_color_hex(UI_COL_ACCENT), 0);
}
