#include "weight_popup.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstdio>

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "app/id_spool.h"
#include "hardware/sd_logger.h"
#include "services/auto_weight_state.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "confirm_popup.h"
#include "tare_entry.h"
#include "weight_button.h"
#include "lang.h"
#include "theme.h"
#include "ui_common.h"

// Redesign of 26.10.2026 (mock-ups on the canvas "Gewicht-Popup Redesign").
// The popup it replaces gave seven buttons nearly the same weight; sending
// the weight, which is what it is opened for almost every time, was 14 px
// taller than archiving. Now one large button sends, the two switches that
// change what it sends sit under it, and the rare things move to Options.
//
// One screen's coordinates, inside the box's content area (456 wide).
#define WP_BOX_W        460
#define WP_X             10
#define WP_INNER_W      436
#define WP_PRIMARY_Y     54
#define WP_PRIMARY_H     76
#define WP_PRIMARY_SUB_DY 20
#define WP_ROW_Y0       138
#define WP_ROW_H         46
#define WP_ROW_STEP      52
#define WP_SWITCH_ROWS_MAX 2  // bag, automatic sending
#define WP_BOTTOM_H      46
#define WP_BOX_EXTRA     12    // the margin under the last row, and the border
#define WP_ARCHIVE_W    120
#define WP_GAP            8
#define WP_OPT_ROW_Y0    40
#define WP_OPT_ROW_H     58
#define WP_OPT_ROW_STEP  64

static lv_obj_t *s_popup = nullptr;   // level 1
static lv_obj_t *s_opts  = nullptr;   // level 2, Options

// What level 1 repaints in place when a switch changes. Rebuilding would
// delete the switch from inside its own callback.
struct WpView {
  lv_obj_t *line1, *change, *diff;
  lv_obj_t *primary, *main_lbl, *main_sub;
  lv_obj_t *bag_row, *bag_sub, *bag_state;
  lv_obj_t *auto_row, *auto_state;
};
static WpView s_v = {};

// The reading when the popup opened. Every number on it and every write it
// makes comes from this one value, so what the user read is what lands.
static float s_gross_g = 0.0f;
// "Weighed in the bag", off every time the popup opens: a spool in use is
// weighed bare almost always (Nikolai, 26.10.2026).
static bool  s_bag_on  = false;
// The spool those numbers were read for. Another spool loaded under an open
// popup would otherwise take this popup's weight (weightPopupTick()).
static int   s_spool_id = 0;

static float bagG() { return s_bag_on ? bag_weight_g : 0.0f; }

static float newG() {
  const float g = s_gross_g - (float)sm_spool_weight - bagG();
  return g < 0.0f ? 0.0f : g;
}

// The same test the automatic weighing applies before it writes.
static bool risen() {
  return !sm_archived && newG() - sm_remaining > AUTO_WEIGHT_RISE_G;
}

void closeWeightPopups() {
  releaseScreen(&s_popup);
  releaseScreen(&s_opts);
  s_v = {};
}

bool isWeightPopupOpen() {
  return s_popup != nullptr || s_opts != nullptr;
}

void weightPopupTick() {
  if (!isWeightPopupOpen() || sm_id == s_spool_id) return;
  logSDf("UI: weight popup for spool %d closed unsent, spool %d is loaded now", s_spool_id, sm_id);
  closeWeightPopups();
}

// ---------------------------------------------------------------------------
//  Building blocks
// ---------------------------------------------------------------------------

static lv_obj_t* wpLabel(lv_obj_t *parent, const char *text, const lv_font_t *font, uint32_t col) {
  lv_obj_t *l = lv_label_create(parent);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(col), 0);
  return l;
}

static lv_obj_t* wpButton(lv_obj_t *box, int x, int y, int w, int h) {
  lv_obj_t *b = lv_btn_create(box);
  lv_obj_set_size(b, w, h);
  lv_obj_set_pos(b, x, y);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(b, 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_ROW_PRESSED), 0);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_pad_all(b, 0, 0);
  return b;
}

// A switch in the look of the settings lists: the whole row is the button,
// ON or OFF on its right, the border in the accent while it is on. No
// slider: one would invite a tap on itself while the row is what answers.
struct WpSwitch { lv_obj_t *row, *sub, *state; };

static WpSwitch wpSwitchRow(lv_obj_t *box, int y, const char *icon, int title_id) {
  WpSwitch s;
  s.row = wpButton(box, WP_X, y, WP_INNER_W, WP_ROW_H);
  lv_obj_align(wpLabel(s.row, icon, UI_FONT_BODY, UI_COL_ACCENT), LV_ALIGN_LEFT_MID, 14, 0);
  lv_obj_align(wpLabel(s.row, T(title_id), UI_FONT_BODY, UI_COL_INK), LV_ALIGN_LEFT_MID, 44, -9);
  s.sub = wpLabel(s.row, "", UI_FONT_CAPTION, UI_COL_CAPTION);
  lv_obj_align(s.sub, LV_ALIGN_LEFT_MID, 44, 11);
  s.state = wpLabel(s.row, "", UI_FONT_SMALL, UI_COL_CAPTION);
  lv_obj_align(s.state, LV_ALIGN_RIGHT_MID, -14, 0);
  return s;
}

// line: 0 for the usual border, or a colour that overrides it.
static void wpPaintSwitch(lv_obj_t *row, lv_obj_t *state, bool on, uint32_t line) {
  lv_label_set_text(state, T(on ? STR_ON : STR_OFF));
  lv_obj_set_style_text_color(state, lv_color_hex(on ? UI_COL_ACCENT : UI_COL_CAPTION), 0);
  if (!line) line = on ? UI_COL_ACCENT : UI_COL_ROW_PRESSED;
  lv_obj_set_style_border_color(row, lv_color_hex(line), 0);
}

// ---------------------------------------------------------------------------
//  Level 1: painting
// ---------------------------------------------------------------------------

static void wpPaintHeader(float g, bool rise) {
  char buf[96];
  if (rise) {
    snprintf(buf, sizeof(buf), T(STR_WP_RISE_LINE), backendName());
  } else {
    const char *tail = sm_archived ? T(STR_ARCHIVED) : sm_vendor_g;
    snprintf(buf, sizeof(buf), tail[0] ? "#%d  %s - %s" : "#%d  %s", sm_id, sm_filament_name, tail);
  }
  lv_label_set_text(s_v.line1, buf);
  lv_obj_set_style_text_color(s_v.line1, lv_color_hex(rise ? UI_COL_WARN
                              : sm_archived ? UI_COL_ARCHIVE_TEXT : UI_COL_INK_SOFT), 0);

  snprintf(buf, sizeof(buf), "%s  %.0f g   " LV_SYMBOL_RIGHT "   %.0f g",
           backendName(), sm_remaining, g);
  lv_label_set_text(s_v.change, buf);
  snprintf(buf, sizeof(buf), "%+.0f g", g - sm_remaining);
  lv_label_set_text(s_v.diff, sm_archived ? "" : buf);
  lv_obj_set_style_text_color(s_v.diff, lv_color_hex(rise ? UI_COL_WARN : UI_COL_INK_SOFT), 0);
}

static void wpPaintPrimary(float g, bool rise) {
  char num[48], buf[64], sub[64] = "";
  uint32_t bg = UI_COL_OK_BG, line = UI_COL_OK_BG_PRESSED, ink = UI_COL_OK_TEXT;
  if (sm_archived) {
    snprintf(buf, sizeof(buf), LV_SYMBOL_REFRESH "  %s", T(STR_WP_REACTIVATE));
    snprintf(sub, sizeof(sub), T(STR_WP_REACT_SUB), g);
    bg = UI_COL_GO_BG; line = UI_COL_ACCENT; ink = UI_COL_ACCENT;
  } else if (rise) {
    // Still possible, but no longer the obvious thing to do.
    snprintf(buf, sizeof(buf), T(STR_WP_SEND_ANYWAY), g);
    bg = UI_COL_ROW; line = UI_COL_LINE; ink = UI_COL_INK_2;
  } else {
    snprintf(num, sizeof(num), T(STR_WP_SEND), g);
    snprintf(buf, sizeof(buf), LV_SYMBOL_OK "  %s", num);
  }
  if (!sm_archived && s_bag_on) snprintf(sub, sizeof(sub), T(STR_WP_BAG_MINUS), g + bag_weight_g, bag_weight_g);

  lv_obj_set_style_bg_color(s_v.primary, lv_color_hex(bg), 0);
  lv_obj_set_style_border_color(s_v.primary, lv_color_hex(line), 0);
  lv_label_set_text(s_v.main_lbl, buf);
  lv_obj_set_style_text_color(s_v.main_lbl, lv_color_hex(ink), 0);
  lv_label_set_text(s_v.main_sub, sub);
  const bool has_sub = sub[0] != '\0';
  lv_obj_align(s_v.main_lbl, LV_ALIGN_CENTER, 0, has_sub ? -WP_PRIMARY_SUB_DY / 2 : 0);
  lv_obj_align(s_v.main_sub, LV_ALIGN_CENTER, 0, WP_PRIMARY_SUB_DY);
}

// When the spool reads heavier than stored and the switch is off, the row
// says what the bag would make of it: the likeliest explanation, one tap away.
static void wpPaintBag(float g, bool rise) {
  if (!s_v.bag_row) return;
  const bool hint = rise && !s_bag_on;
  char buf[48];
  if (hint) {
    const float with_bag = g - bag_weight_g;
    snprintf(buf, sizeof(buf), T(STR_WP_BAG_HINT), with_bag < 0.0f ? 0.0f : with_bag);
  } else {
    snprintf(buf, sizeof(buf), T(STR_WP_BAG_SUB), bag_weight_g);
  }
  lv_label_set_text(s_v.bag_sub, buf);
  lv_obj_set_style_text_color(s_v.bag_sub, lv_color_hex(hint ? UI_COL_WARN : UI_COL_CAPTION), 0);
  wpPaintSwitch(s_v.bag_row, s_v.bag_state, s_bag_on, hint ? UI_COL_WARN : 0);
}

static void wpRefresh() {
  if (!s_popup) return;
  const float g = newG();
  const bool rise = risen();
  wpPaintHeader(g, rise);
  wpPaintPrimary(g, rise);
  wpPaintBag(g, rise);
  if (s_v.auto_row) wpPaintSwitch(s_v.auto_row, s_v.auto_state, g_auto_weight, 0);
}

// ---------------------------------------------------------------------------
//  Level 1: building
// ---------------------------------------------------------------------------

static void wpPrimaryClicked(lv_event_t *e) {
  // A tap in the pass the spool changed in, before the tick took the popup down.
  if (sm_id != s_spool_id) { closeWeightPopups(); return; }
  const float g = newG();
  if (sm_archived) {
    logSDf("UI: weight popup -> reactivate spool %d at %.0f g", sm_id, g);
    // Deferred like every other network call reached from a callback.
    reactivate_weight_g = g;
    reactivate_pending  = true;
  } else {
    logSDf("UI: weight popup -> send %.0f g for spool %d (bag %s)", g, sm_id, s_bag_on ? "on" : "off");
    confirmQueueWeight(g, s_gross_g - bagG());
    // Sent by hand: the automatic weighing must not send this spool again.
    // The button says what happened once the queued write has an answer
    // (confirm_popup.cpp, CJ_WEIGHT), not before.
    if (g_auto_weight) auto_weight_done = true;
  }
  closeWeightPopups();
}

static void wpBuildHeaderAndPrimary(lv_obj_t *box) {
  s_v.line1 = wpLabel(box, "", UI_FONT_SMALL, UI_COL_INK_SOFT);
  lv_label_set_long_mode(s_v.line1, LV_LABEL_LONG_DOT);
  lv_obj_set_width(s_v.line1, WP_INNER_W);
  lv_obj_set_pos(s_v.line1, WP_X, 6);
  s_v.change = wpLabel(box, "", UI_FONT_BODY, UI_COL_INK_2);
  lv_obj_set_pos(s_v.change, WP_X, 28);
  s_v.diff = wpLabel(box, "", UI_FONT_BODY, UI_COL_INK_SOFT);
  lv_obj_align(s_v.diff, LV_ALIGN_TOP_RIGHT, -WP_X, 28);

  s_v.primary = wpButton(box, WP_X, WP_PRIMARY_Y, WP_INNER_W, WP_PRIMARY_H);
  lv_obj_set_style_radius(s_v.primary, UI_RADIUS_BOX, 0);
  s_v.main_lbl = wpLabel(s_v.primary, "", UI_FONT_ICON, UI_COL_OK_TEXT);
  s_v.main_sub = wpLabel(s_v.primary, "", UI_FONT_CAPTION, UI_COL_OK_TEXT_2);
  lv_obj_add_event_cb(s_v.primary, wpPrimaryClicked, LV_EVENT_CLICKED, NULL);
}

static void wpBuildSwitches(lv_obj_t *box) {
  int y = WP_ROW_Y0;
  if (bagInUse()) {
    const WpSwitch s = wpSwitchRow(box, y, LV_SYMBOL_DRIVE, STR_WP_BAG_ROW);
    s_v.bag_row = s.row; s_v.bag_sub = s.sub; s_v.bag_state = s.state;
    lv_obj_add_event_cb(s.row, [](lv_event_t *e) {
      s_bag_on = !s_bag_on;
      logSDf("UI: weight popup -> bag %s", s_bag_on ? "on" : "off");
      wpRefresh();
    }, LV_EVENT_CLICKED, NULL);
    y += WP_ROW_STEP;
  }
  // A spool shown by its id is never weighed on its own, so the switch
  // would have nothing to switch.
  if (!idSpoolActive()) {
    const WpSwitch s = wpSwitchRow(box, y, LV_SYMBOL_REFRESH, STR_WP_AUTO_ROW);
    s_v.auto_row = s.row; s_v.auto_state = s.state;
    lv_label_set_text(s.sub, T(STR_WP_AUTO_SUB));
    lv_obj_add_event_cb(s.row, [](lv_event_t *e) {
      autoWeightSwitch(!g_auto_weight);
      wpRefresh();
    }, LV_EVENT_CLICKED, NULL);
  }
}

static void wpShowOptions();

static void wpBuildBottom(lv_obj_t *box, int y) {
  const bool archive = !sm_archived;
  int x = WP_X;
  if (archive) {
    // Quiet on purpose: rarely wanted, and the question behind it catches a
    // stray tap.
    lv_obj_t *b = wpButton(box, x, y, WP_ARCHIVE_W, WP_BOTTOM_H);
    lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_SURFACE), 0);
    lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ARCHIVE_BG_PRESSED), LV_STATE_PRESSED);
    // A 1 px outline in the faint tone read as no button at all on the panel.
    lv_obj_set_style_border_width(b, UI_LEAVE_BORDER_W, 0);
    lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_ARCHIVE_BG_PRESSED), 0);
    char buf[40];
    snprintf(buf, sizeof(buf), LV_SYMBOL_TRASH "  %s", T(STR_WP_ARCHIVE));
    lv_obj_center(wpLabel(b, buf, UI_FONT_SMALL, UI_COL_ARCHIVE_TEXT));
    lv_obj_add_event_cb(b, [](lv_event_t *e) {
      closeWeightPopups();
      showConfirmPopup(T(STR_ARCHIVE_CONFIRM), 3);
    }, LV_EVENT_CLICKED, NULL);
    x += WP_ARCHIVE_W + WP_GAP;
  }
  const int w = (WP_X + WP_INNER_W - x - WP_GAP) / 2;
  lv_obj_t *opt = wpButton(box, x, y, w, WP_BOTTOM_H);
  char buf[40];
  snprintf(buf, sizeof(buf), LV_SYMBOL_SETTINGS "  %s", T(STR_WP_OPTIONS));
  lv_obj_center(wpLabel(opt, buf, UI_FONT_SMALL, UI_COL_INK_2));
  lv_obj_add_event_cb(opt, [](lv_event_t *e) { wpShowOptions(); }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *close = wpButton(box, x + w + WP_GAP, y, w, WP_BOTTOM_H);
  lv_obj_center(wpLabel(close, T(STR_BT_CLOSE), UI_FONT_SMALL, UI_COL_INK_2));
  styleLeaveButton(close);
  lv_obj_add_event_cb(close, [](lv_event_t *e) { closeWeightPopups(); }, LV_EVENT_CLICKED, NULL);
}

// fresh: a new look at the pad. Coming back from Options keeps the reading
// and the bag switch the user had set.
static void wpOpenLevel1(bool fresh) {
  if (fresh) {
    s_gross_g = scale_weight_g;
    s_bag_on = false;
    s_spool_id = sm_id;
  }
  closeWeightPopups();
  // Room for both switch rows even when one is missing: the popup keeps its
  // height and the bottom row its place, and less of the screen behind it
  // shows through.
  const int bottom_y = WP_ROW_Y0 + WP_SWITCH_ROWS_MAX * WP_ROW_STEP;
  lv_obj_t *box = uiPopupBox(&s_popup, WP_BOX_W, bottom_y + WP_BOTTOM_H + WP_BOX_EXTRA);
  wpBuildHeaderAndPrimary(box);
  wpBuildSwitches(box);
  wpBuildBottom(box, bottom_y);
  wpRefresh();
}

void showWeightPopup() {
  logSDf("SHOW: WeightPopup (spool %d, %.0f g on the pad)", sm_id, scale_weight_g);
  wpOpenLevel1(true);
}

// ---------------------------------------------------------------------------
//  Level 2: Options
// ---------------------------------------------------------------------------

static lv_obj_t* wpOptionRow(lv_obj_t *box, int y, const char *icon, int title_id, const char *sub) {
  lv_obj_t *b = wpButton(box, WP_X, y, WP_INNER_W, WP_OPT_ROW_H);
  lv_obj_set_style_radius(b, UI_RADIUS_BOX, 0);
  lv_obj_align(wpLabel(b, icon, UI_FONT_HEADLINE, UI_COL_ACCENT), LV_ALIGN_LEFT_MID, 14, 0);
  lv_obj_align(wpLabel(b, T(title_id), UI_FONT_BODY, UI_COL_INK), LV_ALIGN_LEFT_MID, 50, -10);
  lv_obj_align(wpLabel(b, sub, UI_FONT_CAPTION, UI_COL_CAPTION), LV_ALIGN_LEFT_MID, 50, 12);
  lv_obj_align(wpLabel(b, LV_SYMBOL_RIGHT, UI_FONT_BODY, UI_COL_INK_FAINT), LV_ALIGN_RIGHT_MID, -14, 0);
  return b;
}

static void wpBuildOptionRows(lv_obj_t *box, bool tare) {
  char sub[64];
  snprintf(sub, sizeof(sub), T(STR_WP_FULL_SUB), confirmNewSpoolShownG(newG()));
  lv_obj_t *full = wpOptionRow(box, WP_OPT_ROW_Y0, LV_SYMBOL_PLUS, STR_WP_FULL, sub);
  lv_obj_add_event_cb(full, [](lv_event_t *e) {
    const float g = newG();
    logSDf("UI: weight options -> full spool, %.0f g", g);
    closeWeightPopups();
    confirmNewSpool(g);
  }, LV_EVENT_CLICKED, NULL);
  // Not offered where no scope can take an empty spool weight: BamBuddy
  // behind Spoolman.
  if (!tare) return;

  snprintf(sub, sizeof(sub), T(STR_WP_WEIGH_EMPTY_SUB), scale_weight_g);
  lv_obj_t *weigh = wpOptionRow(box, WP_OPT_ROW_Y0 + WP_OPT_ROW_STEP, LV_SYMBOL_DOWNLOAD,
                                STR_WP_WEIGH_EMPTY, sub);
  lv_obj_add_event_cb(weigh, [](lv_event_t *e) {
    // The reading at the moment of the press.
    const float g = scale_weight_g;
    closeWeightPopups();
    showSpoolWeightScope(g, true);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *type = wpOptionRow(box, WP_OPT_ROW_Y0 + 2 * WP_OPT_ROW_STEP, LV_SYMBOL_KEYBOARD,
                               STR_WP_TYPE_EMPTY, T(STR_WP_TYPE_EMPTY_SUB));
  lv_obj_add_event_cb(type, [](lv_event_t *e) {
    closeWeightPopups();
    showTareEntryPad();
  }, LV_EVENT_CLICKED, NULL);
}

static void wpShowOptions() {
  logSD("SHOW: WeightOptions");
  const bool tare = backendCanTareSpool() || backendCanTareFilamentOrVendor();
  const int back_y = WP_OPT_ROW_Y0 + (tare ? 3 : 1) * WP_OPT_ROW_STEP;
  releaseScreen(&s_popup);
  lv_obj_t *box = uiPopupBox(&s_opts, WP_BOX_W, back_y + WP_BOTTOM_H + WP_BOX_EXTRA);

  lv_obj_set_pos(wpLabel(box, T(STR_WP_OPTIONS), UI_FONT_TITLE, UI_COL_INK), WP_X + 4, 10);
  char buf[48];
  snprintf(buf, sizeof(buf), "#%d  %s", sm_id, sm_filament_name);
  lv_obj_t *who = wpLabel(box, buf, UI_FONT_SMALL, UI_COL_INK_SOFT);
  lv_obj_align(who, LV_ALIGN_TOP_RIGHT, -WP_X - 4, 12);

  wpBuildOptionRows(box, tare);

  lv_obj_t *back = wpButton(box, WP_X, back_y, WP_INNER_W, WP_BOTTOM_H);
  lv_obj_center(wpLabel(back, T(STR_BACK), UI_FONT_SMALL, UI_COL_INK_2));
  styleLeaveButton(back, LV_SYMBOL_LEFT);
  lv_obj_add_event_cb(back, [](lv_event_t *e) { wpOpenLevel1(false); }, LV_EVENT_CLICKED, NULL);
}
