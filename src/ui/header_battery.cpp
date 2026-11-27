#include "header_battery.h"

#include <cstdio>
#include <cstring>

#include "app/app_state.h"
#include "hardware/fuel_gauge.h"
#include "hardware/lvgl_mem.h"
#include "hardware/sd_logger.h"
#include "services/user_options.h"
#include "ui/theme.h"

// Outline 36 x 16 with a 2 px pole: 38 px in the row, 12 less than the
// FontAwesome glyph with its percent took. Inside the 1 px outline and 1 px
// padding the fill has 32 x 12: "100" or a bolt and two digits in font 12,
// with a pixel of air to the outline. At 34 it touched it.
#define BAT_BODY_W        36
#define BAT_BODY_H        16
#define BAT_BODY_BORDER    1
#define BAT_BODY_PAD       1
#define BAT_INNER_W       (BAT_BODY_W - 2 * (BAT_BODY_BORDER + BAT_BODY_PAD))
#define BAT_INNER_H       (BAT_BODY_H - 2 * (BAT_BODY_BORDER + BAT_BODY_PAD))
#define BAT_POLE_W         2
#define BAT_POLE_H         6
#define BAT_W             (BAT_BODY_W + BAT_POLE_W)
// One pixel between the digits: without it "88" runs together at this size.
#define BAT_TEXT_LETTER_SPACE 1

// Fill colour by level, in percent: green from BAT_GREEN_PCT, yellow from
// BAT_YELLOW_PCT, red below.
#define BAT_GREEN_PCT     45
#define BAT_YELLOW_PCT    20
#define BAT_PCT_FULL     100
// Under a text the fill is drawn at half cover: the number keeps 4.9:1 or more
// on green and yellow in both themes, and the level still shows. Red stays
// solid: below BAT_YELLOW_PCT it ends where the centred text begins.
#define BAT_FILL_OPA_UNDER_TEXT LV_OPA_50

// One object that draws itself: outline, pole, fill and text are painted in
// its draw event rather than built from five child objects and a label,
// which cost 1.1 kB of LVGL memory in 21 blocks. Only its size lives in a
// shared style, so it holds no local style until the header places it.
static lv_style_t s_st_box;
static char s_text[12] = "";
static int s_pct = 0;

static void areaAt(lv_area_t *a, lv_coord_t x, lv_coord_t y, lv_coord_t w, lv_coord_t h) {
  a->x1 = x;
  a->y1 = y;
  a->x2 = x + w - 1;
  a->y2 = y + h - 1;
}

static uint32_t levelColour(int pct);

static void drawShell(lv_draw_ctx_t *ctx, const lv_area_t *box) {
  lv_draw_rect_dsc_t dsc;
  lv_draw_rect_dsc_init(&dsc);
  dsc.bg_opa = LV_OPA_TRANSP;
  dsc.border_width = BAT_BODY_BORDER;
  dsc.border_color = lv_color_hex(UI_COL_CAPTION);
  dsc.radius = UI_RADIUS_GAUGE;
  lv_area_t a;
  areaAt(&a, box->x1, box->y1, BAT_BODY_W, BAT_BODY_H);
  lv_draw_rect(ctx, &dsc, &a);

  lv_draw_rect_dsc_init(&dsc);
  dsc.bg_color = lv_color_hex(UI_COL_CAPTION);
  dsc.radius = UI_RADIUS_GAUGE_INNER;
  areaAt(&a, box->x1 + BAT_BODY_W, box->y1 + (BAT_BODY_H - BAT_POLE_H) / 2, BAT_POLE_W, BAT_POLE_H);
  lv_draw_rect(ctx, &dsc, &a);
}

// Under a text the fill is see-through, see BAT_FILL_OPA_UNDER_TEXT.
static void drawFill(lv_draw_ctx_t *ctx, const lv_area_t *inner) {
  const lv_coord_t w = BAT_INNER_W * s_pct / BAT_PCT_FULL;
  if (w <= 0) return;
  lv_draw_rect_dsc_t dsc;
  lv_draw_rect_dsc_init(&dsc);
  dsc.bg_color = lv_color_hex(levelColour(s_pct));
  dsc.bg_opa = (s_text[0] && s_pct >= BAT_YELLOW_PCT) ? BAT_FILL_OPA_UNDER_TEXT : LV_OPA_COVER;
  dsc.radius = UI_RADIUS_GAUGE_INNER;
  lv_area_t a;
  areaAt(&a, inner->x1, inner->y1, w, BAT_INNER_H);
  lv_draw_rect(ctx, &dsc, &a);
}

// Centred on the fill area; one line of font 12 is taller than the 12 px
// inside, so it is placed by its line height and overhangs the padding evenly.
static void drawText(lv_draw_ctx_t *ctx, const lv_area_t *inner) {
  if (!s_text[0]) return;
  lv_draw_label_dsc_t dsc;
  lv_draw_label_dsc_init(&dsc);
  dsc.font = &lv_font_montserrat_ext_12;
  dsc.color = lv_color_hex(UI_COL_INK);
  dsc.letter_space = BAT_TEXT_LETTER_SPACE;
  dsc.align = LV_TEXT_ALIGN_CENTER;
  const lv_coord_t line_h = lv_font_get_line_height(dsc.font);
  lv_area_t a;
  areaAt(&a, inner->x1, inner->y1 + (BAT_INNER_H - line_h) / 2, BAT_INNER_W, line_h);
  lv_draw_label(ctx, &dsc, &a, s_text, nullptr);
}

static void batteryDrawCb(lv_event_t *e) {
  lv_draw_ctx_t *ctx = lv_event_get_draw_ctx(e);
  lv_area_t box;
  lv_obj_get_coords(lv_event_get_target(e), &box);
  drawShell(ctx, &box);
  const lv_coord_t inset = BAT_BODY_BORDER + BAT_BODY_PAD;
  lv_area_t inner;
  areaAt(&inner, box.x1 + inset, box.y1 + inset, BAT_INNER_W, BAT_INNER_H);
  drawFill(ctx, &inner);
  drawText(ctx, &inner);
}

// A bare object: no theme styles and not clickable, so it reads as a status
// and never as one of the bordered chips that are buttons.
static void buildBattery(lv_obj_t *parent) {
  const LvMemStats before = lvMemStats();
  lv_style_init(&s_st_box);
  lv_style_set_width(&s_st_box, BAT_W);
  lv_style_set_height(&s_st_box, BAT_BODY_H);
  lbl_hdr_bat = lv_obj_create(parent);
  lv_obj_remove_style_all(lbl_hdr_bat);
  lv_obj_add_style(lbl_hdr_bat, &s_st_box, 0);
  lv_obj_clear_flag(lbl_hdr_bat, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(lbl_hdr_bat, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_event_cb(lbl_hdr_bat, batteryDrawCb, LV_EVENT_DRAW_MAIN, nullptr);
  const LvMemStats after = lvMemStats();
  logSDf("Fuel gauge: header battery built, LVGL +%d bytes, +%d blocks",
         (int)(after.int_used - before.int_used), (int)(after.blocks - before.blocks));
}

static uint32_t levelColour(int pct) {
  if (pct >= BAT_GREEN_PCT)  return UI_COL_GOOD;
  if (pct >= BAT_YELLOW_PCT) return UI_COL_WARN;
  return UI_COL_BAD;
}

// Plugged in (charging, or full with the charger still on): a bolt in front
// of the number. Full and plugged in, or without the number, the bolt alone:
// "100" and a bolt do not fit in 30 px.
static void batteryText(char *buf, size_t len, int pct, bool plugged) {
  buf[0] = '\0';
  if (plugged && (pct >= BAT_PCT_FULL || !g_bat_percent)) {
    snprintf(buf, len, "%s", LV_SYMBOL_CHARGE);
  } else if (plugged) {
    snprintf(buf, len, "%s%d", LV_SYMBOL_CHARGE, pct);
  } else if (g_bat_percent) {
    snprintf(buf, len, "%d", pct);
  }
}

// Redraws only when something it shows changed.
static void drawBattery() {
  int pct = fuelGaugePercent();
  if (pct < 0) pct = 0;
  if (pct > BAT_PCT_FULL) pct = BAT_PCT_FULL;
  const FuelGaugeFlow flow = fuelGaugeFlow();
  const bool plugged = flow == FUEL_FLOW_CHARGING || flow == FUEL_FLOW_FULL;
  char text[sizeof(s_text)];
  batteryText(text, sizeof(text), pct, plugged);
  if (pct == s_pct && strcmp(text, s_text) == 0) return;
  s_pct = pct;
  snprintf(s_text, sizeof(s_text), "%s", text);
  lv_obj_invalidate(lbl_hdr_bat);
}

void headerBatteryUpdate(lv_obj_t *parent) {
  if (!fuelGaugePresent()) {
    if (lbl_hdr_bat) lv_obj_add_flag(lbl_hdr_bat, LV_OBJ_FLAG_HIDDEN);
    return;
  }
  if (!lbl_hdr_bat) {
    if (!parent) return;
    buildBattery(parent);
  }
  drawBattery();
  lv_obj_clear_flag(lbl_hdr_bat, LV_OBJ_FLAG_HIDDEN);
}
