#include "app/render_bench.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <lvgl.h>
#include <stdlib.h>

#include "app_config.h"
#include "hardware/display.h"
#include "hardware/lvgl_mem.h"
#include "hardware/sd_logger.h"
#include "ui/theme.h"
#include "ui/ui_common.h"

// The same as the link flow's spool list (showFilteredSpoolList): rows of
// this size, radius and border, three labels and a swatch each, in a list of
// this size below a 52 px header. Kept alike by hand; a bench that draws
// something else measures something else.
//
// Ten rows, not thirty: only the four or five on the panel cost anything to
// draw, and ten fit in internal RAM on every build measured. Rows the pool
// would have put in PSRAM draw slower and would skew a comparison; the line
// says when that happened (ps=).
static constexpr int BENCH_ROWS          = 10;
static constexpr int BENCH_SCROLL_STEP   = 16;   // px per frame, a slow wipe
static constexpr int BENCH_SCROLL_FRAMES = 20;   // 320 px down, then up
static constexpr int BENCH_SCROLL_ROUNDS = 2;
static constexpr int BENCH_FULL_FRAMES   = 5;    // whole screen redrawn
static constexpr int BENCH_FRAMES        = 2 * BENCH_SCROLL_FRAMES * BENCH_SCROLL_ROUNDS;

// Spool data, not a caption: a name as long as real ones get, cut with dots.
static const char* const BENCH_SPOOL_NAME = "PETG HF Bambu Lab Jade White Matte";

static bool s_pending = false;

void renderBenchRequest() { s_pending = true; }

static int cmpU32(const void* a, const void* b) {
  const uint32_t x = *(const uint32_t*)a, y = *(const uint32_t*)b;
  return x < y ? -1 : (x > y ? 1 : 0);
}

static lv_obj_t* buildBenchList(lv_obj_t* ov) {
  lv_obj_t* hdr = lv_obj_create(ov);
  lv_obj_set_size(hdr, 480, 52);
  lv_obj_set_pos(hdr, 0, 0);
  lv_obj_set_style_bg_color(hdr, lv_color_hex(UI_COL_GROUND), 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_t* title = lv_label_create(hdr);
  char title_buf[24];
  snprintf(title_buf, sizeof(title_buf), "Bench - %d", BENCH_ROWS);
  lv_label_set_text(title, title_buf);
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(title, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t* list = lv_obj_create(ov);
  lv_obj_set_size(list, 460, 264);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(UI_COL_GROUND), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);

  static const char* const COLORS[] = { "#E8E8E8", "#1A1A1A", "#C0392B", "#2E86C1", "#F1C40F" };
  for (int i = 0; i < BENCH_ROWS; i++) {
    lv_obj_t* row = lv_btn_create(list);
    if (!row) break;
    lv_obj_set_size(row, 452, 56);
    lv_obj_set_style_bg_color(row, lv_color_hex(UI_COL_SURFACE), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(UI_COL_PRESS_FILL), LV_STATE_PRESSED);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(UI_COL_LINE_SOFT), 0);
    lv_obj_set_style_pad_all(row, 0, 0);

    char buf[32];
    lv_obj_t* id = lv_label_create(row);
    snprintf(buf, sizeof(buf), "%d", 100 + i);
    lv_label_set_text(id, buf);
    lv_obj_set_style_text_color(id, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_set_style_text_font(id, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(id, LV_ALIGN_TOP_LEFT, 6, 5);

    lv_obj_t* name = lv_label_create(row);
    lv_label_set_text(name, BENCH_SPOOL_NAME);
    lv_obj_set_style_text_color(name, lv_color_hex(UI_COL_INK), 0);
    lv_obj_set_style_text_font(name, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(name, LV_ALIGN_TOP_LEFT, 50, 5);
    lv_label_set_long_mode(name, LV_LABEL_LONG_DOT);
    lv_obj_set_width(name, 396);

    lv_obj_t* sw = lv_obj_create(row);
    lv_obj_set_size(sw, 14, 14);
    lv_obj_align(sw, LV_ALIGN_BOTTOM_LEFT, 6, -6);
    lv_obj_set_style_radius(sw, 3, 0);
    lv_obj_set_style_border_width(sw, 1, 0);
    lv_obj_set_style_border_color(sw, lv_color_hex(UI_COL_RULE), 0);
    lv_obj_set_style_pad_all(sw, 0, 0);
    lv_obj_clear_flag(sw, LV_OBJ_FLAG_SCROLLABLE);
    swatchPaintHex(sw, COLORS[i % (int)(sizeof(COLORS) / sizeof(COLORS[0]))]);

    lv_obj_t* rest = lv_label_create(row);
    snprintf(buf, sizeof(buf), "%d g", 120 + 29 * i);
    lv_label_set_text(rest, buf);
    lv_obj_set_style_text_color(rest, lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_set_style_text_font(rest, &lv_font_montserrat_ext_14, 0);
    lv_obj_align(rest, LV_ALIGN_BOTTOM_LEFT, 26, -5);
  }
  return list;
}

// One redraw, timed, with the flushes it caused.
static uint32_t timedRefresh(uint32_t* flush_us, uint32_t* flushes) {
  const uint32_t t0 = micros();
  lv_refr_now(NULL);
  const uint32_t dt = micros() - t0;
  const DisplayFlushStats f = displayFlushStatsTake();
  *flush_us += f.sum_us;
  *flushes  += f.count;
  return dt;
}

void renderBenchTick() {
  if (!s_pending) return;
  s_pending = false;

  // What the perf window gathered so far would be mixed into the bench: it
  // is dropped. The window this run lands in reports the bench only.
  displayFlushStatsTake();

  lv_obj_t* ov = lv_obj_create(lv_scr_act());
  lv_obj_set_size(ov, 480, 320);
  lv_obj_set_pos(ov, 0, 0);
  lv_obj_set_style_bg_color(ov, lv_color_hex(UI_COL_GROUND), 0);
  lv_obj_set_style_bg_opa(ov, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(ov, 0, 0);
  lv_obj_set_style_radius(ov, 0, 0);
  lv_obj_set_style_pad_all(ov, 0, 0);
  lv_obj_clear_flag(ov, LV_OBJ_FLAG_SCROLLABLE);
  const uint32_t ps_before = lvMemStats().ps_allocs;
  lv_obj_t* list = buildBenchList(ov);
  const uint32_t ps_allocs = lvMemStats().ps_allocs - ps_before;

  uint32_t flush_us = 0, flushes = 0;
  timedRefresh(&flush_us, &flushes);  // the first frame lays the list out

  flush_us = flushes = 0;
  uint32_t full_sum = 0;
  for (int i = 0; i < BENCH_FULL_FRAMES; i++) {
    lv_obj_invalidate(ov);
    full_sum += timedRefresh(&flush_us, &flushes);
  }
  const uint32_t full_flush_us = flush_us, full_flushes = flushes;

  static uint32_t frame_us[BENCH_FRAMES];
  flush_us = flushes = 0;
  // A list the pool cut short scrolls less far, and a frame that moved
  // nothing costs nothing: both go into the line.
  int scrolled = 0;
  for (int i = 0; i < BENCH_FRAMES; i++) {
    const bool down = (i / BENCH_SCROLL_FRAMES) % 2 == 0;
    const int dy = down ? -BENCH_SCROLL_STEP : BENCH_SCROLL_STEP;
    const lv_coord_t before = lv_obj_get_scroll_y(list);
    lv_obj_scroll_by(list, 0, dy, LV_ANIM_OFF);
    scrolled += abs(lv_obj_get_scroll_y(list) - before);
    frame_us[i] = timedRefresh(&flush_us, &flushes);
  }
  uint32_t scroll_sum = 0;
  for (int i = 0; i < BENCH_FRAMES; i++) scroll_sum += frame_us[i];
  qsort(frame_us, BENCH_FRAMES, sizeof(frame_us[0]), cmpU32);

  logSDf("bench: %s rows=%u ps=%u px=%d heap=%u full=%u/%u/%u "
         "scroll avg=%u med=%u p90=%u max=%u flush=%u strips=%u (us)",
         FW_VERSION, (unsigned)lv_obj_get_child_cnt(list), (unsigned)ps_allocs, scrolled,
         (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
         (unsigned)(full_sum / BENCH_FULL_FRAMES),
         (unsigned)(full_flush_us / BENCH_FULL_FRAMES),
         (unsigned)(full_flushes / BENCH_FULL_FRAMES),
         (unsigned)(scroll_sum / BENCH_FRAMES),
         (unsigned)frame_us[BENCH_FRAMES / 2],
         (unsigned)frame_us[BENCH_FRAMES * 9 / 10],
         (unsigned)frame_us[BENCH_FRAMES - 1],
         (unsigned)(flush_us / BENCH_FRAMES),
         (unsigned)(flushes / BENCH_FRAMES));

  lv_obj_del(ov);
}
