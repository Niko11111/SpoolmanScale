#include "loading_overlay.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "lang.h"

// Redraw rate. Ten frames a second is enough to read as motion, and every
// frame costs a partial flush of a 480x320 panel that the transfer is waiting
// on - faster would slow down the very thing it is reporting.
#define LOADING_TICK_MS  100

// How far the arc travels per frame. 24 degrees at 10 fps is a full turn in
// 1.5 s, slow enough not to blur and fast enough to look alive.
#define LOADING_STEP_DEG  24

// Length of the moving segment.
#define LOADING_ARC_DEG   70

static lv_obj_t     *scr_loading   = nullptr;
static lv_obj_t     *lbl_loading   = nullptr;
static lv_obj_t     *lbl_bytes     = nullptr;
static lv_obj_t     *arc_loading   = nullptr;
static uint16_t      loading_angle = 0;
static unsigned long loading_last  = 0;

void loadingOverlayShow(const char* text) {
  if (scr_loading) { loadingOverlaySetText(text); return; }

  loading_angle = 0;
  loading_last  = 0;

  // On lv_scr_act() and created last, so it sits above whatever is underneath.
  scr_loading = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_loading, 480, 320);
  lv_obj_set_pos(scr_loading, 0, 0);
  lv_obj_set_style_bg_color(scr_loading, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_loading, LV_OPA_70, 0);
  lv_obj_set_style_border_width(scr_loading, 0, 0);
  lv_obj_set_style_radius(scr_loading, 0, 0);
  lv_obj_set_style_pad_all(scr_loading, 0, 0);
  lv_obj_clear_flag(scr_loading, LV_OBJ_FLAG_SCROLLABLE);
  // Swallows touches rather than letting them through to the list underneath,
  // which is half built at this point.
  lv_obj_add_flag(scr_loading, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *box = lv_obj_create(scr_loading);
  lv_obj_set_size(box, 320, 170);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x2a4080), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // An arc, not lv_spinner: a spinner animates through an LVGL timer, and no
  // timer runs while the fetch is blocking. This one is moved by hand in
  // loadingOverlayTick(), which is the only thing that does run.
  arc_loading = lv_arc_create(box);
  lv_obj_set_size(arc_loading, 62, 62);
  lv_obj_align(arc_loading, LV_ALIGN_TOP_MID, 0, 16);
  lv_arc_set_rotation(arc_loading, 0);
  lv_arc_set_bg_angles(arc_loading, 0, 360);
  lv_arc_set_angles(arc_loading, 0, LOADING_ARC_DEG);
  lv_obj_remove_style(arc_loading, NULL, LV_PART_KNOB);
  lv_obj_clear_flag(arc_loading, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_set_style_arc_width(arc_loading, 6, LV_PART_MAIN);
  lv_obj_set_style_arc_width(arc_loading, 6, LV_PART_INDICATOR);
  lv_obj_set_style_arc_color(arc_loading, lv_color_hex(0x1a3050), LV_PART_MAIN);
  lv_obj_set_style_arc_color(arc_loading, lv_color_hex(0x28d49a), LV_PART_INDICATOR);

  lbl_loading = lv_label_create(box);
  lv_obj_set_style_text_color(lbl_loading, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_loading, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_loading, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_loading, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_loading, 290);
  lv_obj_align(lbl_loading, LV_ALIGN_TOP_MID, 0, 92);

  lbl_bytes = lv_label_create(box);
  lv_label_set_text(lbl_bytes, "");
  lv_obj_set_style_text_color(lbl_bytes, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_bytes, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_bytes, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(lbl_bytes, 290);
  lv_obj_align(lbl_bytes, LV_ALIGN_TOP_MID, 0, 128);

  loadingOverlaySetText(text);
}

void loadingOverlaySetText(const char* text) {
  if (!scr_loading || !lbl_loading) return;
  char buf[64];
  strncpy(buf, text ? text : "", sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  lv_label_set_text(lbl_loading, buf);
  // Painted before returning, which is the whole reason this exists: the
  // caller is about to block, and a label nobody drew helps nobody.
  lv_refr_now(NULL);
  loading_last = millis();
}

void loadingOverlayTick() {
  if (!scr_loading || !arc_loading) return;

  const unsigned long now = millis();
  if (now - loading_last < LOADING_TICK_MS) return;
  loading_last = now;

  loading_angle = (uint16_t)((loading_angle + LOADING_STEP_DEG) % 360);
  lv_arc_set_angles(arc_loading, loading_angle,
                    (loading_angle + LOADING_ARC_DEG) % 360);
  lv_refr_now(NULL);
}

void loadingOverlayProgress(size_t bytes_read) {
  if (!scr_loading) return;
  // Written before the throttle check so the number is current whenever a
  // frame does get drawn, and skipped entirely when no frame is due.
  const unsigned long now = millis();
  if (now - loading_last < LOADING_TICK_MS) return;

  if (lbl_bytes) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%u KB", (unsigned)(bytes_read / 1024));
    lv_label_set_text(lbl_bytes, buf);
  }
  loadingOverlayTick();
}

void loadingOverlayHide() {
  if (!scr_loading) return;
  lv_obj_del(scr_loading);
  scr_loading = nullptr;
  lbl_loading = nullptr;
  lbl_bytes   = nullptr;
  arc_loading = nullptr;
}
