#include "link_wait_card.h"

#include <lvgl.h>

#include <Arduino.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui/theme.h"

// The house card's width and its row of answers, but not its height: 260 is
// room for a question of several lines, and a card that only waits looked
// empty in it (Nikolai, 23.09.2026). Top to bottom 18 - spinner 40 - 12 -
// title - 8 - kilobytes - 14 - button 56 - 12.
#define WAIT_CARD_H         200
#define WAIT_SPINNER_Y      18
#define WAIT_TITLE_Y        70
#define WAIT_BYTES_Y        102
#define WAIT_ROW_Y          (WAIT_CARD_H - UI_CARD_ROW_X - UI_POPUP_BTN_H)

// The spinner turns on its own: LVGL's timers run, the loop is no longer held
// by the download.
#define WAIT_SPINNER_SIZE   40
#define WAIT_SPINNER_ARC    6
#define WAIT_SPINNER_MS     1000
#define WAIT_SPINNER_DEG    70

static lv_obj_t *scr_wait   = nullptr;
static lv_obj_t *lbl_bytes  = nullptr;
static unsigned  shown_kb   = 0;
static bool      cancel_hit = false;

void linkWaitCardShow() {
  if (scr_wait) return;
  logSD("SHOW: LinkWaitCard");
  cancel_hit = false;
  shown_kb   = 0;

  scr_wait = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_wait, LV_HOR_RES, LV_VER_RES);
  lv_obj_set_pos(scr_wait, 0, 0);
  lv_obj_set_style_bg_color(scr_wait, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(scr_wait, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(scr_wait, 0, 0);
  lv_obj_set_style_radius(scr_wait, 0, 0);
  lv_obj_set_style_pad_all(scr_wait, 0, 0);
  lv_obj_clear_flag(scr_wait, LV_OBJ_FLAG_SCROLLABLE);
  // Swallows touches meant for the popup underneath.
  lv_obj_add_flag(scr_wait, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *box = lv_obj_create(scr_wait);
  lv_obj_set_size(box, UI_POPUP_W, WAIT_CARD_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *spin = lv_spinner_create(box, WAIT_SPINNER_MS, WAIT_SPINNER_DEG);
  lv_obj_set_size(spin, WAIT_SPINNER_SIZE, WAIT_SPINNER_SIZE);
  lv_obj_align(spin, LV_ALIGN_TOP_MID, 0, WAIT_SPINNER_Y);
  lv_obj_set_style_arc_width(spin, WAIT_SPINNER_ARC, LV_PART_MAIN);
  lv_obj_set_style_arc_width(spin, WAIT_SPINNER_ARC, LV_PART_INDICATOR);
  lv_obj_set_style_arc_color(spin, lv_color_hex(UI_COL_LINE), LV_PART_MAIN);
  lv_obj_set_style_arc_color(spin, lv_color_hex(UI_COL_ACCENT), LV_PART_INDICATOR);
  lv_obj_clear_flag(spin, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *title = lv_label_create(box);
  lv_label_set_text(title, T(STR_LOADING_SPOOLS));
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(title, UI_FONT_HEADLINE, 0);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(title, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(title, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, WAIT_TITLE_Y);

  lbl_bytes = lv_label_create(box);
  lv_label_set_text(lbl_bytes, "");
  lv_obj_set_style_text_color(lbl_bytes, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_style_text_font(lbl_bytes, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_align(lbl_bytes, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(lbl_bytes, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(lbl_bytes, LV_ALIGN_TOP_MID, 0, WAIT_BYTES_Y);

  // The whole row of answers, like the warning's OK: a way out, not a choice.
  const lv_coord_t btn_w = UI_POPUP_W - 2 * UI_CARD_ROW_X;
  lv_obj_t *btn = lv_btn_create(box);
  lv_obj_set_size(btn, btn_w, UI_POPUP_BTN_H);
  lv_obj_set_pos(btn, UI_CARD_ROW_X, WAIT_ROW_Y);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_POPUP_BORDER), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_set_style_pad_all(btn, 0, 0);
  lv_obj_clear_flag(btn, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(btn, [](lv_event_t *e) {
    (void)e;
    cancel_hit = true;
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *l = lv_label_create(btn);
  lv_label_set_text(l, T(STR_CANCEL));
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(l, UI_FONT_TITLE, 0);
  lv_obj_center(l);
}

void linkWaitCardHide() {
  if (!scr_wait) return;
  lv_obj_del(scr_wait);
  scr_wait   = nullptr;
  lbl_bytes  = nullptr;
  cancel_hit = false;
}

bool linkWaitCardOpen() { return scr_wait != nullptr; }

void linkWaitCardBytes(size_t bytes) {
  if (!lbl_bytes) return;
  const unsigned kb = (unsigned)(bytes / 1024);
  if (kb == shown_kb) return;
  shown_kb = kb;
  char buf[24];
  snprintf(buf, sizeof(buf), "%u KB", kb);
  lv_label_set_text(lbl_bytes, buf);
}

bool linkWaitCardCancelTake() {
  if (!cancel_hit) return false;
  cancel_hit = false;
  return true;
}
