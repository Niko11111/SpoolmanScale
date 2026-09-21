#include "tag_busy_popup.h"

#include <lvgl.h>

#include <Arduino.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/tag_write.h"
#include "ui/theme.h"

// The width of every question, so the card stands where the question stood.
// Lower than one: it has no buttons to make room for.
#define BUSY_BOX_H      190
#define BUSY_ICON_Y      16
#define BUSY_TITLE_Y     56
#define BUSY_HINT_Y      98
#define BUSY_TEXT_PAD    40   // what the two lines stay clear of, left and right together
#define BUSY_BAR_W      320
#define BUSY_BAR_H       10
#define BUSY_BAR_Y      158
// How often the bar is redrawn at most. A page takes about 30 ms and a redraw
// a few, so following every page would make the write one tenth longer for
// steps nobody can see.
#define BUSY_BAR_TICK_MS  120

static lv_obj_t *scr_tag_busy = nullptr;
static lv_obj_t *bar_tag_busy = nullptr;

// From inside the write, after every page, see tagWriteSetProgress(). Draws
// on the spot: the loop stands still until the job is done, so nothing else
// would put a moved bar on the screen before the result replaces it.
static void busyProgress(uint16_t done, uint16_t total) {
  if (!bar_tag_busy || !total) return;
  static unsigned long last = 0;
  const unsigned long now = millis();
  if (done < total && done > 0 && now - last < BUSY_BAR_TICK_MS) return;
  last = now;
  lv_bar_set_value(bar_tag_busy, (int32_t)((uint32_t)done * 100U / total), LV_ANIM_OFF);
  lv_refr_now(NULL);
}

void tagBusyShow(bool erase) {
  if (scr_tag_busy) return;
  logSDf("SHOW: TagBusyPopup %s", erase ? "erase" : "write");

  scr_tag_busy = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_tag_busy, LV_HOR_RES, LV_VER_RES);
  lv_obj_set_pos(scr_tag_busy, 0, 0);
  lv_obj_set_style_bg_color(scr_tag_busy, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(scr_tag_busy, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(scr_tag_busy, 0, 0);
  lv_obj_set_style_radius(scr_tag_busy, 0, 0);
  lv_obj_set_style_pad_all(scr_tag_busy, 0, 0);
  lv_obj_clear_flag(scr_tag_busy, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(scr_tag_busy);
  lv_obj_set_size(box, UI_POPUP_W, BUSY_BOX_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *icon = lv_label_create(box);
  lv_label_set_text(icon, LV_SYMBOL_REFRESH);
  lv_obj_set_style_text_color(icon, lv_color_hex(UI_COL_WARN), 0);
  lv_obj_set_style_text_font(icon, UI_FONT_ICON, 0);
  lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, BUSY_ICON_Y);

  lv_obj_t *title = lv_label_create(box);
  lv_label_set_text(title, T(erase ? STR_TW_BUSY_ERASE : STR_TW_BUSY_WRITE));
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(title, UI_FONT_HEADLINE, 0);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(title, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(title, UI_POPUP_W - BUSY_TEXT_PAD);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, BUSY_TITLE_Y);

  lv_obj_t *hint = lv_label_create(box);
  lv_label_set_text(hint, T(STR_TW_BUSY_HINT));
  lv_obj_set_style_text_color(hint, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(hint, UI_FONT_BODY, 0);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(hint, UI_POPUP_W - BUSY_TEXT_PAD);
  lv_obj_align(hint, LV_ALIGN_TOP_MID, 0, BUSY_HINT_Y);

  // Empty until the first page is on the tag. A write fetches the spool from
  // the server first, and for that part there is nothing to count.
  bar_tag_busy = lv_bar_create(box);
  lv_obj_set_size(bar_tag_busy, BUSY_BAR_W, BUSY_BAR_H);
  lv_obj_align(bar_tag_busy, LV_ALIGN_TOP_MID, 0, BUSY_BAR_Y);
  lv_bar_set_range(bar_tag_busy, 0, 100);
  lv_bar_set_value(bar_tag_busy, 0, LV_ANIM_OFF);
  lv_obj_set_style_bg_color(bar_tag_busy, lv_color_hex(UI_COL_LINE), LV_PART_MAIN);
  lv_obj_set_style_bg_opa(bar_tag_busy, LV_OPA_COVER, LV_PART_MAIN);
  lv_obj_set_style_bg_color(bar_tag_busy, lv_color_hex(UI_COL_ACCENT), LV_PART_INDICATOR);
  lv_obj_set_style_radius(bar_tag_busy, BUSY_BAR_H / 2, LV_PART_MAIN);
  lv_obj_set_style_radius(bar_tag_busy, BUSY_BAR_H / 2, LV_PART_INDICATOR);
  tagWriteSetProgress(busyProgress);

  // Now, not at the next lv_timer_handler(): the write starts on the next loop
  // pass and holds the loop until it is done, and a card that is first drawn
  // together with the result is no card.
  lv_refr_now(NULL);
}

void tagBusyHide() {
  if (!scr_tag_busy) return;
  // First, so that a write nobody is watching - the web page starts those -
  // never reaches for a bar that is gone.
  tagWriteSetProgress(nullptr);
  bar_tag_busy = nullptr;
  lv_obj_del(scr_tag_busy);
  scr_tag_busy = nullptr;
}
