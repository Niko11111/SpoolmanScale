#include "partition_popup.h"

#include <Arduino.h>
#include <lvgl.h>
#include <string.h>

#include "app_config.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/partition_layout.h"
#include "theme.h"
#include "ui_common.h"

#define HINT_BOX_W     440
#define HINT_BOX_H     292
#define HINT_TEXT_W    268
#define HINT_QR        128
#define HINT_BTN_W     200
#define HINT_BTN_H      48
#define HINT_BTN_Y     230

static lv_obj_t *s_pop = nullptr;

void closePartitionHint() { releaseScreen(&s_pop); }

static void laterCb(lv_event_t *e) {
  (void)e;
  logSD("Storage hint: later");
  releaseScreen(&s_pop);
}

void showPartitionHint() {
  logSD("SHOW: StorageHint");
  // Marked at once: the loop asks every pass, and would build it again.
  partitionHintShown();

  releaseScreen(&s_pop);
  lv_obj_t *pop = lv_obj_create(lv_scr_act());
  s_pop = pop;
  lv_obj_set_size(pop, 480, 320);
  lv_obj_set_pos(pop, 0, 0);
  lv_obj_set_style_bg_color(pop, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(pop, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(pop, 0, 0);
  lv_obj_set_style_radius(pop, 0, 0);
  lv_obj_set_style_pad_all(pop, 0, 0);
  lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(pop);
  lv_obj_set_size(box, HINT_BOX_W, HINT_BOX_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  // The blue frame of a question, not the diagnosis amber: nothing is wrong.
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *title = lv_label_create(box);
  lv_label_set_text(title, T(STR_PART_HINT_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(title, UI_FONT_TITLE, 0);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(title, HINT_BOX_W - 16);
  lv_obj_set_pos(title, 8, 16);

  // The text on the left, scrolling if a language needs more room; the code
  // to the flasher on the right, so a phone can open it on the spot.
  lv_obj_t *scroll = lv_obj_create(box);
  lv_obj_set_size(scroll, HINT_TEXT_W, 178);
  lv_obj_set_pos(scroll, 12, 46);
  lv_obj_set_style_bg_opa(scroll, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(scroll, 0, 0);
  lv_obj_set_style_pad_all(scroll, 0, 0);
  lv_obj_set_scroll_dir(scroll, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(scroll, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(scroll, LV_OBJ_FLAG_SCROLL_ELASTIC);

  // A found update that no longer fits is named; before that, the notice that
  // this is the last update to come over the air.
  char text[640];
  const char* too_big = partitionTooBigVersion();
  if (too_big[0]) snprintf(text, sizeof(text), T(STR_PART_HINT_BLOCKED), too_big);
  else            copyT(text, sizeof(text), STR_PART_HINT_TEXT);
  lv_obj_t *info = lv_label_create(scroll);
  lv_label_set_text(info, text);
  lv_obj_set_style_text_color(info, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(info, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_align(info, LV_TEXT_ALIGN_LEFT, 0);
  lv_label_set_long_mode(info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(info, HINT_TEXT_W - 12);
  lv_obj_set_pos(info, 0, 0);

  lv_obj_t *qr = lv_qrcode_create(box, HINT_QR, lv_color_black(), lv_color_white());
  lv_qrcode_update(qr, FLASHER_URL, strlen(FLASHER_URL));
  // The white frame is the quiet zone a phone needs around the code.
  lv_obj_set_style_border_color(qr, lv_color_white(), 0);
  lv_obj_set_style_border_width(qr, 6, 0);
  lv_obj_set_pos(qr, HINT_BOX_W - 12 - HINT_QR - 12, 52);
  lv_obj_t *cap = lv_label_create(box);
  lv_label_set_text(cap, T(STR_PART_HINT_QR));
  lv_obj_set_style_text_color(cap, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_style_text_font(cap, UI_FONT_CAPTION, 0);
  lv_obj_set_style_text_align(cap, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(cap, HINT_QR + 12);
  lv_obj_set_pos(cap, HINT_BOX_W - 12 - HINT_QR - 12, 52 + HINT_QR + 16);

  // Closes it until the next boot. No "never": it comes back until the scale
  // is on the current layout.
  lv_obj_t *btn = lv_btn_create(box);
  lv_obj_set_size(btn, HINT_BTN_W, HINT_BTN_H);
  lv_obj_set_pos(btn, (HINT_BOX_W - HINT_BTN_W) / 2, HINT_BTN_Y);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_POPUP_BORDER), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, laterCb, LV_EVENT_CLICKED, NULL);
  lv_obj_t *l = lv_label_create(btn);
  lv_label_set_text(l, T(STR_PART_HINT_LATER));
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
  lv_obj_center(l);
}
