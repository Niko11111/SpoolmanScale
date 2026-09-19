#include "partition_popup.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/partition_layout.h"
#include "theme.h"
#include "ui_common.h"

#define HINT_BOX_W     440
#define HINT_BOX_H     292
#define HINT_BTN_W     200
#define HINT_BTN_H      48
#define HINT_BTN_Y     230

static lv_obj_t *s_pop = nullptr;

void closePartitionHint() { releaseScreen(&s_pop); }

static void okCb(lv_event_t *e) {
  (void)e;
  logSD("Storage hint: ok for this boot");
  partitionHintShown();
  releaseScreen(&s_pop);
}

static void neverCb(lv_event_t *e) {
  (void)e;
  logSD("Storage hint: never again");
  partitionHintNever();
  releaseScreen(&s_pop);
}

// Same shape as the NFC reset hint's buttons, so the two read as one family.
static void mkButton(lv_obj_t *box, int x, int str_id, bool primary, lv_event_cb_t cb) {
  lv_obj_t *btn = lv_btn_create(box);
  lv_obj_set_size(btn, HINT_BTN_W, HINT_BTN_H);
  lv_obj_set_pos(btn, x, HINT_BTN_Y);
  lv_obj_set_style_bg_color(btn, lv_color_hex(primary ? UI_COL_OK_BG : UI_COL_LINE), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(primary ? UI_COL_OK_BG_PRESSED : UI_COL_POPUP_BORDER),
                            LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, NULL);

  lv_obj_t *l = lv_label_create(btn);
  lv_label_set_text(l, T(str_id));
  lv_obj_set_style_text_color(l, lv_color_hex(primary ? UI_COL_OK_TEXT_2 : UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(l, LV_ALIGN_CENTER, 0, 0);
}

void showPartitionHint() {
  logSD("SHOW: StorageHint");

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

  lv_obj_t *scroll = lv_obj_create(box);
  lv_obj_set_size(scroll, HINT_BOX_W - 16, 178);
  lv_obj_set_pos(scroll, 8, 46);
  lv_obj_set_style_bg_opa(scroll, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(scroll, 0, 0);
  lv_obj_set_style_pad_all(scroll, 0, 0);
  lv_obj_set_scroll_dir(scroll, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(scroll, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(scroll, LV_OBJ_FLAG_SCROLL_ELASTIC);

  lv_obj_t *info = lv_label_create(scroll);
  lv_label_set_text(info, T(STR_PART_HINT_TEXT));
  lv_obj_set_style_text_color(info, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(info, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_align(info, LV_TEXT_ALIGN_LEFT, 0);
  lv_label_set_long_mode(info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(info, HINT_BOX_W - 30);
  lv_obj_set_pos(info, 0, 0);

  mkButton(box,  12, STR_NFCRST_NEVER, false, neverCb);
  mkButton(box, 228, STR_BTN_OK,       true,  okCb);
}
