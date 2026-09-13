#include "nfc_reset_popup.h"

#include <Arduino.h>
#include <cstring>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/nfc_reset.h"
#include "ui_common.h"

#define HINT_TEXT_BUF  768
#define HINT_TITLE_BUF  64

static lv_obj_t *s_hint_pop = nullptr;

void closeNfcResetHint() { releaseScreen(&s_hint_pop); }

static void closeFromButton(lv_event_t *e) {
  (void)e;
  releaseScreen(&s_hint_pop);
}

static void laterCb(lv_event_t *e) {
  logSD("NFC reset hint: later");
  nfcResetHintLater();
  closeFromButton(e);
}

static void neverCb(lv_event_t *e) {
  logSD("NFC reset hint: never again");
  nfcResetHintNever();
  closeFromButton(e);
}

// Same shape as the diagnosis popup's buttons, so the two read as one family.
static void mkButton(lv_obj_t *box, int x, int w, int str_id, bool primary,
                     lv_event_cb_t cb) {
  lv_obj_t *btn = lv_btn_create(box);
  lv_obj_set_size(btn, w, 48);
  lv_obj_set_pos(btn, x, 230);
  lv_obj_set_style_bg_color(btn, lv_color_hex(primary ? 0x1a3020 : 0x1a3060), 0);
  lv_obj_set_style_bg_color(btn,
    lv_color_hex(primary ? 0x2a5030 : 0x2a4080), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 8, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, NULL);

  lv_obj_t *l = lv_label_create(btn);
  char bbuf[40];
  copyT(bbuf, sizeof(bbuf), str_id);
  lv_label_set_text(l, bbuf);
  lv_obj_set_style_text_color(l,
    lv_color_hex(primary ? 0x40c080 : 0xc8d8f0), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(l, LV_ALIGN_CENTER, 0, 0);
}

void showNfcResetHint() {
  logSD("SHOW: NfcResetHint");

  releaseScreen(&s_hint_pop);
  lv_obj_t *pop = lv_obj_create(lv_scr_act());
  s_hint_pop = pop;
  lv_obj_set_size(pop, 480, 320);
  lv_obj_set_pos(pop, 0, 0);
  lv_obj_set_style_bg_color(pop, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(pop, LV_OPA_70, 0);
  lv_obj_set_style_border_width(pop, 0, 0);
  lv_obj_set_style_radius(pop, 0, 0);
  lv_obj_set_style_pad_all(pop, 0, 0);
  lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(pop);
  lv_obj_set_size(box, 440, 292);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  // Blue, not the diagnosis amber: nothing here is wrong with the device.
  lv_obj_set_style_border_color(box, lv_color_hex(0x3a6ea8), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *title = lv_label_create(box);
  char tbuf[HINT_TITLE_BUF];
  copyT(tbuf, sizeof(tbuf), STR_NFCRST_HINT_TITLE);
  lv_label_set_text(title, tbuf);
  lv_obj_set_style_text_color(title, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(title, 424);
  lv_obj_set_pos(title, 8, 16);

  lv_obj_t *scroll = lv_obj_create(box);
  lv_obj_set_size(scroll, 424, 178);
  lv_obj_set_pos(scroll, 8, 46);
  lv_obj_set_style_bg_opa(scroll, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(scroll, 0, 0);
  lv_obj_set_style_pad_all(scroll, 0, 0);
  lv_obj_set_scroll_dir(scroll, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(scroll, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(scroll, LV_OBJ_FLAG_SCROLL_ELASTIC);

  lv_obj_t *info = lv_label_create(scroll);
  static char ibuf[HINT_TEXT_BUF];
  copyT(ibuf, sizeof(ibuf), STR_NFCRST_HINT_TEXT);
  lv_label_set_text(info, ibuf);
  lv_obj_set_style_text_color(info, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(info, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(info, LV_TEXT_ALIGN_LEFT, 0);
  lv_label_set_long_mode(info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(info, 410);
  lv_obj_set_pos(info, 0, 0);

  mkButton(box,  12, 200, STR_NFCRST_NEVER, false, neverCb);
  mkButton(box, 228, 200, STR_NFCRST_LATER, true,  laterCb);
}
