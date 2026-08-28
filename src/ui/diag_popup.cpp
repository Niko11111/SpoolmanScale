#include "diag_popup.h"

#include <Arduino.h>
#include <cstring>
#include <lvgl.h>

#include "app/deferred_actions.h"
#include "app_config.h"
#include "hardware/sd_logger.h"
#include "lang.h"

// The longest body in the table is around 400 bytes once the umlauts are
// counted as the two bytes they really are. 1024 matches info_popup.cpp, for
// the same reason it grew to that there: a silently shortened explanation
// still reads like a finished one, so nothing would ever point at it.
#define DIAG_TEXT_BUF   1024
#define DIAG_TITLE_BUF    64

// Closes the whole modal from any button inside it. Two levels up from a
// button is the box, three is the scrim that owns everything, and it goes
// asynchronously because this runs inside the dispatch of an event belonging
// to a child of what is being freed.
static void closeFromButton(lv_event_t *e) {
  lv_obj_t *box = lv_obj_get_parent(lv_event_get_target(e));
  lv_obj_del_async(lv_obj_get_parent(box));
}

static void laterCb(lv_event_t *e) {
  closeFromButton(e);
}

static void actionCb(lv_event_t *e) {
  const DiagAction act = (DiagAction)(intptr_t)lv_event_get_user_data(e);
  // Only ever a flag. The loop opens the screen or touches the I2C bus on the
  // next pass, by which time this popup is gone.
  if (act == DIAG_ACT_CALIBRATE)    show_factor_pending = true;
  else if (act == DIAG_ACT_RECHECK) i2c_rescan_pending  = true;
  closeFromButton(e);
}

// One button, styled the way the rest of the firmware styles buttons. Green
// for the way forward, blue for the way out.
static lv_obj_t *mkButton(lv_obj_t *box, int x, int w, int str_id, bool primary,
                          lv_event_cb_t cb, void *user_data) {
  lv_obj_t *btn = lv_btn_create(box);
  lv_obj_set_size(btn, w, 48);
  lv_obj_set_pos(btn, x, 208);
  lv_obj_set_style_bg_color(btn, lv_color_hex(primary ? 0x1a3020 : 0x1a3060), 0);
  lv_obj_set_style_bg_color(btn,
    lv_color_hex(primary ? 0x2a5030 : 0x2a4080), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 8, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, user_data);

  lv_obj_t *l = lv_label_create(btn);
  char bbuf[32];
  strncpy(bbuf, T(str_id), sizeof(bbuf) - 1);
  bbuf[sizeof(bbuf) - 1] = '\0';
  lv_label_set_text(l, bbuf);
  lv_obj_set_style_text_color(l,
    lv_color_hex(primary ? 0x40c080 : 0xc8d8f0), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(l, LV_ALIGN_CENTER, 0, 0);
  return btn;
}

void showDiagPopup(DiagCode c) {
  if (c == DIAG_NONE) return;

  logSDf("SHOW: DiagPopup (%s)", diagName(c));

  lv_obj_t *pop = lv_obj_create(lv_scr_act());
  lv_obj_set_size(pop, 480, 320);
  lv_obj_set_pos(pop, 0, 0);
  lv_obj_set_style_bg_color(pop, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(pop, LV_OPA_70, 0);
  lv_obj_set_style_border_width(pop, 0, 0);
  lv_obj_set_style_radius(pop, 0, 0);
  lv_obj_set_style_pad_all(pop, 0, 0);
  lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(pop);
  lv_obj_set_size(box, 440, 270);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  // Amber rather than the usual blue, matching the warning modal in the spool
  // flow: this is a finding, not an explanation someone asked for.
  lv_obj_set_style_border_color(box, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *icon = lv_label_create(box);
  lv_label_set_text(icon, LV_SYMBOL_WARNING);
  lv_obj_set_style_text_color(icon, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(icon, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, 10);

  lv_obj_t *title = lv_label_create(box);
  char tbuf[DIAG_TITLE_BUF];
  strncpy(tbuf, T(diagTitleString(c)), sizeof(tbuf) - 1);
  tbuf[sizeof(tbuf) - 1] = '\0';
  lv_label_set_text(title, tbuf);
  lv_obj_set_style_text_color(title, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(title, 424);
  lv_obj_set_pos(title, 8, 44);

  // Scrolls rather than clips. These texts name four wires by colour, and a
  // reader who loses the last one is worse off than one who has to flick.
  lv_obj_t *scroll = lv_obj_create(box);
  lv_obj_set_size(scroll, 424, 128);
  lv_obj_set_pos(scroll, 8, 74);
  lv_obj_set_style_bg_opa(scroll, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(scroll, 0, 0);
  lv_obj_set_style_pad_all(scroll, 0, 0);
  lv_obj_set_scroll_dir(scroll, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(scroll, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(scroll, LV_OBJ_FLAG_SCROLL_ELASTIC);

  lv_obj_t *info = lv_label_create(scroll);
  // Static for the same reason as in info_popup.cpp: this runs from an LVGL
  // event nested inside lv_timer_handler(), and the buffer only has to live
  // until lv_label_set_text() has copied it into the label's own storage.
  static char ibuf[DIAG_TEXT_BUF];
  // Only the noisy text carries a placeholder, and it wants the threshold it
  // actually tripped rather than a number repeated in prose. snprintf ignores
  // the extra argument for every other text, which is why they can all go
  // through the same call.
  snprintf(ibuf, sizeof(ibuf), T(diagTextString(c)), (int)DIAG_NOISE_G);
  lv_label_set_text(info, ibuf);
  lv_obj_set_style_text_color(info, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(info, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(info, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(info, LV_LABEL_LONG_WRAP);
  // 14 px narrower than the container so the scrollbar has somewhere to sit.
  lv_obj_set_width(info, 410);
  lv_obj_set_pos(info, 0, 0);

  const DiagAction act = diagAction(c);
  if (act == DIAG_ACT_NONE) {
    // Nothing to press. A swapped pair and a loose wire both mean opening the
    // enclosure, and a second button that only closed the popup would pretend
    // the device could help with that.
    mkButton(box, 120, 200, STR_BTN_OK, false, laterCb, NULL);
  } else {
    mkButton(box, 12, 200, STR_DIAG_BTN_LATER, false, laterCb, NULL);
    mkButton(box, 228, 200,
             act == DIAG_ACT_CALIBRATE ? STR_CAL_REMINDER_NOW : STR_DIAG_BTN_RECHECK,
             true, actionCb, (void *)(intptr_t)act);
  }
}
