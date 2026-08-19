#include "reboot_popup.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "theme.h"

void showRebootPopup() {
  logSD("SHOW: RebootPopup");
  logSD("UI: Screen -> RebootPopup");
  lv_obj_t *pop = lv_obj_create(lv_scr_act());
  lv_obj_set_size(pop, 480, 320);
  lv_obj_set_pos(pop, 0, 0);
  lv_obj_set_style_bg_color(pop, tc(TH_BLACK), 0);
  lv_obj_set_style_bg_opa(pop, LV_OPA_70, 0);
  lv_obj_set_style_border_width(pop, 0, 0);
  lv_obj_set_style_pad_all(pop, 0, 0);
  lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(pop);
  lv_obj_set_size(box, 400, 220);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, tc(TH_ACCENT), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *t = lv_label_create(box);
  lv_label_set_text(t, T(STR_REBOOT_TITLE));
  lv_obj_set_style_text_color(t, tc(TH_ACCENT), 0);
  lv_obj_set_style_text_font(t, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(t, LV_ALIGN_TOP_MID, 0, 16);

  lv_obj_t *m = lv_label_create(box);
  lv_label_set_text(m, T(STR_REBOOT_MSG));
  lv_obj_set_style_text_color(m, tc(TH_TEXT), 0);
  lv_obj_set_style_text_font(m, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(m, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(m, LV_ALIGN_CENTER, 0, -18);

  lv_obj_t *btn_rb = lv_btn_create(box);
  lv_obj_set_size(btn_rb, 180, 48);
  lv_obj_align(btn_rb, LV_ALIGN_BOTTOM_LEFT, 10, -12);
  lv_obj_set_style_bg_color(btn_rb, tc(TH_OK_BG), 0);
  lv_obj_set_style_bg_color(btn_rb, tc(TH_SUCCESS_BG), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_rb, 8, 0);
  lv_obj_set_style_shadow_width(btn_rb, 0, 0);
  lv_obj_set_style_border_width(btn_rb, 0, 0);
  lv_obj_add_event_cb(btn_rb, [](lv_event_t *e){ logSD("Reboot: user (language/date change)"); ESP.restart(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *rb_lbl = lv_label_create(btn_rb);
  lv_label_set_text(rb_lbl, T(STR_REBOOT_BTN));
  lv_obj_set_style_text_color(rb_lbl, tc(TH_SUCCESS_TEXT), 0);
  lv_obj_set_style_text_font(rb_lbl, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(rb_lbl);

  lv_obj_t *btn_cancel = lv_btn_create(box);
  lv_obj_set_size(btn_cancel, 180, 48);
  lv_obj_align(btn_cancel, LV_ALIGN_BOTTOM_RIGHT, -10, -12);
  lv_obj_set_style_bg_color(btn_cancel, tc(TH_DANGER_BG), 0);
  lv_obj_set_style_bg_color(btn_cancel, tc(TH_DANGER_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_cancel, 0, 0);
  lv_obj_add_event_cb(btn_cancel, [](lv_event_t *e){
    lv_obj_t *box_obj = lv_obj_get_parent(lv_event_get_target(e));
    lv_obj_t *pop_obj = lv_obj_get_parent(box_obj);
    lv_obj_del(pop_obj);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *c_lbl = lv_label_create(btn_cancel);
  lv_label_set_text(c_lbl, T(STR_CANCEL));
  lv_obj_set_style_text_color(c_lbl, tc(TH_DANGER_TEXT), 0);
  lv_obj_set_style_text_font(c_lbl, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(c_lbl);
}
