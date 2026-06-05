#include "main_screen_helpers.h"

#include <lvgl.h>

extern bool tag_present;
extern bool sm_found;
extern lv_obj_t *btn_dried;
extern lv_obj_t *btn_link;
extern lv_obj_t *btn_weight_main;
extern lv_obj_t *btn_copy;

void updateLinkButton() {
  if (!btn_dried || !btn_link || !btn_weight_main || !btn_copy) return;
  if (tag_present && !sm_found) {
    lv_obj_add_flag(btn_weight_main,   LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_dried,         LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_link,        LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_copy,        LV_OBJ_FLAG_HIDDEN);
  } else {
    lv_obj_clear_flag(btn_weight_main, LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_dried,       LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_link,          LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_copy,          LV_OBJ_FLAG_HIDDEN);
  }
}
