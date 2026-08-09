#include "main_screen_helpers.h"
#include "app/app_state.h"

#include <lvgl.h>
#include "ui/spool_flow.h"

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
