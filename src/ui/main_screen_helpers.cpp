#include "main_screen_helpers.h"
#include "app/app_state.h"

#include <lvgl.h>
#include "ui/spool_flow.h"

void updateLinkButton() {
  if (!btn_dried || !btn_link || !btn_weight_main || !btn_copy) return;

  // Two slots, four buttons: weight and link share the left one, dried and
  // copy the right. An archived spool is the third combination of the same
  // four, not a fifth button - there is no room for one anyway.
  //
  //   unknown tag   link   + copy
  //   archived      weight + copy    <- here
  //   found         weight + dried
  //
  // Drying a spool that has been used up says nothing, while copying it is
  // exactly the restock case: the reason it is archived is that it ran out.
  if (sm_archived && sm_found) {
    lv_obj_clear_flag(btn_weight_main, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_dried,         LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_link,          LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_copy,        LV_OBJ_FLAG_HIDDEN);
    return;
  }

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
