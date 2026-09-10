#include "main_screen_helpers.h"
#include "app/app_state.h"

#include <lvgl.h>
#include "services/user_options.h"
#include "ui/spool_flow.h"

void updateLinkButton() {
  // Whichever button buildUI() put in the left slot. With a load cell that is
  // "update weight"; without one there is no weight to send and the slot holds
  // the location instead. Only ever one of the two exists, so this asks for the
  // one that does rather than testing both.
  lv_obj_t *slot1 = g_scale_fitted ? btn_weight_main : btn_location;

  if (!btn_dried || !btn_link || !slot1 || !btn_copy) return;

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
    // The location picker refuses an archived spool, so on a device without a
    // scale the left slot has nothing to offer and stays empty. A button that
    // does nothing when pressed is worse than a gap.
    if (g_scale_fitted) lv_obj_clear_flag(slot1, LV_OBJ_FLAG_HIDDEN);
    else                lv_obj_add_flag(slot1,   LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_dried,         LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_link,          LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_copy,        LV_OBJ_FLAG_HIDDEN);
    return;
  }

  if (tag_present && !sm_found) {
    lv_obj_add_flag(slot1,             LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_dried,         LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_link,        LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_copy,        LV_OBJ_FLAG_HIDDEN);
  } else {
    lv_obj_clear_flag(slot1,           LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_dried,       LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_link,          LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_copy,          LV_OBJ_FLAG_HIDDEN);
  }
}
