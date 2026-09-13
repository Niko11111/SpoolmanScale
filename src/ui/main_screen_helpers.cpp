#include "main_screen_helpers.h"
#include "app/app_state.h"

#include <lvgl.h>
#include "services/ams_presence.h"
#include "services/user_options.h"
#include "app_config.h"
#include "services/backend_api.h"
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


void updateAmsAffordance() {
  // Two questions, and both have to be yes. backendHasAmsView() is the cheap
  // one - a backendMode() switch and two string checks, no network - and it
  // only says the backend could talk about a printer at all. Whether that
  // printer actually has an AMS costs a blocking round trip, so it is asked
  // on a slow timer and cached in ams_presence. Without the second half the
  // chip appears on every FilaMan and BamBuddy setup, including printers
  // with no AMS on them, and leads to an empty page.
  const bool has_ams = backendHasAmsView() && amsPresenceHasAms();

  // The header chip first, and in both modes - it is the only way in on a
  // device that has a load cell. Before layoutHeaderChips() runs, which is
  // what lets the row close up when it goes.
  if (btn_hdr_ams) {
    if (has_ams) lv_obj_clear_flag(btn_hdr_ams, LV_OBJ_FLAG_HIDDEN);
    else         lv_obj_add_flag(btn_hdr_ams,   LV_OBJ_FLAG_HIDDEN);
  }

  // The rest is zone 4's right half, which exists only without a load cell.
  if (!lbl_no_scale) return;

  const bool show_ams = btn_ams_main && has_ams;

  if (btn_ams_main) {
    if (show_ams) lv_obj_clear_flag(btn_ams_main, LV_OBJ_FLAG_HIDDEN);
    else          lv_obj_add_flag(btn_ams_main,   LV_OBJ_FLAG_HIDDEN);
  }

  // With a button under it the note is a caption and sits on the zone's
  // caption row, level with "Spoolman:" opposite. Alone it is the only thing
  // in the half and goes in the middle.
  if (show_ams) {
    lv_obj_set_pos(lbl_no_scale, MAIN_NOSCALE_X, MAIN_ZONE4_Y);
    return;
  }

  // Centred from the height it really has, not from a number worked out for
  // German: a longer translation wraps to two lines, and a fixed y would hang
  // it out of the zone. The label only knows its height after a layout pass.
  lv_obj_set_pos(lbl_no_scale, MAIN_NOSCALE_X, MAIN_ZONE4_Y);
  lv_obj_update_layout(lbl_no_scale);
  const lv_coord_t h = lv_obj_get_height(lbl_no_scale);
  lv_obj_set_pos(lbl_no_scale, MAIN_NOSCALE_X,
                 MAIN_ZONE4_Y + (MAIN_ZONE4_H - h) / 2);
}
