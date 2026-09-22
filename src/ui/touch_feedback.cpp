#include "touch_feedback.h"

void touchFeedback(lv_indev_drv_t* drv, uint8_t code) {
  (void)drv;
  if (code != LV_EVENT_SCROLL_BEGIN) return;
  // The object the finger went down on, valid here because this runs inside
  // the touch processing that is sending the event. The release after a scroll
  // sends no click, so nothing but the look depends on this state.
  lv_obj_t* pressed = lv_indev_get_obj_act();
  if (pressed) lv_obj_clear_state(pressed, LV_STATE_PRESSED);
}
