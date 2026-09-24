#include "touch_feedback.h"

// A pressed button the finger has left by more than the slop, while nothing
// scrolls: its look goes at once, and lv_indev_wait_release() turns the
// release into PRESS_LOST instead of RELEASED and CLICKED.
static void cancelIfSlidOff() {
  lv_indev_t* indev = lv_indev_get_act();
  lv_obj_t* pressed = lv_indev_get_obj_act();
  if (!indev || !pressed) return;
  if (indev->proc.wait_until_release || indev->proc.types.pointer.scroll_obj) return;
  if (!lv_obj_has_class(pressed, &lv_btn_class) &&
      !lv_obj_check_type(pressed, &lv_obj_class) &&
      !lv_obj_check_type(pressed, &lv_label_class)) return;

  lv_point_t p;
  lv_indev_get_point(indev, &p);
  lv_area_t a;
  lv_obj_get_coords(pressed, &a);
  if (p.x >= a.x1 - TOUCH_SLIDE_OFF_SLOP_PX && p.x <= a.x2 + TOUCH_SLIDE_OFF_SLOP_PX &&
      p.y >= a.y1 - TOUCH_SLIDE_OFF_SLOP_PX && p.y <= a.y2 + TOUCH_SLIDE_OFF_SLOP_PX) return;

  lv_obj_clear_state(pressed, LV_STATE_PRESSED);
  lv_indev_wait_release(indev);
}

void touchFeedback(lv_indev_drv_t* drv, uint8_t code) {
  (void)drv;
  if (code == LV_EVENT_PRESSING) {
    cancelIfSlidOff();
    return;
  }
  if (code != LV_EVENT_SCROLL_BEGIN) return;
  // The object the finger went down on, valid here because this runs inside
  // the touch processing that is sending the event. The release after a scroll
  // sends no click, so nothing but the look depends on this state.
  lv_obj_t* pressed = lv_indev_get_obj_act();
  if (pressed) lv_obj_clear_state(pressed, LV_STATE_PRESSED);
}
