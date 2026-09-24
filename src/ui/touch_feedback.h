#pragma once

#include <lvgl.h>

// ============================================================
//  WHAT A TOUCH DOES BEYOND WHAT LVGL DOES ON ITS OWN
//
//  LVGL 8.3 marks a row pressed the moment a finger lands on it
//  (lv_obj_event(), LV_EVENT_PRESSED), before it can know whether the finger
//  is about to tap or to scroll. Once the list starts to scroll, only the list
//  hears about it: the row keeps its pressed look until the finger lets go,
//  although the release will not click it. So every scroll through a list
//  dragged a highlighted row along that nobody had chosen.
//
//  This takes the pressed look away when the scroll begins, for every list at
//  once: it is the input driver's feedback callback, which LVGL calls for each
//  event the touch sends, so no list has to register anything.
//
//  The same place makes a press that slides off its button a cancel, as on
//  a phone. LVGL 8.3 gives every child object LV_OBJ_FLAG_PRESS_LOCK
//  (lv_obj.c:438): the button stays pressed wherever the finger goes and
//  the release clicks it. In a list that scrolls, the scroll prevents that;
//  in one short enough to fit, it did not, and a row slid off still opened.
//  Clearing the flag instead would be worse: LVGL then presses whatever the
//  finger is over, and the release clicks the neighbouring row.
//
//  Only buttons, plain objects and labels: a slider, an arc or the keyboard
//  has to follow the finger beyond its own area, which is what the lock is
//  for.
// ============================================================

// How far past the button's edge the finger may drift before the press counts
// as abandoned. Rows are 56 px tall, a fingertip covers about 40.
#define TOUCH_SLIDE_OFF_SLOP_PX 24

// Set as feedback_cb on the pointer input driver, next to read_cb.
void touchFeedback(lv_indev_drv_t* drv, uint8_t code);
