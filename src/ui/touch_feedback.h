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
// ============================================================

// Set as feedback_cb on the pointer input driver, next to read_cb.
void touchFeedback(lv_indev_drv_t* drv, uint8_t code);
