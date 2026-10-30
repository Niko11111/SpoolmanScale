#pragma once

#include <stdint.h>
#include <lvgl.h>

// The weight button on the main screen, in every state the automatic
// weighing takes it through. Its caption used to be written in six places -
// the main screen, the loop, the popup's switch, a spool shown by its id -
// each with its own copy of "(A)" and its own colour. One painter now, so
// they cannot disagree.
enum WeightLook : uint8_t {
  WL_MANUAL = 0,   // automatic off, or a spool shown by its id
  WL_AUTO,         // automatic on, waiting for a spool that lies still
  WL_COUNTING,     // lying still: the fill drains, the weight goes out when it is gone
  WL_SENT,         // written, until the spool comes off
  WL_UNCHANGED,    // under AUTO_WEIGHT_MIN_CHANGE_G off the backend: nothing written
  WL_RISE,         // heavier than the backend: nothing written, a tap asks
  WL_NO_SPOOL      // tag present but the pad too light for its spool: nothing written
};

// Called once the main screen has built the button and its caption. Adds the
// countdown fill behind the caption and paints the idle look.
void weightButtonAttach(lv_obj_t *btn, lv_obj_t *lbl);

// grams: the weight the caption names. WL_RISE takes the difference instead.
void weightButtonShow(WeightLook look, float grams = 0.0f);

// The countdown of WL_COUNTING, as the fill that drains towards the right
// like every other countdown on the device.
void weightButtonFill(uint32_t remaining_ms);

// WL_AUTO or WL_MANUAL, whichever the setting and a spool shown by its id
// call for.
void weightButtonIdle();

WeightLook weightButtonLook();

// Back to the idle look from one that only lasts while the spool lies still
// (WL_COUNTING, WL_NO_SPOOL): the weight moved or weighing is held off.
void weightButtonIdleIfWaiting();

// Switches automatic weighing on or off, stores it and repaints the button.
// The popup's row and the scale menu's row both go through here.
void autoWeightSwitch(bool on);
