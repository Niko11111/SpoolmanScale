#pragma once

#include <lvgl.h>

// The fuel gauge's battery in the header: an outline with a pole, filled to
// its level in green, yellow or red, the percent inside and a bolt in front
// of it while the charger is plugged in. Drawn from plain LVGL objects
// because the FontAwesome battery does not match the outlined chips beside
// it.
//
// Built the first time a gauge answers, so a scale without one carries no
// object for it at all. Its width is the same in every state; the header
// places it far right (lbl_hdr_bat).

// Builds the battery under parent on the first call with a gauge present,
// then shows or hides it and draws level, colour and text. Called from
// updateHeaderStatus(), before the chips are packed.
void headerBatteryUpdate(lv_obj_t *parent);
