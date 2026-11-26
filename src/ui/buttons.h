#pragma once

#include <lvgl.h>

// The looks a recurring button takes, one per meaning, so a meaning reads the
// same on every screen. One colour, one meaning:
//   - green fill:            go ahead (Save, Write, Calibrate now)
//   - red fill, red edge:    destroys something (Delete, Reset, Unlink)
//   - quiet outline:         the alternative that is neither (Later, Skip,
//                            an option not chosen)
//   - filled, fine edge:     the way out. Cancel and Back with a caption go
//                            through styleLeaveButton() in ui_common.h,
//                            neutral; the icon-only close X goes through
//                            BTN_CLOSE here, in the red fill without the
//                            bright edge, so it is found at a glance and
//                            still does not read as a warning.
enum BtnRole { BTN_CONFIRM, BTN_DANGER, BTN_NEUTRAL, BTN_CLOSE, BTN_ROLE_COUNT };

// Gives a finished button its role: fill, pressed fill, border and the colour
// of every label directly on it. Size, position, radius and font stay the
// caller's. Colours the button set locally before are dropped, so the role
// wins whatever the button was built with; a caller that wants to differ
// sets its own style after this call.
void uiBtnRole(lv_obj_t* btn, BtnRole role);

// red_pct of `red`, the rest of `base`: the bright edge of a destructive button.
lv_color_t uiMixRed(uint32_t red, uint32_t base, int red_pct);

// One segment of a row of choices of which one is picked (Display's minutes,
// the drying mode, the backend, the date format): the picked one has the
// picked fill, a green edge and green text, the others are quiet, and an
// unavailable one is dimmed and takes no tap. One look for every such row, so
// a choice reads the same on every screen. Like uiBtnRole(), it is given to a
// finished button and colours the labels on it; size, position, radius and
// font stay the caller's.
enum SegState { SEG_OFF, SEG_PICKED, SEG_UNAVAILABLE, SEG_STATE_COUNT };
void uiSegmentLook(lv_obj_t* btn, SegState state);
