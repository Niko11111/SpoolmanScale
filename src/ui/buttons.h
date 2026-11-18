#pragma once

#include <lvgl.h>

// The looks a recurring button takes, one per meaning, so a meaning reads the
// same on every screen. One colour, one meaning:
//   - green fill:            go ahead (Save, Write, Calibrate now)
//   - red fill, red edge:    destroys something (Delete, Reset, Unlink)
//   - quiet outline:         the alternative that is neither (Later, Skip,
//                            an option not chosen)
//   - red outline, neutral:  the way out. Cancel and Back with a caption go
//                            through styleLeaveButton() in ui_common.h, the
//                            icon-only close X through BTN_CLOSE here.
enum BtnRole { BTN_CONFIRM, BTN_DANGER, BTN_NEUTRAL, BTN_CLOSE, BTN_ROLE_COUNT };

// Gives a finished button its role: fill, pressed fill, border and the colour
// of every label directly on it. Size, position, radius and font stay the
// caller's. Colours the button set locally before are dropped, so the role
// wins whatever the button was built with; a caller that wants to differ
// sets its own style after this call.
void uiBtnRole(lv_obj_t* btn, BtnRole role);

// red_pct of `red`, the rest of `base`: the reddish edge and icon of the way
// out (here and in styleLeaveButton) and the bright edge of a destructive one.
lv_color_t uiMixRed(uint32_t red, uint32_t base, int red_pct);
