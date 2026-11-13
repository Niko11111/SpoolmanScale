#pragma once

#include <lvgl.h>

// A status message too long for its line stands with "..." for a moment, then
// scrolls through once, stands again, and so on while it is shown. Short
// messages are not touched. LVGL scrolls a label on its own, but endlessly and
// without the dotted rest in between, so this switches the label between its
// dotted and its scrolling mode.
//
// The label needs a fixed height of one line: LVGL dots a label only where its
// text is taller than the label, and without a height it wraps instead.

// Takes over the long mode of label. Call once, after its width and height are set.
void statusScrollAttach(lv_obj_t *label);

// From the loop, every pass. A compare of the label's text while nothing changes.
void statusScrollTick();
