#pragma once

#include <lvgl.h>

// The one visible sign that the diagnosis found something.
//
// A 480x22 strip filling the status bar (zone 2, y=26..47). The main screen is
// otherwise fully packed - the only free rectangle is a 194x18 block in zone 4,
// too small for a sentence anyone can read - and the status line is the right
// thing to cover: it carries "waiting for a scan" and a scan counter, and when
// the hardware does not work, the reason is worth more than either. Nothing is
// moved to make room, so when the finding clears the strip goes away and the
// status bar is exactly as it was.
//
// Two decisions that are not cosmetic:
//
// It is a child of the status bar, not of the screen. Overlay screens are
// siblings of the status bar created later, so they draw above it and above
// everything inside it - which means this cannot float over the settings
// screens no matter when it comes into being. Parenting it to lv_scr_act()
// would have made that true only for as long as it was created before the
// first overlay.
//
// And it is built on demand rather than at boot. The LVGL pool on this device
// reaches 97 percent with 1136 bytes as its biggest free block while the extra
// fields screen is open; two objects held permanently for a device with
// nothing wrong were enough to push a rounded border there into a mask
// allocation it never came back from. A healthy scale now pays nothing, and a
// scale with a finding is one whose owner is about to be looking at it anyway.
void diagBannerInit(lv_obj_t *status_bar);

// Creates, re-texts or frees the strip to match diagnosticsCurrent(). Cheap on
// an unchanged finding, so the loop can call it every pass. Called from the
// loop and never from an event, which is what makes the delete here safe.
void updateDiagBanner();
