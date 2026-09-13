#pragma once

#include <stdint.h>

void saveCalFactor(float factor);
void saveBagWeight(float weight);
void saveTareOffset(int32_t offset);
void resetScaleFilter();

// The one writer of "this device has a load cell". Both switches - the row in
// the scale menu and /api/scalefitted in the browser - go through here so the
// clean-up cannot be forgotten on one of them.
//
// Turning it off drops the readings on the spot. Without that scl_ok freezes
// at whatever it last was: the 5 s refresher is skipped once the switch is
// off, and the 200 ms loss detector needs scale_ready. On hardware where the
// NAU7802 really is wired that left a green SCL in the header until the next
// restart.
//
// What it cannot do is rearrange the home screen - that is read once while the
// interface is built, which is why both callers still ask for a restart.
void setScaleFitted(bool fitted);
