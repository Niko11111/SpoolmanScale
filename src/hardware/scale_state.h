#pragma once

#include <stdint.h>

void saveCalFactor(float factor);
void saveBagWeight(float weight);
void saveTareOffset(int32_t offset);
void resetScaleFilter();

// Drift correction for an empty pad. Call once per new sample, after
// scale_weight_g has been updated. `allowed` is false whenever something other
// than an empty pad could explain a small reading: a tag on the reader, a
// spool adopted without one, or a popup that is working with the weight.
// Re-zeroes only when the filtered weight has sat within AUTO_TARE_BAND_G of
// zero, steady, for AUTO_TARE_STABLE_MS, and never twice within
// AUTO_TARE_COOLDOWN_MS.
#define AUTO_TARE_BAND_G        5.0f     // largest offset it will remove
#define AUTO_TARE_DEADZONE_G    0.5f     // below this the display reads 0 anyway
#define AUTO_TARE_SPREAD_G      1.0f     // peak to peak of the filter window
#define AUTO_TARE_STABLE_MS     3000
#define AUTO_TARE_COOLDOWN_MS   60000
void scaleAutoTareTick(bool allowed);

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
