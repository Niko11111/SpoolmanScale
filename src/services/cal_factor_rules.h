#pragma once

#include "app_config.h"

// The rules around the factory calibration factor, free of NVS and of the
// device, so a host test can run them (test/test_cal_factor_rules.py).
// "Not calibrated yet" is read off the value itself: cal_factor equal to
// CAL_FACTOR_DEFAULT. Both functions keep that comparison truthful.

// A device that was reset before the factory value changed still stores the
// old one, and would otherwise count as calibrated with a factor of 1 from now
// on. A real calibration stays what it is.
inline float calFactorFromStored(float stored) {
  return stored == CAL_FACTOR_LEGACY_DEFAULT ? CAL_FACTOR_DEFAULT : stored;
}

// A round factor can be measured for real: 500000 counts over a 500 g
// reference. Moved off the factory value, or the reminder would stay up after
// a good calibration. The step changes a weight by 0.001 percent.
inline float calFactorFromMeasured(float measured) {
  return measured == CAL_FACTOR_DEFAULT ? measured + CAL_FACTOR_MEASURED_STEP : measured;
}
