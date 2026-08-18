#include "scale.h"

#include <Adafruit_NAU7802.h>

static Adafruit_NAU7802 nau;

// Give up on the internal calibration after roughly three seconds. This used
// to retry forever, which hung the whole boot on a defective load cell or a
// loose cable: no display, no WiFi, no web interface, nothing but a device that
// looks dead. Returning false instead lets app_boot.cpp carry on without the
// scale, so display, NFC and the filament manager still work and the red SCL!
// in the header says what is wrong. Do not turn this back into a bare while.
#define CAL_MAX_ATTEMPTS  30
#define CAL_RETRY_DELAY_MS 100

bool scaleHardwareBegin(TwoWire* wire, void (*calibration_wait_cb)()) {
  if (!nau.begin(wire)) return false;

  nau.setLDO(NAU7802_3V0);
  nau.setGain(NAU7802_GAIN_128);
  nau.setRate(NAU7802_RATE_10SPS);

  delay(300);
  for (int attempt = 0; attempt < CAL_MAX_ATTEMPTS; attempt++) {
    if (nau.calibrate(NAU7802_CALMOD_INTERNAL)) return true;
    if (calibration_wait_cb) {
      calibration_wait_cb();
    } else {
      Serial.println("Calibrate retry...");
      delay(CAL_RETRY_DELAY_MS);
    }
  }
  Serial.println("NAU7802 calibration timed out");
  return false;
}

// True once the ADC has finished a new conversion. Reading without checking
// returns the previous sample again, which then enters the moving average a
// second time and weights it twice.
bool scaleHardwareAvailable() {
  return nau.available();
}

int32_t scaleHardwareReadRaw() {
  return nau.read();
}
