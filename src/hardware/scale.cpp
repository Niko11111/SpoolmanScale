#include "scale.h"

#include <Adafruit_NAU7802.h>

static Adafruit_NAU7802 nau;

bool scaleHardwareBegin(TwoWire* wire, void (*calibration_wait_cb)()) {
  if (!nau.begin(wire)) return false;

  nau.setLDO(NAU7802_3V0);
  nau.setGain(NAU7802_GAIN_128);
  nau.setRate(NAU7802_RATE_10SPS);

  delay(300);
  while (!nau.calibrate(NAU7802_CALMOD_INTERNAL)) {
    if (calibration_wait_cb) {
      calibration_wait_cb();
    } else {
      Serial.println("Calibrate retry...");
      delay(100);
    }
  }
  return true;
}

int32_t scaleHardwareReadRaw() {
  return nau.read();
}
