#include "scale.h"

#include <Adafruit_NAU7802.h>

#include "app_config.h"

static Adafruit_NAU7802 nau;
// Kept so the address can be probed without the caller handing the bus in
// again - see scaleHardwarePresent().
static TwoWire* nau_wire = nullptr;

// Give up on the internal calibration after roughly three seconds. This used
// to retry forever, which hung the whole boot on a defective load cell or a
// loose cable: no display, no WiFi, no web interface, nothing but a device that
// looks dead. Returning false instead lets app_boot.cpp carry on without the
// scale, so display, NFC and the filament manager still work and the red SCL!
// in the header says what is wrong. Do not turn this back into a bare while.
#define CAL_MAX_ATTEMPTS  30
#define CAL_RETRY_DELAY_MS 100

bool scaleHardwareBegin(TwoWire* wire, void (*calibration_wait_cb)()) {
  nau_wire = wire;

  // Asked separately so the two failure modes can be told apart. begin() also
  // returns false for a chip that answers and then refuses to start, and the
  // caller prints a different line for each.
  if (!scaleHardwarePresent()) {
    Serial.printf("NAU7802 does not acknowledge 0x%02X\n", I2C_ADDR_NAU7802);
    return false;
  }
  if (!nau.begin(wire)) {
    Serial.println("NAU7802 answered but would not start");
    return false;
  }

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

bool scaleHardwarePresent() {
  if (!nau_wire) return false;
  nau_wire->beginTransmission(I2C_ADDR_NAU7802);
  return nau_wire->endTransmission() == 0;
}

// True once the ADC has finished a new conversion. Reading without checking
// returns the previous sample again, which then enters the moving average a
// second time and weights it twice.
//
// The presence probe comes first. Without it this answers true for a chip that
// is not on the bus at all, because the failed register read is all ones and
// the conversion ready bit is one of them.
bool scaleHardwareAvailable() {
  return scaleHardwarePresent() && nau.available();
}

int32_t scaleHardwareReadRaw() {
  return nau.read();
}
