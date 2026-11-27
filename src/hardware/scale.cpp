#include "scale.h"

#include <Adafruit_NAU7802.h>

#include "app_config.h"
#include "scale_hx711.h"

static Adafruit_NAU7802 nau;
// Kept so the address can be probed without the caller handing the bus in
// again - see scaleHardwarePresent().
static TwoWire* nau_wire = nullptr;

// Which ADC the last scaleHardwareBegin() settled on. A NAU7802 that answers
// always wins, so a device that has one behaves exactly as before; the HX711
// on pins 5/6 is only asked when nothing acknowledges 0x2A.
enum class ScaleAdc : uint8_t { None, Nau7802, Hx711 };
static ScaleAdc s_adc = ScaleAdc::None;

// Give up on the internal calibration after roughly three seconds. This used
// to retry forever, which hung the whole boot on a defective load cell or a
// loose cable: no display, no WiFi, no web interface, nothing but a device that
// looks dead. Returning false instead lets app_boot.cpp carry on without the
// scale, so display, NFC and the filament manager still work and the red SCL!
// in the header says what is wrong. Do not turn this back into a bare while.
#define CAL_MAX_ATTEMPTS  30
#define CAL_RETRY_DELAY_MS 100

static bool nauAcks() {
  if (!nau_wire) return false;
  nau_wire->beginTransmission(I2C_ADDR_NAU7802);
  return nau_wire->endTransmission() == 0;
}

static bool nauBegin(TwoWire* wire, void (*calibration_wait_cb)()) {
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

bool scaleHardwareBegin(TwoWire* wire, void (*calibration_wait_cb)()) {
  nau_wire = wire;

  // Asked separately so the two failure modes can be told apart. begin() also
  // returns false for a chip that answers and then refuses to start, and the
  // caller prints a different line for each.
  if (nauAcks()) {
    s_adc = ScaleAdc::Nau7802;
    return nauBegin(wire, calibration_wait_cb);
  }
  Serial.printf("NAU7802 does not acknowledge 0x%02X, trying HX711\n", I2C_ADDR_NAU7802);
  if (hx711Begin(calibration_wait_cb)) {
    s_adc = ScaleAdc::Hx711;
    return true;
  }
  s_adc = ScaleAdc::None;
  return false;
}

// Nothing found yet: either one coming back counts, so the 5 s probe in the
// loop finds a plug pushed in later, whichever ADC is behind it.
bool scaleHardwarePresent() {
  switch (s_adc) {
    case ScaleAdc::Nau7802: return nauAcks();
    case ScaleAdc::Hx711:   return hx711Present();
    default:                return nauAcks() || hx711Present();
  }
}

// True once the ADC has finished a new conversion. Reading without checking
// returns the previous sample again, which then enters the moving average a
// second time and weights it twice.
//
// The presence probe comes first. Without it this answers true for a chip that
// is not on the bus at all, because the failed register read is all ones and
// the conversion ready bit is one of them.
bool scaleHardwareAvailable() {
  switch (s_adc) {
    case ScaleAdc::Nau7802: return nauAcks() && nau.available();
    case ScaleAdc::Hx711:   return hx711Available();
    default:                return false;
  }
}

int32_t scaleHardwareReadRaw() {
  return s_adc == ScaleAdc::Hx711 ? hx711ReadRaw() : nau.read();
}

const char* scaleHardwareName() {
  switch (s_adc) {
    case ScaleAdc::Nau7802: return "NAU7802";
    case ScaleAdc::Hx711:   return "HX711";
    default:                return "no ADC";
  }
}
