#include "scale.h"

#include <Adafruit_NAU7802.h>

#include "app_config.h"
#include "pins.h"

#if SCALE_ADC_HX711
static bool hx_initialized = false;
static uint32_t hx_last_ready_ms = 0;

// SCK held high for more than 60 us puts the HX711 into power-down, and the
// sample being clocked out is lost. A WiFi interrupt landing mid-bit could
// stretch the pulse past that limit, so interrupts on this core are masked
// for the ~60 us a full read takes. A critical section rather than
// noInterrupts(), because it nests safely inside other critical code.
static portMUX_TYPE hx_mux = portMUX_INITIALIZER_UNLOCKED;

// HX711 conversion data is ready while DOUT is low and remains there until
// the 25th clock selects channel A, gain 128, for the next conversion.
static bool hx_ready() {
  if (!hx_initialized) return false;
  if (digitalRead(hw_pins::HX711_DOUT) == LOW) {
    hx_last_ready_ms = millis();
    return true;
  }
  // DOUT is normally high while a conversion is in progress. Treat the
  // module as present during that interval, but notice a disconnected/stuck
  // output after several expected 10 SPS conversion periods.
  return hx_last_ready_ms != 0 && millis() - hx_last_ready_ms < 1500;
}

static bool hx_wait_ready(void (*wait_cb)()) {
  const uint32_t started = millis();
  while (millis() - started < 3000) {
    if (digitalRead(hw_pins::HX711_DOUT) == LOW) {
      hx_last_ready_ms = millis();
      return true;
    }
    if (wait_cb) wait_cb();
    else delay(10);
  }
  return false;
}

// One SCK pulse, returning DOUT as sampled while SCK is high. The datasheet
// wants at least 0.2 us high and 0.1 us before DOUT is valid.
static inline uint32_t hx_clock() {
  digitalWrite(hw_pins::HX711_SCK, HIGH);
  delayMicroseconds(1);
  const uint32_t bit = digitalRead(hw_pins::HX711_DOUT) == HIGH ? 1U : 0U;
  digitalWrite(hw_pins::HX711_SCK, LOW);
  delayMicroseconds(1);
  return bit;
}

// Clocks out one conversion: 24 data bits, MSB first, then the 25th pulse
// that selects channel A at gain 128 for the next one.
static uint32_t hx_shift_in() {
  uint32_t value = 0;
  portENTER_CRITICAL(&hx_mux);
  for (uint8_t i = 0; i < 24; ++i) value = (value << 1) | hx_clock();
  hx_clock();
  portEXIT_CRITICAL(&hx_mux);
  return value;
}
#else
static Adafruit_NAU7802 nau;
// Kept so the address can be probed without the caller handing the bus in
// again - see scaleHardwarePresent().
static TwoWire* nau_wire = nullptr;
#endif

// The most recent sample handed out, for reports that want the raw count
// without clocking a conversion away from the weight filter - see
// scaleHardwareLastRaw().
static int32_t last_raw = 0;
static bool have_last_raw = false;

// Give up on the internal calibration after roughly three seconds. This used
// to retry forever, which hung the whole boot on a defective load cell or a
// loose cable: no display, no WiFi, no web interface, nothing but a device that
// looks dead. Returning false instead lets app_boot.cpp carry on without the
// scale, so display, NFC and the filament manager still work and the red SCL!
// in the header says what is wrong. Do not turn this back into a bare while.
#define CAL_MAX_ATTEMPTS  30
#define CAL_RETRY_DELAY_MS 100

bool scaleHardwareBegin(TwoWire* wire, void (*calibration_wait_cb)()) {
#if SCALE_ADC_HX711
  (void)wire;
  pinMode(hw_pins::HX711_DOUT, INPUT_PULLUP);
  pinMode(hw_pins::HX711_SCK, OUTPUT);
  // Power-down and back up: SCK high for well over 60 us, then low, resets
  // the chip to channel A, gain 128, whatever state a half-finished read or
  // a recovery after a loose plug left it in.
  digitalWrite(hw_pins::HX711_SCK, HIGH);
  delayMicroseconds(100);
  digitalWrite(hw_pins::HX711_SCK, LOW);
  hx_initialized = true;
  hx_last_ready_ms = 0;

  if (!hx_wait_ready(calibration_wait_cb)) {
    Serial.println("HX711 did not become ready (check power, DOUT and SCK)");
    return false;
  }
  // The first conversion after a reset is discarded; the next one proves the
  // clock line reaches the chip as well, not only the data line.
  hx_shift_in();
  if (!hx_wait_ready(calibration_wait_cb)) {
    Serial.println("HX711 did not produce a conversion after gain setup");
    return false;
  }
  return true;
#else
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
#endif
}

bool scaleHardwarePresent() {
#if SCALE_ADC_HX711
  return hx_ready();
#else
  if (!nau_wire) return false;
  nau_wire->beginTransmission(I2C_ADDR_NAU7802);
  return nau_wire->endTransmission() == 0;
#endif
}

bool scaleHardwareProbe() {
#if SCALE_ADC_HX711
  if (!hx_initialized) return false;
  // A conversion seen recently answers at once, so the 5 s watchdog does not
  // stall the loop for up to a conversion period on a healthy scale.
  if (hx_ready()) return true;
  const uint32_t started = millis();
  while (millis() - started < 150) {
    if (digitalRead(hw_pins::HX711_DOUT) == LOW) {
      hx_last_ready_ms = millis();
      return true;
    }
    delay(1);
  }
  return hx_ready();
#else
  return scaleHardwarePresent();
#endif
}

// True once the ADC has finished a new conversion. Reading without checking
// returns the previous sample again, which then enters the moving average a
// second time and weights it twice.
//
// The presence probe comes first. Without it this answers true for a chip that
// is not on the bus at all, because the failed register read is all ones and
// the conversion ready bit is one of them.
bool scaleHardwareAvailable() {
#if SCALE_ADC_HX711
  return hx_initialized && digitalRead(hw_pins::HX711_DOUT) == LOW;
#else
  return scaleHardwarePresent() && nau.available();
#endif
}

bool scaleHardwareReadRaw(int32_t* raw) {
  if (!raw) return false;
  const uint32_t wait_started = millis();
  while (!scaleHardwareAvailable() && millis() - wait_started < 150) {
    delay(1);
  }
  if (!scaleHardwareAvailable()) return false;
#if SCALE_ADC_HX711
  hx_last_ready_ms = millis();
  uint32_t value = hx_shift_in();

  // A DOUT wire that comes loose mid-read is pulled high and yields all ones.
  // Reject it rather than letting a lost sensor contribute a plausible-looking
  // sample of -1; a genuine -1 only costs one dropped reading.
  if (value == 0xFFFFFFU) return false;
  if (value & 0x800000U) value |= 0xFF000000U;
  *raw = (int32_t)value;
#else
  *raw = nau.read();
#endif
  last_raw = *raw;
  have_last_raw = true;
  return true;
}

bool scaleHardwareLastRaw(int32_t* raw) {
  if (!raw || !have_last_raw) return false;
  *raw = last_raw;
  return true;
}
