#include "scale_hx711.h"

#include <Arduino.h>

#include "pins.h"

// SCK high for more than 60 us powers the HX711 down; 100 us is safely past it
// and resets the chip to channel A, gain 128 when SCK falls again.
static constexpr uint32_t HX711_POWER_CYCLE_US = 100;
// A conversion takes 100 ms at 10 SPS (RATE low, the usual module) and the
// first one after a reset some 400 ms; a second covers both with room.
static constexpr uint32_t HX711_READY_TIMEOUT_MS = 1000;
// Without a conversion for this long the chip counts as gone.
static constexpr uint32_t HX711_ALIVE_MS = 1500;
static constexpr uint32_t HX711_POLL_MS = 5;
// The datasheet wants SCK high at least 0.2 us and DOUT valid 0.1 us after it.
static constexpr uint32_t HX711_CLOCK_HALF_US = 1;
static constexpr uint8_t HX711_DATA_BITS = 24;
static constexpr uint32_t HX711_ALL_ONES = 0xFFFFFFU;
static constexpr uint32_t HX711_SIGN_BIT = 0x800000U;
static constexpr uint32_t HX711_SIGN_EXTEND = 0xFF000000U;

static bool s_pins_set = false;
static uint32_t s_last_ready_ms = 0;
static int32_t s_last_raw = 0;

// A WiFi interrupt in the middle of a bit could stretch SCK past 60 us and
// power the chip down mid-sample, so the 25 pulses (some 60 us) run with this
// core's interrupts masked. A critical section nests where noInterrupts() would not.
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

static bool doutLow() {
  if (digitalRead(hw_pins::HX711_DOUT) != LOW) return false;
  s_last_ready_ms = millis();
  return true;
}

static bool waitReady(void (*wait_cb)()) {
  const uint32_t started = millis();
  while (millis() - started < HX711_READY_TIMEOUT_MS) {
    if (doutLow()) return true;
    if (wait_cb) wait_cb();
    else delay(HX711_POLL_MS);
  }
  return false;
}

// One SCK pulse; DOUT is sampled while SCK is high.
static inline uint32_t clockBit() {
  digitalWrite(hw_pins::HX711_SCK, HIGH);
  delayMicroseconds(HX711_CLOCK_HALF_US);
  const uint32_t bit = digitalRead(hw_pins::HX711_DOUT) == HIGH ? 1U : 0U;
  digitalWrite(hw_pins::HX711_SCK, LOW);
  delayMicroseconds(HX711_CLOCK_HALF_US);
  return bit;
}

// 24 data bits, MSB first, then the 25th pulse that selects channel A at gain
// 128 for the next conversion.
static uint32_t shiftIn() {
  uint32_t value = 0;
  portENTER_CRITICAL(&s_mux);
  for (uint8_t i = 0; i < HX711_DATA_BITS; ++i) value = (value << 1) | clockBit();
  clockBit();
  portEXIT_CRITICAL(&s_mux);
  return value;
}

bool hx711Begin(void (*calibration_wait_cb)()) {
  pinMode(hw_pins::HX711_DOUT, INPUT_PULLUP);
  pinMode(hw_pins::HX711_SCK, OUTPUT);
  digitalWrite(hw_pins::HX711_SCK, HIGH);
  delayMicroseconds(HX711_POWER_CYCLE_US);
  digitalWrite(hw_pins::HX711_SCK, LOW);
  s_pins_set = true;
  s_last_ready_ms = 0;

  if (!waitReady(calibration_wait_cb)) {
    Serial.println("HX711 did not become ready (power, DOUT on pin 6, SCK on pin 5)");
    return false;
  }
  // The next conversion proves the clock reaches the chip, not only DOUT the ESP.
  shiftIn();
  if (!waitReady(calibration_wait_cb)) {
    Serial.println("HX711 gave no second conversion (SCK on pin 5?)");
    return false;
  }
  hx711ReadRaw();
  return true;
}

bool hx711Present() {
  if (!s_pins_set) return false;
  if (doutLow()) return true;
  return s_last_ready_ms != 0 && millis() - s_last_ready_ms < HX711_ALIVE_MS;
}

bool hx711Available() { return s_pins_set && doutLow(); }

int32_t hx711ReadRaw() {
  if (!hx711Available()) return s_last_raw;
  uint32_t value = shiftIn();
  // A DOUT wire coming loose mid-read is pulled high and reads as all ones.
  if (value == HX711_ALL_ONES) return s_last_raw;
  if (value & HX711_SIGN_BIT) value |= HX711_SIGN_EXTEND;
  s_last_raw = (int32_t)value;
  return s_last_raw;
}
