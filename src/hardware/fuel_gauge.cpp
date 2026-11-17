#include "fuel_gauge.h"

#include <Arduino.h>
#include <Wire.h>
#include <math.h>

#include "app/app_state.h"
#include "hardware/i2c_scan.h"
#include "hardware/sd_logger.h"

// MAX17048 registers. SOC is 1/256 of a percent per LSB. CRATE is a signed
// rate in 0.208 %/hour per LSB: positive while the cell is taking charge,
// negative while it is giving it back. VCELL is 78.125 µV per LSB.
// MODE bit 14 restarts the ModelGauge from the voltage it sees right now.
// A chip that came up before the cell was there, or that never got a first
// calculation, sits at 0% and will not leave it on its own.
#define FUEL_REG_VCELL  0x02
#define FUEL_REG_SOC    0x04
#define FUEL_REG_MODE   0x06
#define FUEL_REG_CRATE  0x16
#define FUEL_MODE_QUICK 0x4000
#define FUEL_VCELL_UV   78.125f
#define FUEL_SOC_LSB_PER_PCT 256.0f
#define FUEL_CRATE_PCT_H     0.208f
// Above this the read did not reach the chip (0xFFFF reads as 255 %).
#define FUEL_SOC_SANE_MAX    120.0f
#define FUEL_UV_PER_V        1000000.0f
#define FUEL_PERCENT_MAX     100
// The shown percent moves only once the raw value is this far from it, so a
// cell sitting at x.5 % does not flip the header and the log every poll.
#define FUEL_PERCENT_HYST    0.75f

// The rate register on this chip swings from one sample to the next, so the
// icon follows the smoothed rate, not the raw one. A charger that is also
// feeding the display can leave only a couple of percent an hour for the
// cell, so the threshold to enter a direction is low; the hold below keeps
// the noise out. A direction is kept until the smoothed rate falls inside
// the leave band or turns the other way.
#define FUEL_RATE_ENTER_PCT_H  1.5f
#define FUEL_RATE_LEAVE_PCT_H  0.5f
// At the top of the scale a small positive rate is the charger tapering off,
// not a cell that is still filling. Past this it is still charging.
#define FUEL_TRICKLE_PCT_H     2.0f
#define FUEL_FULL_PERCENT      99
// How many polls a new direction has to last before the icon follows.
#define FUEL_FLOW_HOLD_POLLS   3
// Weight of a new rate sample in the running average (0..1).
#define FUEL_RATE_SMOOTHING    0.3f
// A cell at this voltage is not empty, so a gauge that still reads below
// FUEL_STUCK_PERCENT after FUEL_STUCK_POLLS polls (one minute) never got its
// first calculation and is restarted once.
#define FUEL_STUCK_PERCENT     2
#define FUEL_STUCK_MIN_V       3.50f
#define FUEL_STUCK_POLLS       12

#define FUEL_POLL_PRESENT_MS   5000
#define FUEL_POLL_ABSENT_MS    30000
#define FUEL_MISS_LIMIT        3

static bool s_present = false;
static int s_percent = 0;
static FuelGaugeFlow s_flow = FUEL_FLOW_RESTING;
static uint8_t s_misses = 0;
static uint32_t s_last_ms = 0;
static bool s_quick_done = false;
static bool s_rate_init = false;
static float s_rate_avg = 0;
static FuelGaugeFlow s_pending = FUEL_FLOW_RESTING;
static uint8_t s_pending_n = 0;
static uint8_t s_low_soc_n = 0;

bool fuelGaugePresent() { return s_present; }
int fuelGaugePercent() { return s_percent; }
FuelGaugeFlow fuelGaugeFlow() { return s_flow; }

static bool readReg(uint8_t reg, uint16_t *out) {
  I2C_EXT.beginTransmission(I2C_ADDR_MAX17048);
  I2C_EXT.write(reg);
  if (I2C_EXT.endTransmission(false) != 0) return false;
  if (I2C_EXT.requestFrom((int)I2C_ADDR_MAX17048, 2) != 2) return false;
  const uint8_t hi = I2C_EXT.read();
  const uint8_t lo = I2C_EXT.read();
  *out = (uint16_t)((hi << 8) | lo);
  return true;
}

static bool writeReg(uint8_t reg, uint16_t value) {
  I2C_EXT.beginTransmission(I2C_ADDR_MAX17048);
  I2C_EXT.write(reg);
  I2C_EXT.write((uint8_t)(value >> 8));
  I2C_EXT.write((uint8_t)(value & 0xFF));
  return I2C_EXT.endTransmission() == 0;
}

static FuelGaugeFlow classify(float rate, int percent) {
  const float charge_at = (s_flow == FUEL_FLOW_CHARGING)
                            ? FUEL_RATE_LEAVE_PCT_H : FUEL_RATE_ENTER_PCT_H;
  const float discharge_at = (s_flow == FUEL_FLOW_DISCHARGING)
                               ? -FUEL_RATE_LEAVE_PCT_H : -FUEL_RATE_ENTER_PCT_H;
  const bool topped = percent >= FUEL_FULL_PERCENT;

  if (rate >= charge_at) {
    if (topped && rate < FUEL_TRICKLE_PCT_H) return FUEL_FLOW_FULL;
    return FUEL_FLOW_CHARGING;
  }
  if (rate <= discharge_at) return FUEL_FLOW_DISCHARGING;
  if (topped) return FUEL_FLOW_FULL;
  // Inside the band a direction is kept only while the rate still points
  // that way. A cell that was discharging and now gains charge, even slowly,
  // is no longer discharging.
  if (s_flow == FUEL_FLOW_CHARGING && rate > 0) return FUEL_FLOW_CHARGING;
  if (s_flow == FUEL_FLOW_DISCHARGING && rate < 0) return FUEL_FLOW_DISCHARGING;
  return FUEL_FLOW_RESTING;
}

// The icon lags the raw register. One sample of the other sign is not a new
// direction.
static FuelGaugeFlow heldFlow(FuelGaugeFlow want) {
  if (want == s_flow) {
    s_pending_n = 0;
    return s_flow;
  }
  if (want != s_pending) {
    s_pending = want;
    s_pending_n = 1;
    return s_flow;
  }
  if (++s_pending_n < FUEL_FLOW_HOLD_POLLS) return s_flow;
  s_pending_n = 0;
  return want;
}

static void markGone() {
  if (!s_present) return;
  s_present = false;
  s_percent = 0;
  s_flow = FUEL_FLOW_RESTING;
  s_misses = 0;
  s_quick_done = false;
  s_rate_init = false;
  s_rate_avg = 0;
  s_pending = FUEL_FLOW_RESTING;
  s_pending_n = 0;
  s_low_soc_n = 0;
  logSD("Fuel gauge: MAX17048 gone");
}

// A miss is a read that failed or came back as no chip. Three in a row and
// the gauge counts as gone. Returns true when that hid the icon.
static bool countMiss() {
  if (++s_misses < FUEL_MISS_LIMIT) return false;
  const bool was = s_present;
  markGone();
  s_misses = 0;
  return was;
}

struct FuelSample {
  int percent;
  float volts;
  float rate;
};

static int shownPercent(float soc) {
  if (s_present && fabsf(soc - (float)s_percent) < FUEL_PERCENT_HYST) return s_percent;
  int percent = (int)(soc + 0.5f);
  if (percent < 0) percent = 0;
  if (percent > FUEL_PERCENT_MAX) percent = FUEL_PERCENT_MAX;
  return percent;
}

static bool readSample(FuelSample *out) {
  uint16_t vcell_raw = 0;
  uint16_t soc_raw = 0;
  uint16_t rate_raw = 0;
  if (!readReg(FUEL_REG_VCELL, &vcell_raw) ||
      !readReg(FUEL_REG_SOC, &soc_raw) ||
      !readReg(FUEL_REG_CRATE, &rate_raw)) {
    return false;
  }
  // 0xFFFF is what a read returns when the byte never arrived. A real cell
  // does not report 255 percent.
  const float soc = soc_raw / FUEL_SOC_LSB_PER_PCT;
  if (soc > FUEL_SOC_SANE_MAX) return false;

  out->percent = shownPercent(soc);
  out->volts = vcell_raw * FUEL_VCELL_UV / FUEL_UV_PER_V;
  out->rate = (int16_t)rate_raw * FUEL_CRATE_PCT_H;
  return true;
}

static void smoothRate(float rate) {
  if (!s_rate_init) {
    s_rate_avg = rate;
    s_rate_init = true;
  } else {
    s_rate_avg += (rate - s_rate_avg) * FUEL_RATE_SMOOTHING;
  }
}

// The first read after power-up is 0% for about a second, before the chip
// has computed anything. Restarting the model on that sample throws the
// rate around and the icon with it. Only restart if it is still empty
// after a minute on a cell that is not empty. Never while current flows: the
// chip takes the voltage it sees as the resting voltage, and a charger lifts
// it, so a quick-start on a charging flat cell reads far too full for hours.
static void quickStartIfStuck(const FuelSample &s) {
  if (s.percent >= FUEL_STUCK_PERCENT || s.volts < FUEL_STUCK_MIN_V ||
      fabsf(s_rate_avg) >= FUEL_RATE_LEAVE_PCT_H) {
    s_low_soc_n = 0;
    return;
  }
  if (s_quick_done || ++s_low_soc_n < FUEL_STUCK_POLLS) return;
  if (!writeReg(FUEL_REG_MODE, FUEL_MODE_QUICK)) {
    logSD("Fuel gauge: quick-start write failed");
    s_low_soc_n = 0;
    return;
  }
  s_quick_done = true;
  s_rate_init = false;
  logSDf("Fuel gauge: quick-start at %.2f V (SOC stayed %d%%)",
         s.volts, s.percent);
}

bool fuelGaugePoll(bool force) {
  const uint32_t now = millis();
  const uint32_t gap = s_present ? FUEL_POLL_PRESENT_MS : FUEL_POLL_ABSENT_MS;
  if (!force && s_last_ms != 0 && (uint32_t)(now - s_last_ms) < gap) return false;
  s_last_ms = now;

  // An address probe only while it is missing. Once it has answered, the
  // register read is the probe: three misses and the icon goes away.
  if (!s_present && !i2cPresent(I2C_EXT, I2C_ADDR_MAX17048)) return false;

  FuelSample sample;
  if (!readSample(&sample)) return countMiss();
  s_misses = 0;

  smoothRate(sample.rate);
  quickStartIfStuck(sample);
  const FuelGaugeFlow flow = heldFlow(classify(s_rate_avg, sample.percent));

  const bool changed = !s_present || sample.percent != s_percent || flow != s_flow;
  if (changed) {
    static const char *const kFlow[] = { "resting", "charging", "discharging", "full" };
    logSDf("Fuel gauge: %.2f V, %d%%, rate %+.1f avg %+.1f %%/h, %s",
           sample.volts, sample.percent, sample.rate, s_rate_avg, kFlow[flow]);
  }
  s_present = true;
  s_percent = sample.percent;
  s_flow = flow;
  return changed;
}
