#include "fuel_gauge.h"

#include <Arduino.h>
#include <Wire.h>
#include <math.h>

#include "app/app_state.h"
#include "hardware/i2c_scan.h"
#include "hardware/sd_logger.h"
#include "services/prefs_store.h"

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
#define FUEL_REG_HIBRT  0x0A
#define FUEL_MODE_QUICK 0x4000
// HIBRT 0 keeps the chip out of hibernation. Its default (0x8030) hibernates
// after six minutes below about 27 %/h, and a hibernating chip reports a rate
// of 0, so a cell charging at +13 %/h read as resting.
#define FUEL_HIBRT_OFF  0x0000
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

// Plugging the charger in or pulling it lifts or drops the cell voltage by
// 50 mV or more at once: the charge current flows through the cell's own
// resistance. Between two polls the voltage otherwise drifts by about a
// millivolt, and a backlight step moves it 20 to 30 mV, so a step this big
// is a plug event. The plug state it sets is kept until the next one: near
// full, CRATE reads a few %/h negative while the charger is still pushing
// current in, so the rate cannot be what ends it.
#define FUEL_JUMP_V            0.040f
// Plugged in, a voltage this far below its peak since the plug means the
// supply cannot carry the load and the cell is making up the rest.
#define FUEL_SAG_V             0.050f
// Unplugged, a voltage this far above its low since the unplug is a charger
// whose step was too small to see. More than a dimmed backlight gives back.
#define FUEL_RISE_V            0.060f
// At boot there was no plug event to see. The cell voltage against its
// resting voltage at the reported charge says which way current flows:
// above it while charging, below it under load. Inside this band, or until
// it agrees FUEL_SEED_POLLS times in a row, the rate decides.
#define FUEL_SEED_BAND_V       0.020f
#define FUEL_SEED_POLLS        3
// Plugged in and above FUEL_DONE_MIN_V, a charge that has not gained
// FUEL_TOP_STEP_PCT for FUEL_TOP_WAIT_MS has finished. The rate register
// cannot say so: at the top it wobbles by more than the last of the charge
// adds. The charge itself, at 1/256 %, only stops rising when the charger
// stops.
#define FUEL_DONE_MIN_V        4.10f
#define FUEL_TOP_STEP_PCT      0.05f
#define FUEL_TOP_WAIT_MS       (20UL * 60UL * 1000UL)
// Full is kept until the plug is pulled or the charge has fallen this far.
#define FUEL_FULL_DROP_PCT     2.0f
// A voltage sag only counts as discharging once the charge fell this far
// too: a cell the charger has let go of relaxes by about as many millivolts.
#define FUEL_SAG_PCT           1.0f
// The chip's generic model puts this cell, finished, at about 96 %. The
// reading at a finished charge is kept and shown as 100 %. Outside these
// bounds it is not believed, and flash is written only for a real change.
#define FUEL_LEARN_MIN_PCT     92.0f
#define FUEL_LEARN_MAX_PCT     100.0f
#define FUEL_LEARN_SAVE_PCT    0.5f
// Plugged in and this close to the learned full reading is full at once.
#define FUEL_FULL_NEAR_PCT     1.0f
#define FUEL_PREF_FULL         "fuel_full"
// A charger in its constant-voltage phase holds the cell here. With the rate
// down to a trickle that is a full cell, whatever the percent says yet.
#define FUEL_FULL_V            4.17f

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
enum FuelPlug { PLUG_UNKNOWN, PLUG_IN, PLUG_OUT };
static float s_prev_volts = 0;
static FuelPlug s_plug = PLUG_UNKNOWN;
// Highest voltage since plugging in, lowest since unplugging.
static float s_plug_ref_v = 0;
static FuelPlug s_seed_want = PLUG_UNKNOWN;
static uint8_t s_seed_n = 0;
// Since plugging in: the highest charge, and the charge and time of the last
// gain the finished-charge rule saw. Negative is "nothing yet".
static float s_peak_soc = -1;
static float s_top_soc = -1;
static uint32_t s_top_ms = 0;
static bool s_top_done = false;
static bool s_full = false;
// The chip's reading for a finished charge; 100 until one has been seen.
static float s_full_soc = FUEL_LEARN_MAX_PCT;
static bool s_full_loaded = false;

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

// raw is this sample. avg is the smoothed rate, which lags a discharge by
// several polls, so it is not what decides that charging has started.
static FuelGaugeFlow classify(float raw, float avg, int percent, float volts) {
  const bool topped = percent >= FUEL_FULL_PERCENT ||
                      (volts >= FUEL_FULL_V && avg > -FUEL_RATE_LEAVE_PCT_H);

  if (raw >= FUEL_RATE_ENTER_PCT_H) {
    if (topped && raw < FUEL_TRICKLE_PCT_H) return FUEL_FLOW_FULL;
    return FUEL_FLOW_CHARGING;
  }
  if (s_flow == FUEL_FLOW_CHARGING && avg > 0) return FUEL_FLOW_CHARGING;

  const float discharge_at = (s_flow == FUEL_FLOW_DISCHARGING)
                               ? -FUEL_RATE_LEAVE_PCT_H : -FUEL_RATE_ENTER_PCT_H;
  if (avg <= discharge_at) return FUEL_FLOW_DISCHARGING;
  if (topped) return FUEL_FLOW_FULL;
  if (s_flow == FUEL_FLOW_DISCHARGING && avg < 0) return FUEL_FLOW_DISCHARGING;
  return FUEL_FLOW_RESTING;
}

// Charging shows on the sample that crossed the line. Leaving it, or any
// other change, waits, so one noisy sample does not clear the bolt.
static FuelGaugeFlow heldFlow(FuelGaugeFlow want) {
  if (want == FUEL_FLOW_CHARGING || want == s_flow) {
    s_pending_n = 0;
    return want;
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
  s_prev_volts = 0;
  s_plug = PLUG_UNKNOWN;
  s_seed_want = PLUG_UNKNOWN;
  s_seed_n = 0;
  s_peak_soc = -1;
  s_top_soc = -1;
  s_top_done = false;
  s_full = false;
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

// percent is what the header shows. soc is the chip's own reading, which is
// what every rule in here compares against.
struct FuelSample {
  int percent;
  float soc;
  float volts;
  float rate;
};

static int shownPercent(float raw) {
  const float soc = raw * FUEL_PERCENT_MAX / s_full_soc;
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
  out->soc = soc;
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
  if (s.soc >= FUEL_STUCK_PERCENT || s.volts < FUEL_STUCK_MIN_V ||
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

static void setPlug(FuelPlug plug, float volts, const char *why) {
  s_plug = plug;
  s_plug_ref_v = volts;
  s_peak_soc = -1;
  s_top_soc = -1;
  s_top_done = false;
  s_full = false;
  // The average still holds the old direction; start it from this sample.
  s_rate_init = false;
  logSDf("Fuel gauge: charger %s (%s)", plug == PLUG_IN ? "connected" : "removed", why);
}

// Typical LiPo resting voltage per 10 %, 0 to 100.
static const float kOcv[] = { 3.50f, 3.68f, 3.73f, 3.77f, 3.80f, 3.84f,
                              3.88f, 3.94f, 4.00f, 4.07f, 4.18f };
#define FUEL_OCV_STEP_PCT 10

static float restingVolts(float soc) {
  if (soc <= 0) return kOcv[0];
  if (soc >= FUEL_PERCENT_MAX) return kOcv[FUEL_PERCENT_MAX / FUEL_OCV_STEP_PCT];
  const int i = (int)(soc / FUEL_OCV_STEP_PCT);
  const float t = (soc - i * FUEL_OCV_STEP_PCT) / FUEL_OCV_STEP_PCT;
  return kOcv[i] + (kOcv[i + 1] - kOcv[i]) * t;
}

static void seedPlug(const FuelSample &s) {
  const float off = s.volts - restingVolts(s.soc);
  const FuelPlug want = off >= FUEL_SEED_BAND_V ? PLUG_IN
                      : off <= -FUEL_SEED_BAND_V ? PLUG_OUT : PLUG_UNKNOWN;
  if (want != s_seed_want) {
    s_seed_want = want;
    s_seed_n = 0;
  }
  if (want == PLUG_UNKNOWN || ++s_seed_n < FUEL_SEED_POLLS) return;
  setPlug(want, s.volts, off > 0 ? "above resting voltage" : "below resting voltage");
}

// Follows the plug from the voltage: a step either way, a slow rise while
// unplugged, or the boot-time estimate while nothing has been seen yet.
static void trackPlug(const FuelSample &s) {
  const float dv = (s_prev_volts > 0) ? s.volts - s_prev_volts : 0;
  s_prev_volts = s.volts;
  if (dv >= FUEL_JUMP_V && s_plug != PLUG_IN) { setPlug(PLUG_IN, s.volts, "voltage step"); return; }
  if (dv <= -FUEL_JUMP_V && s_plug != PLUG_OUT) { setPlug(PLUG_OUT, s.volts, "voltage step"); return; }
  if (s_plug == PLUG_IN) {
    if (s.volts > s_plug_ref_v) s_plug_ref_v = s.volts;
  } else if (s_plug == PLUG_OUT) {
    if (s.volts < s_plug_ref_v) s_plug_ref_v = s.volts;
    if (s.volts >= s_plug_ref_v + FUEL_RISE_V) setPlug(PLUG_IN, s.volts, "voltage rising");
  } else {
    seedPlug(s);
  }
}

static void learnFull(float soc) {
  if (soc < FUEL_LEARN_MIN_PCT || soc > FUEL_LEARN_MAX_PCT) {
    logSDf("Fuel gauge: charge finished at %.1f%%, not kept as the full point", soc);
    return;
  }
  if (fabsf(soc - s_full_soc) < FUEL_LEARN_SAVE_PCT) return;
  logSDf("Fuel gauge: full point %.1f%% -> %.1f%%", s_full_soc, soc);
  s_full_soc = soc;
  prefsPutFloat(FUEL_PREF_FULL, soc);
}

static void restartTop(const FuelSample &s, uint32_t now) {
  s_top_soc = s.soc;
  s_top_ms = now;
  s_top_done = false;
}

// Watches for the charge to stop rising. A later gain starts the wait again,
// so a charge that ends higher than last time is learned as well.
static void trackTop(const FuelSample &s, uint32_t now) {
  if (s_top_soc < 0 || s.volts < FUEL_DONE_MIN_V ||
      s.soc >= s_top_soc + FUEL_TOP_STEP_PCT) {
    restartTop(s, now);
    return;
  }
  if (s_top_done || (uint32_t)(now - s_top_ms) < FUEL_TOP_WAIT_MS) return;
  s_top_done = true;
  s_full = true;
  learnFull(s_top_soc);
}

static FuelGaugeFlow pluggedFlow(const FuelSample &s, uint32_t now) {
  if (s.soc > s_peak_soc) s_peak_soc = s.soc;
  trackTop(s, now);
  if (s_full && s.soc <= s_peak_soc - FUEL_FULL_DROP_PCT) {
    // The charger takes over again from here; measure from this point.
    s_full = false;
    s_peak_soc = s.soc;
    s_plug_ref_v = s.volts;
    restartTop(s, now);
  }
  const bool learned = s_full_soc < FUEL_LEARN_MAX_PCT;
  if (s.soc >= FUEL_FULL_PERCENT ||
      (learned && s.soc >= s_full_soc - FUEL_FULL_NEAR_PCT)) {
    s_full = true;
  }
  if (s_full) return FUEL_FLOW_FULL;
  if (s.volts <= s_plug_ref_v - FUEL_SAG_V && s.soc <= s_peak_soc - FUEL_SAG_PCT) {
    return FUEL_FLOW_DISCHARGING;
  }
  return FUEL_FLOW_CHARGING;
}

static FuelGaugeFlow nextFlow(const FuelSample &s, uint32_t now) {
  trackPlug(s);
  smoothRate(s.rate);
  if (s_plug == PLUG_OUT) return FUEL_FLOW_DISCHARGING;
  if (s_plug == PLUG_IN) return pluggedFlow(s, now);
  return heldFlow(classify(s.rate, s_rate_avg, (int)(s.soc + 0.5f), s.volts));
}

// Checked every poll rather than once: a chip that loses its cell resets to
// the default and would hibernate again without the ESP noticing.
static void keepAwake() {
  uint16_t hibrt = 0;
  if (!readReg(FUEL_REG_HIBRT, &hibrt) || hibrt == FUEL_HIBRT_OFF) return;
  if (writeReg(FUEL_REG_HIBRT, FUEL_HIBRT_OFF)) {
    logSDf("Fuel gauge: hibernation off (HIBRT was 0x%04X)", hibrt);
  } else {
    logSD("Fuel gauge: HIBRT write failed");
  }
}

bool fuelGaugePoll(bool force) {
  const uint32_t now = millis();
  const uint32_t gap = s_present ? FUEL_POLL_PRESENT_MS : FUEL_POLL_ABSENT_MS;
  if (!force && s_last_ms != 0 && (uint32_t)(now - s_last_ms) < gap) return false;
  s_last_ms = now;

  // An address probe only while it is missing. Once it has answered, the
  // register read is the probe: three misses and the icon goes away.
  if (!s_present && !i2cPresent(I2C_EXT, I2C_ADDR_MAX17048)) return false;

  if (!s_full_loaded) {
    s_full_loaded = true;
    const float full = prefsGetFloat(FUEL_PREF_FULL, FUEL_LEARN_MAX_PCT);
    if (full >= FUEL_LEARN_MIN_PCT && full <= FUEL_LEARN_MAX_PCT) s_full_soc = full;
  }

  FuelSample sample;
  if (!readSample(&sample)) return countMiss();
  s_misses = 0;
  keepAwake();

  const FuelGaugeFlow flow = nextFlow(sample, now);
  quickStartIfStuck(sample);

  const bool changed = !s_present || sample.percent != s_percent || flow != s_flow;
  // The state goes to the log at every level; each percent step only at
  // verbose, where a full discharge is about a hundred lines.
  const bool state_changed = !s_present || flow != s_flow;
  if (state_changed || (changed && sd_verbose)) {
    static const char *const kFlow[] = { "resting", "charging", "discharging", "full" };
    logSDf("%sFuel gauge: %.2f V, %d%% (chip %.1f%%), rate %+.1f avg %+.1f %%/h, %s",
           state_changed ? "" : "[verbose] ",
           sample.volts, sample.percent, sample.soc, sample.rate, s_rate_avg, kFlow[flow]);
  }
  s_present = true;
  s_percent = sample.percent;
  s_flow = flow;
  return changed;
}
