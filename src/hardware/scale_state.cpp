#include "scale_state.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <cstring>

#include "app_config.h"
#include "services/prefs_store.h"
#include "services/user_options.h"
#include "services/auto_weight_state.h"
#include "hardware/sd_logger.h"
#include <math.h>


void saveCalFactor(float factor) {
  cal_factor = factor;
  prefsPutFloat("cal_factor", factor);
  Serial.printf("cal_factor saved: %.4f\n", factor);
}

void saveBagWeight(float weight) {
  bag_weight_g = weight;
  prefsPutFloat("bag_weight", weight);
  Serial.printf("bag_weight saved: %.1fg\n", weight);
}

void saveTareOffset(int32_t offset) {
  // A new zero is the user's "nothing on the pad": an empty spool taken off
  // on top of the old one would be counted twice.
  g_spool_offset_g = 0.0f;
  zero_offset = offset;
  prefsPutInt("zero_offset", offset);
  Serial.printf("zero_offset saved: %d\n", offset);
}

void resetScaleFilter() {
  memset(scale_filter_buf, 0, sizeof(scale_filter_buf));
  scale_filter_idx = 0;
  scale_filter_full = false;
}

void scaleAutoTareTick(bool allowed, float spread_g) {
  static unsigned long band_since_ms = 0;
  static unsigned long last_tare_ms  = 0;
  static uint16_t      tare_count    = 0;
  static float         tare_sum_g    = 0.0f;

  const float w = scale_weight_g;
  const bool candidate = g_auto_tare && allowed && scale_ready && scale_filter_full &&
                         fabsf(cal_factor) >= CAL_FACTOR_MIN &&
                         fabsf(w) >= AUTO_TARE_DEADZONE_G && fabsf(w) <= AUTO_TARE_BAND_G &&
                         spread_g <= AUTO_TARE_SPREAD_G;
  if (!candidate) { band_since_ms = 0; return; }

  const unsigned long now = millis();
  if (band_since_ms == 0) { band_since_ms = now; return; }
  if (now - band_since_ms < AUTO_TARE_STABLE_MS) return;
  if (last_tare_ms != 0 && now - last_tare_ms < AUTO_TARE_COOLDOWN_MS) return;

  // The window average is the offset in grams, so the new zero is the old one
  // moved by that many counts. Averaged, unlike the button, which takes one
  // raw sample.
  const int32_t delta = (int32_t)lroundf(w * cal_factor);
  saveTareOffset(zero_offset + delta);
  scale_weight_g = 0.0f;
  resetScaleFilter();
  last_tare_ms  = now;
  band_since_ms = 0;
  // The log is the only place that shows how much a cell drifts and how often
  // this has to step in: each move with its sign, the sum since boot and the
  // uptime it took. A sum that grows by grams an hour points at the hardware.
  tare_count++;
  tare_sum_g += w;
  const unsigned long up_min = now / 60000UL;
  Serial.printf("Auto-tare #%u: zero moved by %+.2f g (%+.2f g in %lu min since boot)\n",
                tare_count, w, tare_sum_g, up_min);
  logSDf("Auto-tare #%u: zero moved by %+.2f g (%+.2f g in %lu min since boot)",
         tare_count, w, tare_sum_g, up_min);
}


void setScaleFitted(bool fitted) {
  g_scale_fitted = fitted;
  prefsPutBool("scale_fitted", fitted);
  Serial.printf("scale_fitted saved: %s\n", fitted ? "yes" : "no");

  // Only the way down needs doing. Coming back up is the restart's job: the
  // ADC has to be probed and calibrated, and that belongs in app_boot.cpp.
  if (!fitted) {
    scale_ready    = false;
    scl_ok         = false;
    scale_weight_g = 0.0f;
    resetScaleFilter();
  }
}
