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
  zero_offset = offset;
  prefsPutInt("zero_offset", offset);
  Serial.printf("zero_offset saved: %d\n", offset);
}

void resetScaleFilter() {
  memset(scale_filter_buf, 0, sizeof(scale_filter_buf));
  scale_filter_idx = 0;
  scale_filter_full = false;
}

void scaleAutoTareTick(bool allowed) {
  static unsigned long band_since_ms = 0;
  static unsigned long last_tare_ms  = 0;

  const float w = scale_weight_g;
  bool candidate = g_auto_tare && allowed && scale_ready && scale_filter_full &&
                   fabsf(cal_factor) >= CAL_FACTOR_MIN &&
                   fabsf(w) >= AUTO_TARE_DEADZONE_G && fabsf(w) <= AUTO_TARE_BAND_G;
  if (candidate) {
    float lo = scale_filter_buf[0], hi = scale_filter_buf[0];
    for (int i = 1; i < SCALE_FILTER_SIZE; i++) {
      if (scale_filter_buf[i] < lo) lo = scale_filter_buf[i];
      if (scale_filter_buf[i] > hi) hi = scale_filter_buf[i];
    }
    candidate = (hi - lo) <= AUTO_TARE_SPREAD_G;
  }
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
  Serial.printf("Auto-tare: removed %.2f g of drift\n", w);
  logSDf("Auto-tare: removed %.2f g of drift", w);
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
