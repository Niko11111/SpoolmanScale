#include "scale_state.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <cstring>

#include "app_config.h"
#include "services/prefs_store.h"
#include "services/user_options.h"


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
