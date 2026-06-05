#include "scale_state.h"

#include <Arduino.h>
#include <cstring>

#include "app_config.h"
#include "services/prefs_store.h"

extern float cal_factor;
extern int32_t zero_offset;
extern float bag_weight_g;
extern float scale_filter_buf[SCALE_FILTER_SIZE];
extern int scale_filter_idx;
extern bool scale_filter_full;

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
