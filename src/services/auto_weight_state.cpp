#include "auto_weight_state.h"

bool g_auto_weight = false;
bool g_auto_loc_popup = false;
bool g_auto_tare = AUTO_TARE_DEFAULT;
float auto_weight_last_val = -9999.0f;
unsigned long auto_weight_stable_ms = 0;
bool auto_weight_done = false;

bool autoWeightPadTooLight(float grams) {
  return grams < AUTO_WEIGHT_EMPTY_PAD_G;
}
