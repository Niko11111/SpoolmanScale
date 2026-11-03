#include "services/tare_chain.h"

static bool holdsValue(const float* grams) { return grams && *grams >= 0.0f; }

float tareFromChain(const float* spool_g, const float* filament_g, const float* vendor_g,
                    uint8_t* source) {
  uint8_t from = TARE_NONE;
  float w = 0.0f;
  if (holdsValue(spool_g)) {
    from = TARE_SPOOL;
    w = *spool_g;
  } else if (holdsValue(filament_g)) {
    from = TARE_FILAMENT;
    w = *filament_g;
  } else if (holdsValue(vendor_g)) {
    from = TARE_VENDOR;
    w = *vendor_g;
  }
  if (source) *source = from;
  return w;
}

bool tareMeasureAgrees(uint8_t source, float tare_g) {
  if (source == TARE_NONE) return true;
  return source != TARE_VENDOR && tare_g > 0.0f;
}
