#include "services/spool_tare.h"

#include "services/tare_chain.h"

// A level holds a value when the server sent a number. Null or absent, the
// next level answers.
static const float* levelValue(JsonVariantConst level, float* grams) {
  if (!level.is<float>()) return nullptr;
  *grams = level.as<float>();
  return grams;
}

float spoolTare(JsonVariantConst spool, uint8_t* source) {
  float spool_g = 0.0f, filament_g = 0.0f, vendor_g = 0.0f;
  JsonVariantConst filament = spool["filament"];
  return tareFromChain(levelValue(spool["spool_weight"], &spool_g),
                       levelValue(filament["spool_weight"], &filament_g),
                       levelValue(filament["vendor"]["empty_spool_weight"], &vendor_g),
                       source);
}
