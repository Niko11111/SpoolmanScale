#include "services/spool_tare.h"

#include "app/app_state.h"   // TareSource

float spoolTare(JsonVariantConst spool, uint8_t* source) {
  uint8_t from = TARE_NONE;
  float w = spool["spool_weight"] | 0.0f;
  if (w > 0) {
    from = TARE_SPOOL;
  } else if ((w = spool["filament"]["spool_weight"] | 0.0f) > 0) {
    from = TARE_FILAMENT;
  } else if ((w = spool["filament"]["vendor"]["empty_spool_weight"] | 0.0f) > 0) {
    from = TARE_VENDOR;
  } else {
    w = 0.0f;
  }
  if (source) *source = from;
  return w;
}
