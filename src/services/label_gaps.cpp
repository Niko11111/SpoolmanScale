#include "services/label_gaps.h"

#include "services/label_layout.h"

static uint32_t bit(LabelField f) { return 1u << f; }

static bool none(const char* s) { return !s || !s[0]; }

// The date the layout would print: the added one alone, or either.
static bool dateMissing(const SpoolLabelData& s, uint32_t options) {
  if (options & (1u << LO_DATE_ADDED)) return none(s.added);
  return none(s.first_used) && none(s.added);
}

uint32_t labelEmptyFields(const SpoolLabelData& s, uint32_t options) {
  uint32_t m = 0;
  if (none(s.vendor))   m |= bit(LF_VENDOR);
  if (none(s.material)) m |= bit(LF_MATERIAL);
  if (none(s.name))     m |= bit(LF_NAME);
  if (none(s.color) && (none(s.color_name) || !(options & (1u << LO_COLOR_NAME))))
    m |= bit(LF_COLOR);
  if (none(s.article))  m |= bit(LF_ARTICLE);
  if (dateMissing(s, options)) m |= bit(LF_DATE);
  if (s.spool_weight_g <= 0) m |= bit(LF_SPOOL_WEIGHT);
  if (s.net_weight_g <= 0)   m |= bit(LF_NET_WEIGHT);
  if (s.nozzle_max <= 0)     m |= bit(LF_TEMPS);
  if (none(s.location)) m |= bit(LF_LOCATION);
  if (none(s.dried))    m |= bit(LF_DRIED);
  if (s.dry_temp_c <= 0 || s.dry_hours <= 0) m |= bit(LF_DRYING);
  return m;
}

bool labelBackendHasColorName(BackendMode mode) {
  return mode == BACKEND_BAMBUDDY || mode == BACKEND_FILAMAN;
}

uint32_t labelBackendLacks(BackendMode mode) {
  // FilaMan's filament has no print temperatures the scale reads.
  if (mode == BACKEND_FILAMAN) return bit(LF_TEMPS);
  return 0;
}
