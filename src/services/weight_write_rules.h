#pragma once

#include <stdint.h>

#include "server_refusal_rules.h"

// ============================================================
//  WHAT A FAILED WEIGHT WRITE TELLS THE USER
//
//  The popup is gone by the time the answer arrives, so a failure nobody
//  reports looks exactly like a weight that was saved.
// ============================================================

enum WeightWriteProblem : uint8_t {
  WEIGHT_WRITE_FINE,          // saved, or already explained by another popup
  WEIGHT_WRITE_NO_TARE,       // the server will not guess a missing empty weight
  WEIGHT_WRITE_NOT_SAVED      // anything else: the weight did not arrive
};

// `spoolman` is the Spoolman API, where a 409 on a measure means the empty
// spool weight is missing (spec 6.1). Elsewhere it says nothing of the kind.
inline WeightWriteProblem weightWriteProblemOf(int code, bool spoolman) {
  if (code >= 200 && code < 300) return WEIGHT_WRITE_FINE;
  // Said by the refusal popup already (server_refusal.h).
  if (serverRefusalOf(code) != REFUSAL_NONE) return WEIGHT_WRITE_FINE;
  if (code == 409 && spoolman) return WEIGHT_WRITE_NO_TARE;
  return WEIGHT_WRITE_NOT_SAVED;
}
