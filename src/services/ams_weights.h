#pragma once

#include <stdint.h>

#include "services/ams_slots.h"

// ============================================================
//  AMS WEIGHTS
//
//  What a bay really holds, in grams, for the backends whose AMS
//  answer does not say.
//
//  FilaMan names the remaining grams per bay in the same answer
//  the grid is drawn from. BamBuddy does not: its printer status
//  carries the printer's own estimate in percent, while the real
//  figure - the one the scale itself weighed - sits in the
//  inventory behind it, one record per spool.
//
//  Fetching that while the view opens would put an assignment
//  request plus one request per bay in front of the first frame.
//  So the grid draws with what the printer said and this fills the
//  grams in afterwards, on a task of its own: same shape as the
//  drying batch, core 0, below the loop, one at a time. The loop
//  takes the result and redraws.
// ============================================================

// Four units of four bays plus the external holder.
#define AMS_WEIGHTS_MAX  (AMS_MAX_UNITS * AMS_MAX_TRAYS + AMS_MAX_EXT)

enum AmsWeightsState : uint8_t {
  AWS_IDLE = 0,
  AWS_RUNNING,
  AWS_DONE
};

struct AmsWeightItem {
  int16_t grams;     // AMS_REMAIN_NA when the record has none
  uint8_t ams_id;
  uint8_t tray_id;
};

struct AmsWeightsResult {
  AmsWeightItem item[AMS_WEIGHTS_MAX];
  int           printer_id;
  uint8_t       count;    // bays answered
  uint8_t       found;    // of those, with a weight on file
};

// Starts a fetch for every bay of st that holds filament without a weight.
// False when nothing is missing, when a fetch is still running or uncollected,
// when the backend cannot resolve bays, or when the heap is too low.
bool amsWeightsStart(int printer_id, const AmsSlotState& st);

AmsWeightsState amsWeightsState();
bool            amsWeightsBusy();

// Valid while the state is AWS_DONE.
const AmsWeightsResult& amsWeightsResult();

// Hands the slot back. Only from AWS_DONE.
void amsWeightsTake();
