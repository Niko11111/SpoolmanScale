#include "ams_weights.h"

#include <Arduino.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "services/backend_api.h"
#include "services/dried_batch.h"
#include "services/spool_detail.h"

// The numbers the other workers run with, and for the same reasons.
#define AMS_WEIGHTS_STACK_BYTES  16384
#define AMS_WEIGHTS_PRIORITY     1
#define AMS_WEIGHTS_CORE         0
#define AMS_WEIGHTS_MIN_HEAP     60000
// Per request. Shorter than a write: nothing is lost when this gives up, the
// grid simply keeps the percentage it already shows.
#define AMS_WEIGHTS_TIMEOUT_MS   5000

static volatile AmsWeightsState s_state = AWS_IDLE;
static AmsWeightsResult         s_res;
// The bays to ask about, filled before the task starts.
static AmsSlotSpool             s_bay[AMS_WEIGHTS_MAX];
static uint8_t                  s_bay_count = 0;

static void amsWeightsTask(void* arg) {
  (void)arg;
  // One request for the whole printer: which spool sits in which bay.
  AmsSlotSpool assigned[AMS_WEIGHTS_MAX];
  uint8_t assigned_count = 0;
  const int code = backendFindPrinterSpools(s_res.printer_id, assigned,
                                            AMS_WEIGHTS_MAX, &assigned_count,
                                            AMS_WEIGHTS_TIMEOUT_MS);
  if (code != 200) {
    logSDf("AMSWEIGHTS: assignments of printer %d not read, HTTP %d",
           s_res.printer_id, code);
    __sync_synchronize();
    s_state = AWS_DONE;
    vTaskDelete(NULL);
    return;
  }

  // Then the record behind each bay. Only the bays the view asked about, so
  // a spool assigned to an empty bay costs nothing.
  for (uint8_t i = 0; i < s_bay_count; i++) {
    int spool_id = 0;
    int16_t grams = AMS_REMAIN_NA;
    for (uint8_t a = 0; a < assigned_count; a++) {
      if (assigned[a].ams_id != s_bay[i].ams_id) continue;
      if (assigned[a].tray_id != s_bay[i].tray_id) continue;
      spool_id = assigned[a].spool_id;
      grams    = assigned[a].grams;
      break;
    }
    if (spool_id <= 0) continue;

    // Only where the list did not bring the weight along: that is the mode
    // that keeps the inventory on a Spoolman server, where an assignment is
    // an id and nothing more.
    if (grams < 0) {
      AmsSpoolDetail det{};
      det.remaining_g = SD_WEIGHT_NA;
      det.total_g     = SD_WEIGHT_NA;
      const int detail_code = backendGetSpoolDetail(spool_id, det, AMS_WEIGHTS_TIMEOUT_MS);
      if (detail_code == 200 && det.found && det.remaining_g >= 0.0f) {
        // Held as grams, like the AMS answer's own figure. A spool heavier
        // than the field can hold is left unknown rather than wrapped.
        const long g = lroundf(det.remaining_g);
        if (g >= 0 && g <= INT16_MAX) grams = (int16_t)g;
      }
    }

    AmsWeightItem& out = s_res.item[s_res.count];
    out.ams_id  = s_bay[i].ams_id;
    out.tray_id = s_bay[i].tray_id;
    out.grams   = grams;
    if (grams >= 0) s_res.found++;
    s_res.count++;
  }

  logSDf("AMSWEIGHTS: printer %d, %u of %u bay(s) weighed, stack left %u",
         s_res.printer_id, (unsigned)s_res.found, (unsigned)s_res.count,
         (unsigned)uxTaskGetStackHighWaterMark(NULL));
  // Written before the state says so, read the other way round by the loop.
  __sync_synchronize();
  s_state = AWS_DONE;
  vTaskDelete(NULL);
}

bool amsWeightsStart(int printer_id, const AmsSlotState& st) {
  if (s_state != AWS_IDLE || printer_id <= 0 || !st.valid) return false;
  // One HTTP worker at a time: a second task is another 16 kB of stack, and
  // the drying batch is the one the user is waiting for.
  if (driedBatchBusy()) return false;
  if (!backendCanAssignAmsSlot()) return false;   // BamBuddy names bays, others do not

  s_bay_count = 0;
  for (uint8_t u = 0; u < st.unit_count && s_bay_count < AMS_WEIGHTS_MAX; u++) {
    const AmsSlotUnit& unit = st.unit[u];
    for (uint8_t t = 0; t < unit.tray_count && s_bay_count < AMS_WEIGHTS_MAX; t++) {
      const AmsSlotTray& tray = unit.tray[t];
      // Only bays with filament in them, and only where the answer left the
      // grams out. A backend that names them needs none of this.
      if (!tray.exists || tray.remain_g > 0) continue;
      s_bay[s_bay_count].ams_id   = unit.ams_id;
      s_bay[s_bay_count].tray_id  = tray.tray_id;
      s_bay[s_bay_count].spool_id = tray.spool_id;
      s_bay_count++;
    }
  }
  if (s_bay_count == 0) return false;

  if (ESP.getFreeHeap() < AMS_WEIGHTS_MIN_HEAP) {
    logSDf("AMSWEIGHTS: not started, heap %u", (unsigned)ESP.getFreeHeap());
    return false;
  }

  s_res = AmsWeightsResult{};
  s_res.printer_id = printer_id;

  s_state = AWS_RUNNING;
  BaseType_t ok = xTaskCreatePinnedToCore(amsWeightsTask, "amsweights",
                                          AMS_WEIGHTS_STACK_BYTES, nullptr,
                                          AMS_WEIGHTS_PRIORITY, nullptr,
                                          AMS_WEIGHTS_CORE);
  if (ok != pdPASS) {
    s_state = AWS_IDLE;
    logSD("AMSWEIGHTS: task creation failed");
    return false;
  }
  return true;
}

AmsWeightsState amsWeightsState() { return s_state; }

bool amsWeightsBusy() { return s_state != AWS_IDLE; }

const AmsWeightsResult& amsWeightsResult() { return s_res; }

void amsWeightsTake() {
  if (s_state != AWS_DONE) return;
  s_state = AWS_IDLE;
}
