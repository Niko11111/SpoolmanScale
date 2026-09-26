#include "tag_probe_job.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "app/backend_switch.h"
#include "hardware/sd_logger.h"
#include "ui/spoolman_lookup.h"

// The web jobs' stack, not the backend job's smaller one: a backend behind
// https does its TLS handshake on this task. Priority, core and heap floor as
// in both, for the same reasons.
#define TAG_PROBE_STACK_BYTES   16384
#define TAG_PROBE_PRIORITY      1
#define TAG_PROBE_CORE          0
#define TAG_PROBE_MIN_HEAP      60000

static volatile TagProbeState s_state = TPS_IDLE;
static TagProbeResult         s_res;
// The address as it was when the probe started. A host change on the loop
// rewrites cfg_spoolman_base, and this task must not read it half written; the
// generation then drops whatever came back.
static char                   s_base[sizeof(cfg_spoolman_base)] = "";

static void tagProbeTask(void* arg) {
  (void)arg;
  const uint32_t t0 = millis();
  s_res.hit = spoolmanTagResolvesAt(s_base, s_res.query, &s_res.unanswered, &s_res.spool_id);
  s_res.ms = millis() - t0;
  // Everything above is written before the state says so: the loop on the
  // other core reads the state first and the result after.
  __sync_synchronize();
  s_state = TPS_DONE;
  vTaskDelete(NULL);
}

bool tagProbeStart(const char* query) {
  if (s_state != TPS_IDLE || !query || !query[0]) return false;
  // Checked here rather than inside the task: the stack comes out of the
  // heap the moment the task is created.
  if (ESP.getFreeHeap() < TAG_PROBE_MIN_HEAP) {
    logSDf("Recheck: postponed, heap %u", (unsigned)ESP.getFreeHeap());
    return false;
  }
  s_res.hit        = false;
  s_res.unanswered = false;
  s_res.spool_id   = 0;
  s_res.gen        = backendGeneration();
  s_res.ms         = 0;
  snprintf(s_res.query, sizeof(s_res.query), "%s", query);
  snprintf(s_base, sizeof(s_base), "%s", cfg_spoolman_base);

  // Set before the task exists: if creation fails it is cleared again below,
  // and if it succeeds the task may finish before this line would run - on
  // the simulator it always does.
  s_state = TPS_RUNNING;
  BaseType_t ok = xTaskCreatePinnedToCore(tagProbeTask, "tagprobe",
                                          TAG_PROBE_STACK_BYTES, nullptr,
                                          TAG_PROBE_PRIORITY, nullptr,
                                          TAG_PROBE_CORE);
  if (ok != pdPASS) {
    s_state = TPS_IDLE;
    logSD("Recheck: task creation failed");
    return false;
  }
  return true;
}

TagProbeState tagProbeState() { return s_state; }

const TagProbeResult& tagProbeResult() { return s_res; }

void tagProbeTake() {
  if (s_state == TPS_DONE) s_state = TPS_IDLE;
}
