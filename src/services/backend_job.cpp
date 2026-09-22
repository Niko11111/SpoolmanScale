#include "backend_job.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "app/backend_switch.h"
#include "hardware/sd_logger.h"
#include "services/backend_api.h"
#include "services/http_progress.h"
#include "web/web_jobs.h"

// The numbers the web jobs run with, for the same reasons: the task sits
// below the loop so the display keeps its share, it lives on the other core,
// and the heap floor is checked before the stack is taken from it.
#define BACKEND_JOB_STACK_BYTES   16384
#define BACKEND_JOB_PRIORITY      1
#define BACKEND_JOB_CORE          0
#define BACKEND_JOB_MIN_HEAP      60000

// The same allocator the lookup path uses: the inventory goes into PSRAM,
// not into the 320 kB the rest of the firmware shares. Static, because the
// document outlives every function that touches it.
struct SpiRamAllocator : ArduinoJson::Allocator {
  void* allocate(size_t n) override {
    void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM);
    if (!p) p = malloc(n);
    return p;
  }
  void  deallocate(void* p) override { heap_caps_free(p); }
  void* reallocate(void* p, size_t n) override {
    void* q = heap_caps_realloc(p, n, MALLOC_CAP_SPIRAM);
    if (!q) q = realloc(p, n);
    return q;
  }
};

static SpiRamAllocator            s_alloc;
static JsonDocument               s_doc(&s_alloc);
static JsonDocument               s_filter;
static bool                       s_has_filter = false;
static volatile BackendJobState   s_state = BJS_IDLE;
static volatile size_t            s_bytes = 0;
static BackendListResult          s_res;
static uint32_t                   s_timeout_ms = 0;
static uint32_t                   s_retry_pause_ms = 0;
// The address as it was when the job started. A host change on the loop
// rewrites cfg_spoolman_base, and this task must not read it half written; the
// generation then drops whatever came back.
static char                       s_base[sizeof(cfg_spoolman_base)] = "";

static bool transientParseError(const DeserializationError& e) {
  return e == DeserializationError::IncompleteInput ||
         e == DeserializationError::EmptyInput;
}

// The retry rules of the lookup, carried over as they were: another try after
// an HTTP error or a stream that broke off, none after a parse error that
// would only repeat itself.
static void runList() {
  const uint32_t t0 = millis();
  JsonDocument* filter = s_has_filter ? &s_filter : nullptr;
  for (uint8_t attempt = 1; attempt <= s_res.attempts; attempt++) {
    if (attempt > 1) {
      logSDf("Backend job: retry attempt %d (prev err=%s)", attempt, s_res.err.c_str());
      delay(s_retry_pause_ms);     // a task delay on this core, the loop runs on
      s_doc.clear();
      s_bytes = 0;
    }
    s_res.err  = DeserializationError::Ok;
    s_res.code = backendGetSpoolListJson(s_base, s_res.archived, s_doc,
                                         s_timeout_ms, filter, &s_res.err);
    // Right after the call, before anything else can ask for a list: the flag
    // is the backend layer's, and it is what makes a short list no answer.
    s_res.partial = backendLastListPartial();
    if (s_res.code != 200) {
      logSDf("Backend job: HTTP error %d (attempt %d)", s_res.code, attempt);
      if (attempt == s_res.attempts) { s_res.gave_up = true; break; }
      if (s_res.code == -2 && !transientParseError(s_res.err)) break;
      continue;
    }
    if (!s_res.err) break;
    if (!transientParseError(s_res.err)) break;
  }
  s_res.ms = millis() - t0;
}

static void backendJobTask(void* arg) {
  (void)arg;
  httpCountBytesInto(&s_bytes);
  runList();
  httpCountBytesInto(nullptr);
  logSDf("Backend job: list%s done in %lu ms, code=%d err=%s partial=%d, %u bytes, stack left %u",
         s_res.archived ? " with archive" : "", (unsigned long)s_res.ms, s_res.code,
         s_res.err.c_str(), (int)s_res.partial, (unsigned)s_bytes,
         (unsigned)uxTaskGetStackHighWaterMark(NULL));
  // Everything above is written before the state says so: the loop on the
  // other core reads the state first and the result after.
  __sync_synchronize();
  s_state = BJS_DONE;
  vTaskDelete(NULL);
}

bool backendJobStartList(bool allow_archived, const JsonDocument* filter,
                         uint32_t timeout_ms, uint8_t attempts,
                         uint32_t retry_pause_ms) {
  if (backendListBusy() || s_state != BJS_IDLE) return false;
  // Checked here rather than inside the task: the stack comes out of the
  // heap the moment the task is created.
  if (ESP.getFreeHeap() < BACKEND_JOB_MIN_HEAP) {
    logSDf("Backend job: postponed, heap %u", (unsigned)ESP.getFreeHeap());
    return false;
  }
  s_doc.clear();
  s_filter.clear();
  s_has_filter = (filter != nullptr);
  if (filter) s_filter.set(filter->as<JsonVariantConst>());
  s_res.code     = 0;
  s_res.err      = DeserializationError::Ok;
  s_res.partial  = false;
  s_res.gave_up  = false;
  s_res.archived = allow_archived;
  s_res.attempts = attempts ? attempts : 1;
  s_res.gen      = backendGeneration();
  s_res.ms       = 0;
  s_timeout_ms     = timeout_ms;
  s_retry_pause_ms = retry_pause_ms;
  snprintf(s_base, sizeof(s_base), "%s", cfg_spoolman_base);
  s_bytes = 0;

  // Set before the task exists: if creation fails it is cleared again below,
  // and if it succeeds the task may finish before this line would run - on
  // the simulator it always does.
  s_state = BJS_RUNNING;
  BaseType_t ok = xTaskCreatePinnedToCore(backendJobTask, "backendjob",
                                          BACKEND_JOB_STACK_BYTES, nullptr,
                                          BACKEND_JOB_PRIORITY, nullptr,
                                          BACKEND_JOB_CORE);
  if (ok != pdPASS) {
    s_state = BJS_IDLE;
    logSD("Backend job: task creation failed");
    return false;
  }
  return true;
}

BackendJobState backendJobState() { return s_state; }

bool backendListBusy() {
  return s_state == BJS_RUNNING ||
         (webJobState() == WJS_RUNNING && webJobKind() == WJ_SPOOLS);
}

size_t backendJobBytes() { return s_bytes; }

const BackendListResult& backendJobResult() { return s_res; }
JsonDocument&            backendJobDoc()    { return s_doc; }

void backendJobTake() {
  if (s_state != BJS_DONE) return;
  s_doc.clear();
  // clear() keeps the pool it grew into; shrinking hands the PSRAM back, which
  // the fetch by id after an archived match wants.
  s_doc.shrinkToFit();
  s_filter.clear();
  s_state = BJS_IDLE;
}
