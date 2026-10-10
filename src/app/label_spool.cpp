// ArduinoJson ahead of lang.h, whose T() macro it would otherwise meet.
#include <ArduinoJson.h>
#include <esp_heap_caps.h>

#include "app/label_spool.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "app/backend_switch.h"
#include "app/deferred_actions.h"
#include "bambu/bambu_tag.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/backend_api.h"

// One spool by id, a small answer: a slow server only costs the label its date.
#define LABEL_DATE_TIMEOUT_MS  4000
// The browser's dates are fetched on a task of their own, the shape of the
// other backend workers: core 0, below the loop, stack from the heap while
// it runs. TLS needs the 16 kB.
#define LABEL_DATE_STACK_BYTES 16384
#define LABEL_DATE_PRIORITY    1
#define LABEL_DATE_CORE        0
#define LABEL_DATE_MIN_HEAP    60000
#define LABEL_DATE_URL_LEN     160

struct SpiRamAllocator : ArduinoJson::Allocator {
  void* allocate(size_t size) override {
    void* ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
    if (!ptr) ptr = malloc(size);
    return ptr;
  }
  void deallocate(void* pointer) override { heap_caps_free(pointer); }
  void* reallocate(void* ptr, size_t new_size) override {
    void* p = heap_caps_realloc(ptr, new_size, MALLOC_CAP_SPIRAM);
    if (!p) p = realloc(ptr, new_size);
    return p;
  }
};

static SpoolLabelData s_last{};
static bool s_have_last = false;
// The id whose dates s_last carries, 0 for none asked yet.
static int s_dates_for = 0;

bool labelSpoolFromScan(SpoolLabelData* out) {
  if (!out || !(sm_found && sm_id > 0)) return false;
  *out = SpoolLabelData{};
  out->id = sm_id;
  snprintf(out->name, sizeof(out->name), "%s", sm_filament_name);
  snprintf(out->vendor, sizeof(out->vendor), "%s", sm_vendor_g);
  // Like the More info card: the backend's material when it named one,
  // else what the Bambu tag says.
  snprintf(out->material, sizeof(out->material), "%s",
           sm_material_global[0] ? sm_material_global : g_tag.material);
  snprintf(out->color, sizeof(out->color), "%s", sm_color_global);
  snprintf(out->article, sizeof(out->article), "%s", sm_article_nr);
  return true;
}

// The copy follows the pad; the dates stay while it is the same spool.
static void takeFromScan() {
  SpoolLabelData d{};
  if (!labelSpoolFromScan(&d)) return;
  if (s_have_last && s_last.id == d.id) {
    snprintf(d.first_used, sizeof(d.first_used), "%s", s_last.first_used);
    snprintf(d.added, sizeof(d.added), "%s", s_last.added);
  } else {
    s_dates_for = 0;
  }
  s_last = d;
  s_have_last = true;
}

void labelSpoolRemember() { takeFromScan(); }

void labelSpoolForget() {
  s_last = SpoolLabelData{};
  s_have_last = false;
  s_dates_for = 0;
}

bool labelSpoolLast(SpoolLabelData* out) {
  takeFromScan();
  if (!out || !s_have_last) return false;
  *out = s_last;
  return true;
}

bool labelSpoolDatesKnown() { return s_have_last && s_dates_for == s_last.id; }

// "2026-03-03T10:00:00Z" as the servers send it, to dd.mm.yyyy.
static void isoToDate(const char* iso, char* out, size_t n) {
  out[0] = '\0';
  int y = 0, m = 0, day = 0;
  if (!iso || sscanf(iso, "%4d-%2d-%2d", &y, &m, &day) != 3) return;
  snprintf(out, n, "%02d.%02d.%04d", day, m, y);
}

// One spool's dates from the backend. False when it did not answer; `first`
// and `added` are written only on an answer. Any task.
static bool fetchDates(const char* base_url, int id, char* first, char* added, size_t n) {
  SpiRamAllocator alloc;
  JsonDocument doc(&alloc);
  if (backendGetSpoolJson(base_url, id, doc, LABEL_DATE_TIMEOUT_MS) != 200) {
    logSDf("Label: no dates for spool #%d, the label goes without", id);
    return false;
  }
  // The first use where the backend records one (Spoolman), and the day the
  // spool was added.
  isoToDate(doc["first_used"] | "", first, n);
  isoToDate(doc["registered"] | "", added, n);
  return true;
}

void labelSpoolFetchDates(SpoolLabelData* d) {
  if (!d) return;
  // The browser's copy already knows them: no second request, and no label
  // that loses the date its preview showed because this one failed.
  if (labelSpoolDatesKnown() && s_last.id == d->id) {
    snprintf(d->first_used, sizeof(d->first_used), "%s", s_last.first_used);
    snprintf(d->added, sizeof(d->added), "%s", s_last.added);
    return;
  }
  char first[sizeof(d->first_used)] = "", added[sizeof(d->added)] = "";
  if (!fetchDates(backendBaseUrl(), d->id, first, added, sizeof(first))) return;
  snprintf(d->first_used, sizeof(d->first_used), "%s", first);
  snprintf(d->added, sizeof(d->added), "%s", added);
  // A print fetches them too: the copy of the same spool learns them as well.
  if (s_have_last && s_last.id == d->id) {
    snprintf(s_last.first_used, sizeof(s_last.first_used), "%s", first);
    snprintf(s_last.added, sizeof(s_last.added), "%s", added);
    s_dates_for = d->id;
  }
}

// The worker for the browser's dates. Everything it reads is set before it
// starts and everything it writes is read only after s_job_done says so.
struct DateJob {
  char url[LABEL_DATE_URL_LEN];
  int id;
  uint32_t gen;        // backendGeneration() at the start
  bool ok;
  char first[12], added[12];
};
static DateJob s_job;
static volatile bool s_job_running = false, s_job_done = false;

static void dateTask(void*) {
  s_job.ok = fetchDates(s_job.url, s_job.id, s_job.first, s_job.added, sizeof(s_job.first));
  __sync_synchronize();
  s_job_done = true;
  vTaskDelete(NULL);
}

// False when the task could not start; the caller then gives up on the dates.
static bool startDateJob(int id) {
  if (ESP.getFreeHeap() < LABEL_DATE_MIN_HEAP) {
    logSDf("Label: dates not fetched, heap %u", (unsigned)ESP.getFreeHeap());
    return false;
  }
  s_job = DateJob{};
  snprintf(s_job.url, sizeof(s_job.url), "%s", backendBaseUrl());
  s_job.id = id;
  s_job.gen = backendGeneration();
  s_job_done = false;
  s_job_running = true;
  if (xTaskCreatePinnedToCore(dateTask, "labeldates", LABEL_DATE_STACK_BYTES, nullptr,
                              LABEL_DATE_PRIORITY, nullptr, LABEL_DATE_CORE) != pdPASS) {
    s_job_running = false;
    logSD("Label: date task creation failed");
    return false;
  }
  return true;
}

// The answer goes to the copy only while it is still about that spool on
// that server: a switch of backend or host in between makes it someone else's.
static void collectDateJob() {
  if (!s_job_running || !s_job_done) return;
  __sync_synchronize();
  s_job_running = false;
  if (s_job.gen != backendGeneration() || !s_have_last || s_last.id != s_job.id) return;
  if (s_job.ok) {
    snprintf(s_last.first_used, sizeof(s_last.first_used), "%s", s_job.first);
    snprintf(s_last.added, sizeof(s_last.added), "%s", s_job.added);
  }
  // Asked once, answered or not: a server without dates is not asked again.
  s_dates_for = s_job.id;
}

void labelSpoolTick() {
  collectDateJob();
  if (!label_dates_pending) return;
  label_dates_pending = false;
  if (!s_have_last || labelSpoolDatesKnown() || s_job_running) return;
  if (!startDateJob(s_last.id)) s_dates_for = s_last.id;
}
