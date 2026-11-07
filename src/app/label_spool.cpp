// ArduinoJson ahead of lang.h, whose T() macro it would otherwise meet.
#include <ArduinoJson.h>
#include <esp_heap_caps.h>

#include "app/label_spool.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "app/backend_switch.h"
#include "app/deferred_actions.h"
#include "app/label_link.h"
#include "bambu/bambu_tag.h"
#include "hardware/sd_logger.h"
#include "services/worker_heap.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/drying_sync.h"
#include "services/local_date.h"
#include "services/tag_spool_match.h"
#include "services/text_util.h"
#include "ui/date_display.h"

// One spool by id, a small answer: a slow server only costs the label its date.
#define LABEL_DATE_TIMEOUT_MS  4000
// The browser's dates are fetched on a task of their own, the shape of the
// other backend workers: core 0, below the loop, stack from the heap while
// it runs. TLS needs the 16 kB.
#define LABEL_DATE_STACK_BYTES 16384
#define LABEL_DATE_PRIORITY    1
#define LABEL_DATE_CORE        0
// Above this a temperature is a typo or a unit mix-up, not a setting.
#define LABEL_TEMP_MAX_C       500

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

// What the backend adds to the scan: the dates, the temperatures and the
// drying. One request brings them all, so they travel together.
struct LabelExtras {
  char first[12], added[12];
  int16_t nozzle_min, nozzle_max, bed;
  int16_t dry_c, dry_h;
  char page_url[LABEL_QR_LEN];
};

static void extrasInto(SpoolLabelData* d, const LabelExtras& e) {
  snprintf(d->first_used, sizeof(d->first_used), "%s", e.first);
  snprintf(d->added, sizeof(d->added), "%s", e.added);
  d->nozzle_min = e.nozzle_min;
  d->nozzle_max = e.nozzle_max;
  d->bed_temp = e.bed;
  // Known from the scan already; an answer without one takes nothing away.
  if (e.page_url[0]) snprintf(d->page_url, sizeof(d->page_url), "%s", e.page_url);
  // The backend's drying wins; without one the tag's from the scan stays.
  if (e.dry_c > 0 && e.dry_h > 0) {
    d->dry_temp_c = e.dry_c;
    d->dry_hours = e.dry_h;
  }
}

static LabelExtras extrasOf(const SpoolLabelData& d) {
  LabelExtras e{};
  snprintf(e.first, sizeof(e.first), "%s", d.first_used);
  snprintf(e.added, sizeof(e.added), "%s", d.added);
  e.nozzle_min = d.nozzle_min;
  e.nozzle_max = d.nozzle_max;
  e.bed = d.bed_temp;
  snprintf(e.page_url, sizeof(e.page_url), "%s", d.page_url);
  e.dry_c = d.dry_temp_c;
  e.dry_h = d.dry_hours;
  return e;
}

// The last drying as the scan keeps it, in whichever display format the
// setting had when it was looked up, as the label's date; empty for the
// scan's "-" or anything else that is not a date.
static void driedToLocal(const char* local, char* out, size_t n) {
  out[0] = '\0';
  char ymd[LOCAL_DATE_ISO_LEN];
  if (!localDateToIso(local, ymd, sizeof(ymd))) return;
  isoToLabelDate(ymd, out, n);
}

static SpoolLabelData s_last{};
static bool s_have_last = false;
// The id whose dates s_last carries, 0 for none asked yet, and whether the
// server answered: asked once is enough for the browser, a print asks again
// while the answer is missing.
static int  s_dates_for = 0;
static bool s_dates_ok  = false;
// The browser's date task, see dateTask() below.
static volatile bool s_job_running = false, s_job_done = false;

bool labelSpoolFromScan(SpoolLabelData* out) {
  if (!out || !(sm_found && sm_id > 0)) return false;
  *out = SpoolLabelData{};
  out->id = sm_id;
  snprintf(out->page_url, sizeof(out->page_url), "%s", sm_page_url);
  out->filament_id = sm_filament_id > 0 ? sm_filament_id : 0;
  snprintf(out->name, sizeof(out->name), "%s", sm_filament_name_label);
  snprintf(out->vendor, sizeof(out->vendor), "%s", sm_vendor_g);
  // Like the More info card: the backend's material when it named one,
  // else what the Bambu tag says.
  snprintf(out->material, sizeof(out->material), "%s",
           sm_material_global[0] ? sm_material_global : g_tag.material);
  snprintf(out->color, sizeof(out->color), "%s", sm_color_global);
  snprintf(out->article, sizeof(out->article), "%s", sm_article_nr);
  if (sm_tare_source != TARE_NONE && sm_spool_weight > 0) out->spool_weight_g = sm_spool_weight;
  if (sm_total > 0) out->net_weight_g = sm_total;
  utf8Cut(sm_location_name, sizeof(out->location) - 1, out->location, sizeof(out->location));
  driedToLocal(sm_last_dried, out->dried, sizeof(out->dried));
  // The drying a Bambu tag recommends, until the backend's arrives: only
  // while the tag on the reader is the one that found this spool, and only
  // where the two agree, the rule drying_sync.cpp writes it back by.
  if (g_tag.tray_uuid[0] && g_tag.dry_temp_c > 0 && g_tag.dry_hours > 0 &&
      !tagSpoolLookupDiffers()) {
    out->dry_temp_c = (int16_t)g_tag.dry_temp_c;
    out->dry_hours = (int16_t)g_tag.dry_hours;
  }
  return true;
}

// The copy follows the pad; the dates stay while it is the same spool.
static void takeFromScan() {
  SpoolLabelData d{};
  if (!labelSpoolFromScan(&d)) return;
  if (s_have_last && s_last.id == d.id) {
    extrasInto(&d, extrasOf(s_last));
  } else {
    s_dates_for = 0;
    s_dates_ok  = false;
  }
  s_last = d;
  s_have_last = true;
}

void labelSpoolRemember() { takeFromScan(); }

void labelSpoolForget() {
  s_last = SpoolLabelData{};
  s_have_last = false;
  s_dates_for = 0;
  s_dates_ok  = false;
}

bool labelSpoolLast(SpoolLabelData* out) {
  takeFromScan();
  if (!out || !s_have_last) return false;
  *out = s_last;
  return true;
}

bool labelSpoolDatesKnown() { return s_have_last && s_dates_for == s_last.id; }

// "2026-03-03T10:00:00Z" as the servers send it, in the date format the
// display uses (Settings > Language), so label and screen agree; the year
// short, as a label has the room for it.
static void isoToDate(const char* iso, char* out, size_t n) {
  out[0] = '\0';
  int y = 0, m = 0, day = 0;
  if (!iso || sscanf(iso, "%4d-%2d-%2d", &y, &m, &day) != 3) return;
  char ymd[16];
  snprintf(ymd, sizeof(ymd), "%04d-%02d-%02d", y, m, day);
  isoToLabelDate(ymd, out, n);
}

// A temperature as the backend gave it, 0 for none or nonsense.
static int16_t tempOf(JsonVariantConst v) {
  const int t = v | 0;
  return t > 0 && t < LABEL_TEMP_MAX_C ? (int16_t)t : 0;
}

// One spool's dates and temperatures from the backend. False when it did not
// answer; `out` is written only on an answer. Any task.
static bool fetchDates(const char* base_url, int id, LabelExtras* out) {
  SpiRamAllocator alloc;
  JsonDocument doc(&alloc);
  if (backendGetSpoolJson(base_url, id, doc, LABEL_DATE_TIMEOUT_MS) != 200) {
    logSDf("Label: no dates for spool #%d, the label goes without", id);
    return false;
  }
  // The first use where the backend records one (Spoolman), and the day the
  // spool was added.
  LabelExtras e{};
  isoToDate(doc["first_used"] | "", e.first, sizeof(e.first));
  isoToDate(doc["registered"] | "", e.added, sizeof(e.added));
  // A server on the Spoolman way may name the spool's page itself. Spooly does:
  // its link keeps working when its numbers are counted anew, which a link built
  // from the id would not.
  snprintf(e.page_url, sizeof(e.page_url), "%s", backendSpoolLink(doc.as<JsonObjectConst>()));
  // Spoolman's filament settings; BamBuddy's range arrives under the same
  // name for its upper end and a name of the scale's own for the lower.
  JsonObjectConst f = doc["filament"];
  e.nozzle_max = tempOf(f["settings_extruder_temp"]);
  e.nozzle_min = tempOf(f["x_extruder_temp_min"]);
  e.bed = tempOf(f["settings_bed_temp"]);
  // The drying: on the filament in Spoolman and FilaMan, on the spool in
  // BamBuddy's own inventory, one text field either way.
  const char* dry = f["extra"]["drying"] | (const char*)nullptr;
  if (!dry) dry = doc["extra"]["drying"] | "";
  int dry_c = 0, dry_h = 0;
  if (dryingParse(dry, &dry_c, &dry_h)) {
    e.dry_c = (int16_t)dry_c;
    e.dry_h = (int16_t)dry_h;
  }
  *out = e;
  return true;
}

void labelSpoolFetchDates(SpoolLabelData* d) {
  if (!d) return;
  // The QR code's address is due with the label too, and asked here where a
  // request is allowed; not beside the browser's task, for the reason below.
  if (!s_job_running) labelLinkRefresh();
  // The browser's copy already knows them: no second request, and no label
  // that loses the date its preview showed because this one failed. A copy
  // whose request failed is asked again here.
  if (labelSpoolDatesKnown() && s_dates_ok && s_last.id == d->id) {
    extrasInto(d, extrasOf(s_last));
    return;
  }
  // The browser's task is on its request right now and holds the pooled
  // connection: a second one would open beside it, just before the printer's
  // BLE stack needs the memory. The label goes without; the copy learns them.
  if (s_job_running) {
    logSDf("Label: dates of spool #%d still loading, the label goes without", d->id);
    return;
  }
  LabelExtras e{};
  if (!fetchDates(backendBaseUrl(), d->id, &e)) return;
  extrasInto(d, e);
  // A print fetches them too: the copy of the same spool learns them as well.
  if (s_have_last && s_last.id == d->id) {
    extrasInto(&s_last, e);
    s_dates_for = d->id;
    s_dates_ok  = true;
  }
}

// The worker for the browser's dates. Everything it reads is set before it
// starts and everything it writes is read only after s_job_done says so:
// also where the backend is, which the loop may change while the task runs.
struct DateJob {
  BackendTarget at;
  int id;
  uint32_t gen;        // backendGeneration() at the start
  bool ok;
  LabelExtras extras;
  bool want_link;      // the QR code's address is due as well
  LabelLinkAnswer link;
};
static DateJob s_job;

static void dateTask(void*) {
  if (s_job.want_link) labelLinkFetchAt(s_job.at, s_job.gen, &s_job.link);
  s_job.ok = fetchDates(s_job.at.base, s_job.id, &s_job.extras);
  __sync_synchronize();
  s_job_done = true;
  vTaskDelete(NULL);
}

// A refused start is asked for again on every loop pass.
static LogGate s_refusal_gate{};

// False when the task could not start; the caller then gives up on the dates.
static bool startDateJob(int id) {
  if (!workerHeapReady("Label: dates", workerFloorBackend(), LABEL_DATE_STACK_BYTES,
                       &s_refusal_gate)) {
    return false;
  }
  s_job = DateJob{};
  backendTargetSnapshot(&s_job.at);
  s_job.id = id;
  s_job.gen = backendGeneration();
  s_job.want_link = labelLinkDue();
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
  // Taken before the dates count as known: the preview drawn on them then
  // carries the right address as well.
  if (s_job.want_link) labelLinkTake(s_job.link);
  if (s_job.gen != backendGeneration() || !s_have_last || s_last.id != s_job.id) return;
  if (s_job.ok) {
    extrasInto(&s_last, s_job.extras);
    s_dates_ok = true;
  }
  // Asked once, answered or not: a server without dates is not asked again
  // for the browser. A print asks once more while s_dates_ok is false.
  s_dates_for = s_job.id;
}

void labelSpoolTick() {
  collectDateJob();
  if (!label_dates_pending) return;
  label_dates_pending = false;
  if (!s_have_last || labelSpoolDatesKnown() || s_job_running) return;
  if (!startDateJob(s_last.id)) s_dates_for = s_last.id;
}
