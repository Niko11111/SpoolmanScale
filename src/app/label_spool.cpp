// ArduinoJson ahead of lang.h, whose T() macro it would otherwise meet.
#include <ArduinoJson.h>
#include <esp_heap_caps.h>

#include "app/label_spool.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "bambu/bambu_tag.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/backend_api.h"

// One spool by id, a small answer: a slow server only costs the label its date.
#define LABEL_DATE_TIMEOUT_MS  4000

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

void labelSpoolFetchDates(SpoolLabelData* d) {
  if (!d) return;
  d->first_used[0] = d->added[0] = '\0';
  SpiRamAllocator alloc;
  JsonDocument doc(&alloc);
  if (backendGetSpoolJson(backendBaseUrl(), d->id, doc, LABEL_DATE_TIMEOUT_MS) != 200) {
    logSDf("Label: no dates for spool #%d, the label goes without", d->id);
    return;
  }
  // The first use where the backend records one (Spoolman), and the day the
  // spool was added.
  isoToDate(doc["first_used"] | "", d->first_used, sizeof(d->first_used));
  isoToDate(doc["registered"] | "", d->added, sizeof(d->added));
  // A print fetches them too: the copy of the same spool learns them as well.
  if (s_have_last && s_last.id == d->id) {
    snprintf(s_last.first_used, sizeof(s_last.first_used), "%s", d->first_used);
    snprintf(s_last.added, sizeof(s_last.added), "%s", d->added);
    s_dates_for = d->id;
  }
}

void labelSpoolTick() {
  if (!label_dates_pending) return;
  label_dates_pending = false;
  if (!s_have_last || labelSpoolDatesKnown()) return;
  SpoolLabelData d = s_last;
  labelSpoolFetchDates(&d);
  // Asked once, answered or not: a server without dates is not asked again.
  s_dates_for = d.id;
}
