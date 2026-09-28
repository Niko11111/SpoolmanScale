#include "bambu_catalog_sync.h"

#include <Arduino.h>
#include <esp_random.h>
#include <time.h>

#include "app/app_state.h"
#include "bambu/bambu_catalog.h"
#include "hardware/sd_logger.h"
#include "services/ota_state.h"
#include "services/prefs_store.h"
#include "web/web_jobs.h"
#include "web/web_server.h"

// After the update check's 90 to 150 s, so the two TLS connections never
// meet, and with its own spread so a workshop of scales does not ask at once.
#define BCAT_FIRST_DELAY_MS   300000UL
#define BCAT_FIRST_JITTER_MS  120000UL
#define BCAT_INTERVAL_S       86400UL
// Busy worker, low heap, no answer: try again in an hour, not in a loop.
#define BCAT_RETRY_MS         3600000UL
#define BCAT_TIME_SYNCED      1700000000UL
#define BCAT_PREF_KEY         "bcat_chk"

static bool          s_init    = false;
static unsigned long s_due_ms  = 0;
static bool          s_started = false;   // a check of ours is on the worker
static uint32_t      s_last    = 0;       // from NVS, kept here

uint32_t bambuCatalogLastCheck() {
  if (!s_init) s_last = prefsGetUInt(BCAT_PREF_KEY, 0);
  return s_last;
}

bool bambuCatalogSyncNow() {
  if (!webJobStart(WJ_BAMBU_CATALOG, "check", false)) return false;
  s_started = true;
  return true;
}

// The result of a check this module started, if nobody collected it first.
// The tags page may, when it happens to be open; the outcome is then logged
// there already and only the schedule is set here.
static void collect() {
  if (!s_started) return;
  if (webJobKind() == WJ_BAMBU_CATALOG && webJobState() == WJS_RUNNING) return;
  s_started = false;
  bool ok = true;
  if (webJobKind() == WJ_BAMBU_CATALOG && webJobState() == WJS_DONE) {
    const WebJobResult& r = webJobResult();
    ok = r.ok;
    if (!r.ok) logSDf("Bambu catalog: check failed, %s", r.err);
    else if (!strcmp(r.tag, "updated")) logSDf("Bambu catalog: changed at BambuStudio, %d colours now", r.code);
    // Only the background checks: a result the page asked for stays for it.
    if (!strcmp(r.pub, "auto")) webJobTake();
  }
  s_due_ms = millis() + (ok ? BCAT_INTERVAL_S * 1000UL : BCAT_RETRY_MS);
}

void bambuCatalogSyncTick() {
  if (!s_init) {
    s_init   = true;
    s_last   = prefsGetUInt(BCAT_PREF_KEY, 0);
    s_due_ms = millis() + BCAT_FIRST_DELAY_MS + (esp_random() % BCAT_FIRST_JITTER_MS);
  }

  // Any download or check that reached GitHub counts, the button's too.
  const uint32_t checked = bambuCatalogTakeChecked();
  if (checked) {
    s_last = checked;
    if (checked >= BCAT_TIME_SYNCED) prefsPutUInt(BCAT_PREF_KEY, checked);
  }

  collect();
  if (s_started) return;
  if ((long)(millis() - s_due_ms) < 0) return;
  if (!g_upd_autocheck || !wifi_ok) { s_due_ms = millis() + BCAT_RETRY_MS; return; }
  if (gh_flash_active || otaWebUploadActive()) { s_due_ms = millis() + BCAT_RETRY_MS; return; }

  // A day since the last comparison, by the wall clock where there is one.
  // A device that has a catalog and restarts often asks once a day all the
  // same; one without asks at the first chance.
  const time_t now = time(nullptr);
  if (bambuCatalogCount() > 0 && (uint32_t)now >= BCAT_TIME_SYNCED &&
      s_last >= BCAT_TIME_SYNCED && (uint32_t)now - s_last < BCAT_INTERVAL_S) {
    s_due_ms = millis() + (BCAT_INTERVAL_S - ((uint32_t)now - s_last)) * 1000UL;
    return;
  }

  if (!webJobStart(WJ_BAMBU_CATALOG, "auto", false)) {
    s_due_ms = millis() + BCAT_RETRY_MS;
    return;
  }
  s_started = true;
}
