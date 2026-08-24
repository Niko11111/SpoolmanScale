#include "dried_action.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <cstring>
#include <time.h>

#include "date_display.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/time_service.h"
#include "lang.h"

// The write itself is deferred to appLoop(). In FilaMan mode it costs two
// sequential HTTP calls, a GET to read custom_fields and a PATCH to write
// them back, because a PATCH replaces the whole object. Up to sixteen
// seconds inside an LVGL callback would freeze the display and can trip the
// watchdog, so the callback only records what to do and returns.
static bool  s_dried_pending = false;
static int   s_dried_spool_id = 0;
static char  s_dried_iso[32]  = "";

void btn_dried_cb(lv_event_t *e) {
  logSD("UI: Button -> Dried Today");
  if (!wifi_ok) {
    lv_label_set_text(lbl_spoolman_dried_val, "No WiFi!");
    return;
  }
  if (!sm_found || sm_id == 0) {
    lv_label_set_text(lbl_spoolman_dried_val, T(STR_WAIT_SCAN));
    return;
  }

  // A real UTC instant, because that is what the Z says and what Spoolman and
  // FilaMan show after converting it back to the viewer's zone. Writing local
  // time under a Z put their display two hours into the future.
  //
  // The other half of this lives on the reading side: the day such a stamp
  // belongs to is the local one, so every reader goes through isoDayLocal()
  // rather than slicing the first ten characters off. Doing only one of the
  // two is what made the date read as yesterday just after midnight.
  struct tm ti;
  char iso_full_buf[32] = "2026-01-01T00:00:00.000Z";
  if (getLocalTime(&ti)) {
    time_t now = mktime(&ti);
    struct tm *utc = gmtime(&now);
    snprintf(iso_full_buf, sizeof(iso_full_buf), "%04d-%02d-%02dT%02d:%02d:%02d.000Z",
      utc->tm_year+1900, utc->tm_mon+1, utc->tm_mday,
      utc->tm_hour, utc->tm_min, utc->tm_sec);
  }

  strncpy(s_dried_iso, iso_full_buf, sizeof(s_dried_iso)-1);
  s_dried_iso[sizeof(s_dried_iso)-1] = '\0';
  s_dried_spool_id = sm_id;
  s_dried_pending  = true;

  // Immediate feedback, the result replaces this on the next loop pass.
  lv_label_set_text(lbl_spoolman_dried_val, "...");
  Serial.printf("Queued last_dried: %s for spool ID %d\n", s_dried_iso, s_dried_spool_id);
}

void handleDriedDeferredAction() {
  if (!s_dried_pending) return;
  s_dried_pending = false;

  int   spool_id = s_dried_spool_id;
  char  iso[32];
  strncpy(iso, s_dried_iso, sizeof(iso)-1);
  iso[sizeof(iso)-1] = '\0';

  int code = backendPatchSpoolLastDried(cfg_spoolman_base, spool_id, iso);

  // The spool may have been swapped while the request was in flight.
  if (spool_id != sm_id) {
    logSDf("Dried: spool changed during write (%d -> %d), display not touched",
           spool_id, sm_id);
    return;
  }

  if (code == 200) {
    char today[11];
    isoDayLocal(iso, today, sizeof(today));
    char de_date[12];
    isoToDe(today, de_date, sizeof(de_date));
    strncpy(sm_last_dried, de_date, sizeof(sm_last_dried)-1);
    sm_last_dried[sizeof(sm_last_dried)-1] = '\0';
    applyDriedLabel(lbl_spoolman_dried_val, lbl_dried_sym, de_date);
    logSDf("Dried: last_dried set for spool %d", spool_id);
  } else {
    logSDf("Dried: write failed for spool %d, HTTP %d", spool_id, code);
    lv_label_set_text(lbl_spoolman_dried_val, T(STR_ERR_SAVE));
  }
}
