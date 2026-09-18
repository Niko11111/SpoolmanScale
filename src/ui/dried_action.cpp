#include "dried_action.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <cstring>
#include <time.h>

#include "date_display.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/dried_batch.h"
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
// The button was pressed for a spool the AMS card's batch was already
// writing. Nothing was queued; the batch's result answers it instead.
static bool  s_batch_tap_waiting = false;

// Today's drying on the label, and in sm_last_dried behind it.
static void applyDriedToday(const char* iso) {
  char today[11];
  isoDayLocal(iso, today, sizeof(today));
  char de_date[12];
  isoToDe(today, de_date, sizeof(de_date));
  strncpy(sm_last_dried, de_date, sizeof(sm_last_dried)-1);
  sm_last_dried[sizeof(sm_last_dried)-1] = '\0';
  applyDriedLabel(lbl_spoolman_dried_val, lbl_dried_sym, de_date);
}

void btn_dried_cb(lv_event_t *e) {
  logSD("UI: Button -> Dried Today");
  if (!wifi_ok) {
    lv_label_set_text(lbl_spoolman_dried_val, T(STR_NO_WIFI));
    return;
  }
  if (!sm_found || sm_id == 0) {
    lv_label_set_text(lbl_spoolman_dried_val, T(STR_WAIT_SCAN));
    return;
  }
  // A drying date on a spool that is out of the inventory records care for
  // something nobody is going to print with. The button is hidden for an
  // archived spool, so this only catches the paths that call in directly.
  if (sm_archived) {
    lv_label_set_text(lbl_spoolman_dried_val, T(STR_ARCHIVED));
    return;
  }
  // The AMS card is writing this very spool in the background. A second
  // write beside it would race it - on FilaMan both read custom_fields and
  // write them back - and would only record the same day twice.
  if (driedBatchContains(sm_id)) {
    s_batch_tap_waiting = true;
    lv_label_set_text(lbl_spoolman_dried_val, "...");
    logSDf("Dried: spool %d is in the AMS batch, waiting for it", sm_id);
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
  //
  // In time_service since the AMS detail card grew its own drying button:
  // two places building the same stamp is two places for that pair to come
  // apart again.
  char iso_full_buf[32];
  if (!nowIsoUtc(iso_full_buf, sizeof(iso_full_buf))) {
    // No clock, no date. The fallback stamp would be booked as the day this
    // spool was dried, and the first of January reads as months overdue.
    logSD("Dried: clock not set, nothing written");
    lv_label_set_text(lbl_spoolman_dried_val, T(STR_ERR_SAVE));
    return;
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
    applyDriedToday(iso);
    logSDf("Dried: last_dried set for spool %d", spool_id);
  } else {
    logSDf("Dried: write failed for spool %d, HTTP %d", spool_id, code);
    lv_label_set_text(lbl_spoolman_dried_val, T(STR_ERR_SAVE));
  }
}

void driedActionApplyBatch(const DriedBatchResult& r) {
  const bool waiting = s_batch_tap_waiting;
  s_batch_tap_waiting = false;
  if (!sm_found || sm_id == 0 || !lbl_spoolman_dried_val) return;
  for (uint8_t i = 0; i < r.count; i++) {
    if (r.spool_id[i] != sm_id) continue;
    if (r.code[i] == 200) {
      applyDriedToday(r.iso);
      logSDf("Dried: spool %d on the pad took the AMS batch's date", sm_id);
    } else if (waiting) {
      // Only when the button asked: otherwise the label never showed "..."
      // and still holds the date it had, which is still true.
      lv_label_set_text(lbl_spoolman_dried_val, T(STR_ERR_SAVE));
    }
    return;
  }
}
