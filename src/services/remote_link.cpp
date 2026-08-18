#include "remote_link.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "app_config.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/filaman_api.h"

static int           s_pending_spool_id = 0;
static unsigned long s_pending_since_ms = 0;
static bool          s_tag_was_present  = false;

bool remote_link_reject_pending = false;

void remoteLinkSetPending(int spool_id) {
  if (spool_id <= 0) return;
  s_pending_spool_id = spool_id;
  s_pending_since_ms = millis();
  // Captured here rather than later: this is the moment the user clicked, and
  // whether a tag was already lying there is what separates "placed it, then
  // asked" from "asked, then walked over".
  s_tag_was_present  = tag_present;
  logSDf("RemoteLink: trigger for spool %d (tag already present: %d)",
         spool_id, s_tag_was_present ? 1 : 0);
}

bool remoteLinkTagWasPresent() {
  return s_tag_was_present;
}

bool remoteLinkPendingActive() {
  return s_pending_spool_id > 0;
}

int remoteLinkPendingSpoolId() {
  return s_pending_spool_id;
}

unsigned long remoteLinkPendingAgeMs() {
  return millis() - s_pending_since_ms;
}

void remoteLinkClear() {
  s_tag_was_present  = false;
  s_pending_spool_id = 0;
  s_pending_since_ms = 0;
}

void remoteLinkReport(bool ok, const char* tag_uuid, const char* error_message) {
  const int spool_id = s_pending_spool_id;
  remoteLinkClear();
  if (spool_id <= 0) return;

  // The link itself may well have happened; only the report can fail here.
  // Saying so in the log matters, because the web UI will show a timeout
  // while the display shows success.
  if (!backendIsFilaMan() || !filamanDeviceToken()[0]) {
    logSDf("RemoteLink: cannot report spool %d, no FilaMan device token", spool_id);
    return;
  }

  filamanRfidResult(backendBaseUrl(), filamanDeviceToken(),
                    ok, tag_uuid, spool_id, error_message);
}

void remoteLinkReportUnsupported(const char* error_message) {
  if (!backendIsFilaMan() || !filamanDeviceToken()[0]) return;
  filamanRfidResult(backendBaseUrl(), filamanDeviceToken(),
                    false, nullptr, 0, error_message);
}
