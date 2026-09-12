#include "ams_presence.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/ams_slots.h"
#include "services/backend_api.h"
#include "ui/ams_view.h"

namespace {

bool          s_known      = false;
bool          s_has_ams    = false;
int           s_printer_id = 0;
unsigned long s_last_ms    = 0;

}  // namespace

bool amsPresenceHasAms()    { return s_known && s_has_ams; }
int  amsPresencePrinterId() { return s_printer_id; }

void amsPresenceForget() {
  s_known      = false;
  s_has_ams    = false;
  s_printer_id = 0;
  s_last_ms    = 0;
}

void amsPresenceTick() {
  if (!wifi_ok || !backendHasAmsView()) return;

  // The view makes the same calls while it is open, and two of them at once
  // would only fight over the socket.
  if (isAmsViewOpen()) return;

  const unsigned long now = millis();
  if (s_last_ms == 0) {
    if (now < AMS_PRESENCE_FIRST_MS) return;
  } else if (now - s_last_ms < AMS_PRESENCE_INTERVAL_MS) {
    return;
  }
  s_last_ms = now;

  // The printer id survives between passes: it changes when somebody adds or
  // removes a printer, not on a timer, and looking it up again every time
  // would double the cost of this check.
  if (s_printer_id <= 0) {
    AmsPrinterList printers;
    const int code = backendListPrinters(printers, 5000);
    if (code != 200 || printers.count == 0) {
      logSDf("[verbose] AMS: no printer to ask about (HTTP %d)", code);
      return;
    }
    s_printer_id = printers.p[0].id;
  }

  AmsSlotState st;
  const int code = backendGetAmsState(s_printer_id, st, 5000);
  if (code != 200) {
    logSDf("[verbose] AMS: presence check failed, HTTP %d", code);
    // A printer that has gone means the id is stale, so the next pass looks
    // it up again rather than asking about something that is not there.
    if (code == 404) s_printer_id = 0;
    return;
  }

  // The external spool holder is not an AMS. A printer that has only that
  // one would otherwise get a chip leading to a page with a single bay on it.
  bool has_unit = false;
  for (uint8_t u = 0; u < st.unit_count; u++) {
    if (!st.unit[u].is_ext) { has_unit = true; break; }
  }

  // Logged on the first answer and on a change, not every five minutes.
  if (!s_known || s_has_ams != has_unit) {
    logSDf("AMS: printer %d %s an AMS", s_printer_id,
           has_unit ? "has" : "has no");
  }
  s_known   = true;
  s_has_ams = has_unit;
}
