#include "ams_presence.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/ams_slots.h"
#include "services/backend_api.h"
#include "ui/ams_view.h"
#include "ui/header_status.h"
#include "ui/main_screen_helpers.h"
#include "ui/ui_common.h"

namespace {

bool          s_known      = false;
bool          s_has_ams    = false;
int           s_printer_id = 0;
unsigned long s_last_ms    = 0;

// In BSS, not on the loop task's stack: together they are close to two
// kilobytes, and ams_slots.h asks for exactly this.
AmsPrinterList s_printers;
AmsSlotState   s_state;

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
  // Two blocking requests under a question the user is looking at would hold
  // the touch panel for their whole timeout. The question comes first.
  if (uiModalWaiting()) return;

  const unsigned long now = millis();
  if (s_last_ms == 0) {
    // First pass after boot or after a forget: ask AMS_PRESENCE_FIRST_MS from
    // now, expressed as an interval that is already mostly elapsed so the
    // check below stays a plain subtraction and survives the millis() wrap.
    s_last_ms = now - (AMS_PRESENCE_INTERVAL_MS - AMS_PRESENCE_FIRST_MS);
    return;
  }
  if (now - s_last_ms < AMS_PRESENCE_INTERVAL_MS) return;
  s_last_ms = now;

  // The printer id survives between passes: it changes when somebody adds or
  // removes a printer, not on a timer, and looking it up again every time
  // would double the cost of this check.
  if (s_printer_id <= 0) {
    const int code = backendListPrinters(s_printers, 5000);
    if (code != 200 || s_printers.count == 0) {
      logSDf("[verbose] AMS: no printer to ask about (HTTP %d)", code);
      return;
    }
    s_printer_id = s_printers.p[0].id;
  }

  AmsSlotState& st = s_state;
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

  const bool changed = (!s_known || s_has_ams != has_unit);

  // Logged on the first answer and on a change, not every five minutes.
  if (changed) {
    logSDf("AMS: printer %d %s an AMS", s_printer_id,
           has_unit ? "has" : "has no");
  }
  s_known   = true;
  s_has_ams = has_unit;

  // The answer lands about twenty seconds after boot, long after the header
  // was built and hid the chip for want of one, and nothing repaints that row
  // on a schedule: updateHeaderStatus() hangs on events - a reachability flip,
  // a way back from another screen - so the chip stayed away until one of them
  // happened to fire. Only on a change, so this is silent every five minutes.
  // Both functions test their own object pointers, and this runs on the loop
  // task, which is the one allowed to touch LVGL.
  if (changed) {
    updateAmsAffordance();
    layoutHeaderChips();
  }
}
