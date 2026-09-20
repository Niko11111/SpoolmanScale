#include "ams_pick.h"

#include <Arduino.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/auto_weight_state.h"
#include "services/backend_api.h"
#include "services/server_reach.h"
#include "services/location_state.h"
#include "services/user_options.h"
#include "ui/ams_view.h"
#include "ui/info_popup.h"
#include "ui/more_info_screen.h"

#include "lang.h"

namespace {

struct Pending {
  bool          active;
  int           spool_id;
  char          name[32];
  unsigned long noted_ms;
};

Pending s_pending;

}  // namespace

bool amsPickActive() {
  return g_ams_pick_ask && backendCanAssignAmsSlot();
}

void amsPickNote(int spool_id, const char* spool_name) {
  if (spool_id <= 0) return;
  s_pending.active   = true;
  s_pending.spool_id = spool_id;
  s_pending.noted_ms = millis();
  s_pending.name[0]  = '\0';
  if (spool_name) {
    strncpy(s_pending.name, spool_name, sizeof(s_pending.name) - 1);
    s_pending.name[sizeof(s_pending.name) - 1] = '\0';
  }
}

bool amsPickHasPending()    { return s_pending.active; }
int  amsPickPendingSpoolId(){ return s_pending.active ? s_pending.spool_id : -1; }

unsigned long amsPickPendingAgeMs() {
  return s_pending.active ? (millis() - s_pending.noted_ms) : 0;
}

void amsPickDropPending() { s_pending.active = false; }

// The location question the picker took the removal event away from. A
// spool that went into a bay needs no shelf; one whose picker was closed
// without a tap is going somewhere else, and that is what the location
// prompt is for. Same conditions and same guard as the AMS question's "no"
// branch in ams_assign_popup.cpp: the NFC poll kept running under the page,
// and a spool that landed meanwhile moved sm_id.
static void offerLocationAfterPick(int spool_id) {
  if (!g_auto_loc_popup || !wifi_ok) return;
  if (!sm_found || sm_archived || sm_id != spool_id) {
    logSDf("LOC: not offered after the picker, id=%d sm_id=%d found=%d archived=%d",
           spool_id, sm_id, (int)sm_found, (int)sm_archived);
    return;
  }
  if (g_loc_popup_shown_for_id == spool_id) return;
  g_loc_popup_shown_for_id = spool_id;
  logSDf("LOC: offered after the picker was closed, id=%d", spool_id);
  requestLocationPicker(true);
}

// Runs one pass after the picker closed, never from the tap itself.
static void onPicked(int ams_id, int tray_id) {
  // The page went away without a tap: back, a backend switch, a navigation
  // that tore it down. The bay question was seen and not answered, so it is
  // not asked again for this spool - the location question still is, because
  // a spool that is not going into the printer is going onto a shelf.
  if (ams_id < 0 || tray_id < 0) {
    const int spool_id = amsPickPendingSpoolId();
    logSD("AMSPICK: picker closed without an answer, note dropped");
    amsPickDropPending();
    offerLocationAfterPick(spool_id);
    return;
  }

  const int spool_id = amsPickPendingSpoolId();
  if (spool_id <= 0) {
    logSD("AMSPICK: answer arrived with no spool remembered");
    return;
  }
  // Another spool can have landed on the pad while the question stood. The
  // answer belongs to the one that was asked about, or to nothing.
  if (sm_found && sm_id > 0 && sm_id != spool_id) {
    logSDf("AMSPICK: answer discarded, parked spool changed from %d to %d",
           spool_id, sm_id);
    amsPickDropPending();
    return;
  }

  const int printer_id = amsViewPrinterId();
  if (printer_id <= 0) {
    logSD("AMSPICK: no printer to assign to");
    amsPickDropPending();
    return;
  }

  // Where it sits now, so the result can say "moved" rather than "assigned"
  // when it was already somewhere. A failure here is not fatal: it only
  // costs the nicer wording.
  int was_ams = -1, was_tray = -1;
  backendFindSpoolSlot(spool_id, printer_id, &was_ams, &was_tray, 6000);

  const int code = serverReachNote(backendAssignAmsSlot(spool_id, printer_id, ams_id, tray_id, 8000), true);
  amsPickDropPending();

  if (code == 200) {
    const bool moved = (was_ams >= 0 && (was_ams != ams_id || was_tray != tray_id));
    logSDf("AMSPICK: spool %d -> printer %d bay %d/%d (%s)",
           spool_id, printer_id, ams_id, tray_id, moved ? "moved" : "new");
    showInfoPopup(STR_AMSV_TITLE, moved ? STR_AMSV_MOVED : STR_AMSV_ASSIGNED,
                  INFO_DONE);
    // A spool going into the printer does not also need the storage location
    // question on top of it.
    g_loc_popup_shown_for_id = spool_id;
  } else {
    // The code goes to the log, not into the popup: showInfoPopup takes
    // string ids so the handler can still read them after the caller's
    // buffers are gone, and a number cannot ride along in one.
    logSDf("AMSPICK: assignment of spool %d failed, HTTP %d", spool_id, code);
    showInfoPopup(STR_AMSV_TITLE, STR_AMSV_ASSIGN_FAIL, INFO_WARN);
  }
}

void amsPickShow() {
  if (!s_pending.active) return;
  // A note taken under one backend can be asked about under another only if
  // that one can assign bays too, and the option is still on.
  if (!amsPickActive()) {
    amsPickDropPending();
    return;
  }

  char fmt[48], head[80];
  copyT(fmt, sizeof(fmt), STR_AMSV_PICK_HEAD);
  snprintf(head, sizeof(head), fmt,
           s_pending.name[0] ? s_pending.name : "");
  requestAmsView(AMS_VIEW_PICK, onPicked, head);
}

void amsPickTick() {
  if (!s_pending.active) return;
  if (isAmsViewOpen()) return;          // the question is on screen, let it stand
  if (amsPickPendingAgeMs() <= AMS_PICK_MAX_MS) return;
  logSDf("AMSPICK: note for spool %d expired", s_pending.spool_id);
  amsPickDropPending();
}
