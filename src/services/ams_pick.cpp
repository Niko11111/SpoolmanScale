#include "ams_pick.h"

#include <Arduino.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/auto_weight_state.h"
#include "services/backend.h"
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
  // One switch per backend: on Spoolman the question goes to an AMS source,
  // which is a different server with its own side effects on the printer.
  const bool ask = backendIsBamBuddy() ? g_ams_pick_ask : g_sm_ams_pick_ask;
  return ask && backendCanAssignAmsSlot();
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
  // Without a load cell nothing is asked on its own: the location has its
  // own button there, and the picker was opened by a tap, not by a removal.
  if (!g_scale_fitted) return;
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

// The Spoolman location for a bay's unit: "X1C AMS 1", "X1C AMS HT", "X1C Ext".
// Language neutral on purpose - it lands in the database, where a German and
// an English scale would otherwise name one shelf twice. One location per
// unit, not per bay: the bay is what the AMS view is for.
#define AMS_HT_FIRST_ID 128
void amsLocationName(char* out, size_t n, const char* printer, int ams_id) {
  char unit[16];
  if (ams_id == AMS_EXT_AMS_ID)        snprintf(unit, sizeof(unit), "Ext");
  else if (ams_id == AMS_HT_FIRST_ID)  snprintf(unit, sizeof(unit), "AMS HT");
  else if (ams_id > AMS_HT_FIRST_ID)   snprintf(unit, sizeof(unit), "AMS HT %d", ams_id - AMS_HT_FIRST_ID + 1);
  else                                 snprintf(unit, sizeof(unit), "AMS %d", ams_id + 1);
  if (printer && printer[0]) snprintf(out, n, "%s %s", printer, unit);
  else                       snprintf(out, n, "%s", unit);
}

// After an assignment through the AMS source: the unit becomes the spool's
// location, so Spoolman's own interface knows where it is. A failure here
// costs only that - the bay is assigned either way - and is logged.
static void setAmsLocation(int spool_id, int ams_id) {
  if (backendMode() != BACKEND_SPOOLMAN || !g_sm_ams_loc) return;
  char loc[64];
  amsLocationName(loc, sizeof(loc), amsViewPrinterName(), ams_id);
  const int code = backendPatchSpoolLocation(cfg_spoolman_base, spool_id, loc, 8000);
  logSDf("AMSPICK: location of spool %d -> '%s', HTTP %d", spool_id, loc, code);
  if (!backendWriteOk(code)) return;
  if (sm_found && sm_id == spool_id) {
    snprintf(sm_location_name, sizeof(sm_location_name), "%s", loc);
    sm_location_id = 0;
  }
}

// What an AMS source's answer means to the user. The contract names these
// codes; BamBuddy's own answers keep the one message they always had.
static int assignFailText(int code) {
  if (backendMode() != BACKEND_SPOOLMAN) return STR_AMSV_ASSIGN_FAIL;
  switch (code) {
    case 403: return STR_AMSV_ERR_READONLY;
    case 404: return STR_AMSV_ERR_UNKNOWN;
    case 502: return STR_AMSV_ERR_INVENTORY;
    case 503: return STR_AMSV_ERR_OFFLINE;
    default:  return STR_AMSV_ASSIGN_FAIL;
  }
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

  const int code = amsReachNote(backendAssignAmsSlot(spool_id, printer_id, ams_id, tray_id, 8000), true);
  amsPickDropPending();

  if (code == 200) {
    const bool moved = (was_ams >= 0 && (was_ams != ams_id || was_tray != tray_id));
    logSDf("AMSPICK: spool %d -> printer %d bay %d/%d (%s)",
           spool_id, printer_id, ams_id, tray_id, moved ? "moved" : "new");
    setAmsLocation(spool_id, ams_id);
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
    showInfoPopup(STR_AMSV_TITLE, assignFailText(code), INFO_WARN);
  }
}

// The page itself, headed with the remembered spool's name.
static void openPicker() {
  char fmt[48], head[80];
  copyT(fmt, sizeof(fmt), STR_AMSV_PICK_HEAD);
  snprintf(head, sizeof(head), fmt,
           s_pending.name[0] ? s_pending.name : "");
  requestAmsView(AMS_VIEW_PICK, onPicked, head);
}

void amsPickShow() {
  if (!s_pending.active) return;
  // A note taken under one backend can be asked about under another only if
  // that one can assign bays too, and the option is still on.
  if (!amsPickActive()) {
    amsPickDropPending();
    return;
  }

  openPicker();
}

void amsPickOpenFor(int spool_id, const char* spool_name) {
  if (spool_id <= 0 || !backendCanAssignAmsSlot()) return;
  amsPickNote(spool_id, spool_name);
  logSDf("AMSPICK: picker opened by the AMS button for id=%d", spool_id);
  openPicker();
}

void amsPickTick() {
  if (!s_pending.active) return;
  if (isAmsViewOpen()) return;          // the question is on screen, let it stand
  if (amsPickPendingAgeMs() <= AMS_PICK_MAX_MS) return;
  logSDf("AMSPICK: note for spool %d expired", s_pending.spool_id);
  amsPickDropPending();
}
