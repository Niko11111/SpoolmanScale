#include "ams_assign.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "backend.h"
#include "filaman_api.h"
#include "hardware/sd_logger.h"
#include "spoolman_actions.h"

uint8_t g_ams_mode      = AMS_OFF;
bool    g_ams_timer_yes = true;
int     g_ams_window_s  = AMS_WINDOW_DEFAULT_S;

namespace {

// What was last weighed. Copied rather than read back from sm_*, because
// those globals survive a removal by design (60 s, see NO_TAG_CLEAR_MS) and a
// second spool arriving in between would otherwise redirect the report.
struct Pending {
  bool          active           = false;
  int           spool_id         = 0;
  float         netto_g          = 0.0f;
  float         gross_g          = 0.0f;
  bool          already_reported = false;
  unsigned long noted_ms         = 0;
};

Pending s_pending;

// Start of the window the server is currently holding open, for the
// countdown. Elapsed differences only, never an absolute deadline: millis()
// wraps after 49 days and a deadline comparison would expire on the spot.
bool          s_window_open       = false;
unsigned long s_window_started_ms = 0;

}  // namespace

bool amsAskActive() {
  return backendIsFilaMan() && g_ams_mode == AMS_ASK && filamanDeviceToken()[0] != '\0';
}

void amsNoteMeasurement(int spool_id, float netto_g, float gross_g,
                        bool already_reported) {
  if (spool_id <= 0) return;
  s_pending.active           = true;
  s_pending.spool_id         = spool_id;
  s_pending.netto_g          = netto_g;
  s_pending.gross_g          = gross_g;
  s_pending.already_reported = already_reported;
  s_pending.noted_ms         = millis();
  logSDf("AMS: noted id=%d netto=%.0fg for the question on removal%s",
         spool_id, netto_g, already_reported ? "" : " (not written yet)");
}

bool  amsHasPending()            { return s_pending.active; }
bool  amsPendingAlreadyReported() { return s_pending.already_reported; }
int   amsPendingSpoolId() { return s_pending.spool_id; }
float amsPendingNetto()   { return s_pending.netto_g; }

unsigned long amsPendingAgeMs() {
  return s_pending.active ? (millis() - s_pending.noted_ms) : 0;
}

void amsDropPending() {
  s_pending = Pending();
}

bool amsWindowOpen() {
  if (!s_window_open) return false;
  if ((millis() - s_window_started_ms) / 1000 >= (unsigned long)g_ams_window_s) {
    s_window_open = false;
    return false;
  }
  return true;
}

int amsWindowRemainingS() {
  if (!amsWindowOpen()) return 0;
  const unsigned long elapsed_s = (millis() - s_window_started_ms) / 1000;
  return g_ams_window_s - (int)elapsed_s;
}

int amsWriteEnabled(bool enabled) {
  const int id = filamanDeviceId();
  if (id <= 0) return FILAMAN_NO_DEVICE_TOKEN;
  return filamanSetDeviceAutoAssign(backendBaseUrl(), filamanApiKey(), id, &enabled, nullptr);
}

int amsWriteWindow(int seconds) {
  if (seconds < AMS_WINDOW_MIN_S) seconds = AMS_WINDOW_MIN_S;
  if (seconds > AMS_WINDOW_MAX_S) seconds = AMS_WINDOW_MAX_S;
  const int id = filamanDeviceId();
  if (id <= 0) return FILAMAN_NO_DEVICE_TOKEN;
  int code = filamanSetDeviceAutoAssign(backendBaseUrl(), filamanApiKey(), id,
                                        nullptr, &seconds);
  if (code == 200) g_ams_window_s = seconds;
  return code;
}

int amsReadServer(bool* out_enabled) {
  const int id = filamanDeviceId();
  if (id <= 0) return FILAMAN_NO_DEVICE_TOKEN;
  int window = g_ams_window_s;
  int code = filamanGetDeviceAutoAssign(backendBaseUrl(), filamanApiKey(), id,
                                        out_enabled, &window);
  if (code == 200) g_ams_window_s = window;
  return code;
}

bool amsCommitWithWindow() {
  if (!s_pending.active) return false;

  const int   spool_id = s_pending.spool_id;
  const float gross    = s_pending.gross_g;
  const float netto    = s_pending.netto_g;
  const bool  written  = s_pending.already_reported;
  amsDropPending();

  int code = amsWriteEnabled(true);
  if (code != 200) {
    // Without the flag the report would land as an ordinary weighing and
    // nothing would be assigned. Sending it anyway would either book a
    // pointless duplicate or write a weight nobody asked for.
    logSDf("AMS: could not arm the window for id=%d, HTTP %d - nothing sent",
           spool_id, code);
    return false;
  }

  int rc;
  if (!written && sm_found && sm_id == spool_id) {
    // Nothing has been written for this spool yet, and the screen still shows
    // it. patchSpoolmanWeight() reaches the same endpoint but also pulls the
    // weight, percentage and date on the main screen along, which matters
    // here: without auto weighing the display would otherwise keep showing
    // the old value right after a new one was written.
    rc = patchSpoolmanWeight(netto);
  } else {
    // Either the value is already in FilaMan and has to go out a second time
    // because the window opens nowhere else, or the display has moved on to
    // another spool and must not be touched.
    rc = filamanReportWeight(backendBaseUrl(), filamanDeviceToken(),
                             spool_id, nullptr, gross);
  }

  // Closed again immediately: the driver holds its own countdown, so this
  // does not shorten the window, it only stops the next weighing from
  // opening one by itself.
  int off = amsWriteEnabled(false);
  if (off != 200) {
    logSDf("AMS: WARNING could not clear auto_assign_enabled, HTTP %d", off);
  }

  if (rc != 200) {
    logSDf("AMS: re-report for id=%d failed, HTTP %d - no window", spool_id, rc);
    return false;
  }

  s_window_open       = true;
  s_window_started_ms = millis();
  logSDf("AMS: window opened for id=%d, %d s (%.0fg %s)",
         spool_id, g_ams_window_s, gross,
         written ? "booked a second time" : "written for the first time");
  return true;
}

void amsBootReconcile() {
  // Only the ask mode ever raises the flag temporarily, so it is the only
  // one that can leave it standing. Off and always are written explicitly
  // when the mode is chosen and need no correction here.
  if (!backendIsFilaMan() || g_ams_mode != AMS_ASK) return;
  if (filamanDeviceId() <= 0 || filamanApiKey()[0] == '\0') return;
  int code = amsWriteEnabled(false);
  if (code == 200) {
    logSD("AMS: auto_assign_enabled cleared on boot");
  } else {
    logSDf("AMS: boot reconcile failed, HTTP %d", code);
  }
}
