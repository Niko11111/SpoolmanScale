#pragma once

#include <stdint.h>

// ============================================================
//  AUTO AMS ASSIGNMENT
//
//  FilaMan can hand a freshly weighed spool to every running printer driver
//  as "pending" for a number of seconds, so that the next tray to be loaded
//  gets it automatically. The server does that inside
//  POST /api/v1/devices/scale/weight and only when the device record has
//  auto_assign_enabled set. There is no separate arm endpoint, no way to
//  cancel an open window, and measured_weight_g is mandatory - so a weight
//  report is the only thing that can ever open one.
//
//  The scale keeps the server flag off and asks once the spool has been
//  lifted. Saying yes reports the same weight a second time with the flag
//  briefly raised. That leaves two measurement events in the spool log for
//  one weighing, which is the accepted price for deciding per spool instead
//  of per device: the alternative was holding the weight back until the
//  question was answered, and then the value would not appear in FilaMan at
//  the moment of weighing.
// ============================================================

enum AmsMode : uint8_t {
  AMS_OFF        = 0,   // server flag stays off, nothing changes
  AMS_ASK        = 1,   // ask on removal, arm only on yes
  AMS_ALWAYS     = 2,   // server flag stays on, every weighing opens a window
  AMS_MODE_COUNT = 3
};

extern uint8_t g_ams_mode;       // NVS "ams_mode",    default AMS_OFF
extern bool    g_ams_timer_yes;  // NVS "ams_tmr_yes", default true
extern int     g_ams_window_s;   // NVS "ams_window",  cached copy of the server value

// How long the question stands before it answers itself. Kept short: the
// window the server opens is spent walking to the printer, so every second
// counted down here is a second missing at the other end.
#define AMS_ASK_COUNTDOWN_MS   10000

// After this the offer is stale and the note is dropped. Nothing is lost by
// it - the weight was written when it was measured.
#define AMS_PENDING_MAX_MS     120000

// How still the pad has to be before a reading counts as the spool's weight,
// for the case where nothing was weighed on purpose. Deliberately looser and
// far shorter than the auto weight criterion (0.5 g over 3 s): there the user
// is waiting for a countdown, here they are putting a spool down and picking
// it up again. With the 1.6 s moving average in front of it, this settles
// about 2.4 s after the spool lands instead of the 5 s the strict values
// needed - which is why the question never appeared for a short placement.
#define AMS_SETTLE_TOL_G       2.0f
#define AMS_SETTLE_MS          800

// Bounds for the server side auto_assign_timeout.
#define AMS_WINDOW_MIN_S       5
#define AMS_WINDOW_MAX_S       600
#define AMS_WINDOW_DEFAULT_S   60

// True when the ask flow may run: FilaMan selected, mode is ask, and a
// device token exists to report the weight with.
bool amsAskActive();

// Remembers what the scale saw, so a yes can report it and open a window.
// already_reported tells the two sources apart: a real weighing has put the
// value in FilaMan already and a yes books it a second time, while a spool
// that was merely rested on the pad has not been written at all and a yes is
// what writes it. Both send, only the wording and the log differ.
void amsNoteMeasurement(int spool_id, float netto_g, float gross_g,
                        bool already_reported);

bool          amsHasPending();
bool          amsPendingAlreadyReported();
int           amsPendingSpoolId();
float         amsPendingNetto();
unsigned long amsPendingAgeMs();

// Forgets the note without contacting the server.
void amsDropPending();

// Reports the remembered weight again with the window open: PUT true,
// report, PUT false. Three HTTP requests, so this only ever runs from
// appLoop(). Returns true when the window was actually opened.
bool amsCommitWithWindow();

// How much of the assignment window is left, for the countdown on the weight
// button. Zero when none is running.
bool amsWindowOpen();
int  amsWindowRemainingS();

// Writes auto_assign_enabled on this device. Returns the HTTP status, or a
// negative sentinel from the filaman layer.
int amsWriteEnabled(bool enabled);

// Writes auto_assign_timeout and updates the cached copy on success.
int amsWriteWindow(int seconds);

// Reads both fields off the server into g_ams_window_s and out_enabled.
int amsReadServer(bool* out_enabled);

// One corrective PUT false after boot. Without it a crash between the two
// PUTs of a commit would leave the flag standing, and "ask" would silently
// behave like "always".
void amsBootReconcile();
