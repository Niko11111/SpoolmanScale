#include "bambuddy_device.h"

#include <Arduino.h>
#include <math.h>
#include <string.h>

#include "app/app_state.h"
#include "app_config.h"
#include "hardware/scale.h"
#include "hardware/scale_state.h"
#include "hardware/sd_logger.h"
#include "services/auto_weight_state.h"
#include "services/bambuddy_api.h"
#include "services/backend.h"
#include "services/wifi_manager.h"

// BamBuddy marks a device offline after 30 seconds without a heartbeat
// (OFFLINE_THRESHOLD_SECONDS in its spoolbuddy routes), so this has to be
// well inside that. Its own daemon uses 10 s.
#define BB_HEARTBEAT_MS       10000
// A failed registration is retried, but not on every pass - a server that is
// up and refusing the key would otherwise produce a request per loop.
#define BB_REGISTER_RETRY_MS  30000
// Live weight for the web interface. At most one per second, and only when
// the reading moved far enough to be worth a request.
#define BB_WEIGHT_MIN_GAP_MS   1000
#define BB_WEIGHT_MIN_DELTA_G     2.0f

static bool          s_registered      = false;
static unsigned long s_last_register_ms = 0;
static unsigned long s_last_hb_ms       = 0;
static bool          s_last_hb_ok       = false;
static unsigned long s_last_weight_ms   = 0;
static float         s_last_weight_g    = -9999.0f;
// Spread of the readings since the last report, which is what decides
// whether the value handed to the web interface counts as settled.
static float         s_win_min          =  1e9f;
static float         s_win_max          = -1e9f;
static char          s_reported_tag[40] = "";

void bambuddyDeviceReset() {
  s_registered = false;
  s_last_register_ms = 0;
  s_reported_tag[0] = '\0';
}

// Answers a command the scale cannot carry out. Every queued command must be
// answered: BamBuddy clears it on the reply, and an unanswered one leaves its
// interface waiting for a device that will never respond.
static void declineCommand(const char* base, const char* key, const char* cmd) {
  bbCommandResult(base, key, cmd, false,
                  "Not supported on SpoolmanScale, this is an ESP32 scale");
  logSDf("BamBuddy: declined command '%s'", cmd);
}

static void handleCommand(const char* base, const char* key, const char* cmd,
                          int write_spool_id) {
  if (strcmp(cmd, "tare") == 0) {
    if (!scale_ready) {
      bbCommandResult(base, key, cmd, false, "Scale not ready");
      logSD("BamBuddy: tare requested but the scale is not ready");
      return;
    }
    // Same three steps the tare button on the main screen performs. The
    // display picks the new value up on the next updateDisplay().
    int32_t raw = scaleHardwareReadRaw();
    saveTareOffset(raw);
    scale_weight_g = 0.0f;
    resetScaleFilter();
    bbSetTare(base, key, raw);
    logSDf("BamBuddy: tare from the server applied (raw=%d)", (int)raw);
    return;
  }

  if (strcmp(cmd, "reboot") == 0 || strcmp(cmd, "restart_daemon") == 0) {
    // restart_daemon means "restart the software" on a Pi, which on this
    // device is the same thing as a reboot.
    bbCommandResult(base, key, cmd, true, "Restarting");
    logSDf("BamBuddy: restarting on request ('%s')", cmd);
    delay(200);          // give the reply a chance to leave
    ESP.restart();
    return;
  }

  if (strcmp(cmd, "write_tag") == 0) {
    // Writing to tags is out of scope for this project by design: the scale
    // only ever reads them. Declined by id so BamBuddy can close the dialog
    // it opened rather than sit on "waiting for SpoolBuddy".
    if (write_spool_id > 0) {
      bbWriteTagResult(base, key, write_spool_id, nullptr, false,
                       "SpoolmanScale never writes to tags, it only reads them");
    } else {
      bbCommandResult(base, key, cmd, false, "SpoolmanScale does not write tags");
    }
    logSD("BamBuddy: declined a tag write");
    return;
  }

  if (strncmp(cmd, "run_", 4) == 0) {
    // run_nfc_diag, run_scale_diag, run_read_tag_diag - all of them run a
    // Python script on the Pi. Reported through the diagnostics endpoint
    // rather than the command one, which is where BamBuddy reads the result.
    const char* diag = (strcmp(cmd, "run_scale_diag") == 0)    ? "scale"
                     : (strcmp(cmd, "run_read_tag_diag") == 0) ? "read_tag"
                                                               : "nfc";
    bbDiagnosticResult(base, key, diag, false,
                       "Diagnostics are a Raspberry Pi feature. This is an ESP32 "
                       "scale: check the SD card log on the device instead.", -1);
    logSDf("BamBuddy: declined diagnostic '%s'", diag);
    return;
  }

  // shutdown, restart_browser, apply_system_config and anything a future
  // BamBuddy adds. Declining by name beats silence.
  declineCommand(base, key, cmd);
}

void bambuddyDeviceTick() {
  if (!backendIsBamBuddy() || !wifi_ok) return;

  const char* base = backendBaseUrl();
  if (strlen(base) <= 7) return;            // longer than "http://"
  const char* key = bambuddyApiKey();

  // --- registration -------------------------------------------
  if (!s_registered) {
    if (s_last_register_ms != 0 && millis() - s_last_register_ms < BB_REGISTER_RETRY_MS) {
      return;
    }
    s_last_register_ms = millis();
    int code = bbRegisterDevice(base, key,
                                wifiManagerLocalIP().toString().c_str(),
                                FW_VERSION, zero_offset, cal_factor);
    if (code != 200) {
      logSDf("BamBuddy: registration failed (HTTP %d), retrying in %d s",
             code, BB_REGISTER_RETRY_MS / 1000);
      return;
    }
    s_registered = true;
    s_last_hb_ms = millis();               // the registration counts as one
    s_last_hb_ok = true;
  }

  // --- heartbeat ----------------------------------------------
  if (millis() - s_last_hb_ms >= BB_HEARTBEAT_MS) {
    s_last_hb_ms = millis();

    char cmd[40] = "";
    int  write_spool_id = 0;
    int  code = bbHeartbeat(base, key, /*nfc_ok=*/true, scale_ready,
                            millis() / 1000,
                            wifiManagerLocalIP().toString().c_str(), FW_VERSION,
                            cmd, sizeof(cmd), &write_spool_id);

    if (code == 404) {
      // The device was removed in the web interface. Registering again is
      // the documented way back, its own daemon does the same.
      logSD("BamBuddy: device is gone from the server, registering again");
      s_registered = false;
      s_last_register_ms = 0;
      return;
    }

    const bool ok = (code == 200);
    if (ok != s_last_hb_ok) {
      // Only on change. A line every ten seconds would bury everything else.
      logSDf("BamBuddy: heartbeat %s (HTTP %d)", ok ? "OK" : "FAILED", code);
      s_last_hb_ok = ok;
    }
    if (ok && cmd[0]) handleCommand(base, key, cmd, write_spool_id);
  }

  // --- tag removal --------------------------------------------
  // Only the removal is reported here. The scan itself already goes out as
  // part of the lookup in bbFindSpoolByTag, once per placement, which is
  // exactly the event BamBuddy wants - sending it a second time from here
  // would double every scan.
  if (tag_present && g_tag.uid_str[0]) {
    strncpy(s_reported_tag, g_tag.uid_str, sizeof(s_reported_tag) - 1);
    s_reported_tag[sizeof(s_reported_tag) - 1] = '\0';
  } else if (!tag_present && s_reported_tag[0]) {
    bbTagRemoved(base, key, s_reported_tag);
    s_reported_tag[0] = '\0';
  }

  // --- live weight --------------------------------------------
  if (scale_ready) {
    // Collected on every pass, not only when a report goes out: the spread
    // over the whole interval is what says whether the load has settled.
    if (scale_weight_g < s_win_min) s_win_min = scale_weight_g;
    if (scale_weight_g > s_win_max) s_win_max = scale_weight_g;

    if (millis() - s_last_weight_ms >= BB_WEIGHT_MIN_GAP_MS) {
      if (fabsf(scale_weight_g - s_last_weight_g) >= BB_WEIGHT_MIN_DELTA_G) {
        // Settled means the readings of the past second stayed inside the
        // same window the automatic weighing waits for. Reporting it lets
        // the web interface distinguish a spool being placed from one that
        // is lying still.
        const bool stable = (s_win_max - s_win_min) < AUTO_WEIGHT_THRESH_G;
        bbScaleReading(base, key, scale_weight_g, stable, scaleHardwareReadRaw());
        s_last_weight_g = scale_weight_g;
      }
      s_last_weight_ms = millis();
      s_win_min =  1e9f;
      s_win_max = -1e9f;
    }
  }
}
