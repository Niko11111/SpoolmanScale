#include "app_loop.h"

#include <Arduino.h>
#include <WiFi.h>
#include <Wire.h>
#include <lvgl.h>
#include <cmath>
#include <cstring>
#include <esp_heap_caps.h>

#include "app_config.h"
#include "bambu/bambu_catalog_sync.h"
#include "services/dried_migrate.h"
#include "services/drying_sync.h"
#include "services/backend_http.h"
#include "app/app_boot.h"
#include "app/app_state.h"
#include "app/app_loop_shared.h"
#include "app/tag_scan.h"
#include "app/backend_switch.h"
#include "app/deferred_actions.h"
#include "app/perf_monitor.h"
#include "app/render_bench.h"
#include "app/screenshot.h"
#include "hardware/lvgl_mem.h"
#include "services/partition_layout.h"
#include "ui/partition_popup.h"
#include "bambu/bambu_tag.h"
#include "hardware/display_power.h"
#include "hardware/nfc.h"
#include "hardware/scale.h"
#include "hardware/scale_state.h"
#include "hardware/sd_logger.h"
#include "hardware/flash_log.h"
#include "services/nfc_reset.h"
#include "ui/reboot_popup.h"
#include "ui/info_popup.h"
#include "ui/nfc_reset_popup.h"
#include "services/auto_weight_state.h"
#include "services/location_state.h"
#include "web/web_server.h"
#include "services/remote_link.h"
#include "services/user_options.h"
#include "web/web_access.h"
#include "services/tag_write.h"
#include "hardware/sound.h"

#include "services/tag_link.h"
#include "ui/ota_github.h"
#include "ui/weight_button.h"
#include "services/ota_state.h"
#include "services/update_check.h"
#include "ui/ota_browser.h"
#include "ui/remote_link_popup.h"
#include "ui/tag_write_popup.h"
#include "services/ams_assign.h"
#include "services/spoolman_actions.h"
#include "services/backend_api.h"
#include "services/server_reach.h"
#include "services/server_refusal.h"
#include "services/spool_cache.h"
#include "services/uid_index.h"
#include "services/dried_batch.h"
#include "services/tag_field.h"
#include "services/bambuddy_device.h"
#include "services/ams_presence.h"
#include "services/ams_pick.h"
#include "ui/ams_detail_popup.h"
#include "ui/status_picker.h"
#include "ui/ams_view.h"
#include "services/wifi_manager.h"
#include "services/wifi_remote.h"
#include "services/wifi_roam.h"
#include "services/backend_job.h"
#include "services/ams_weights.h"
#include "services/improv_serial.h"
#include "services/setup_portal.h"
#include "ui/wifi_portal_screen.h"
#include "services/filaman_api.h"
#include "services/device_name.h"
#include "services/mdns_service.h"
#include "services/backend.h"
#include "services/backend_profiles.h"
#include "services/breadcrumb.h"
#include "services/diagnostics.h"
#include "hardware/i2c_scan.h"
#include "ui/diag_banner.h"
#include "ui/ams_assign_popup.h"
#include "ui/second_tag_popup.h"
#include "ui/ams_assign_screen.h"
#include "ui/filaman_fields_screen.h"
#include "ui/backend_screen.h"
#include "ui/online_screen.h"
#include "ui/filaman_options_screen.h"
#include "ui/bag_screen.h"
#include "ui/bambuddy_options_screen.h"
#include "ui/spoolman_options_screen.h"
#include "ui/tag_companion_screen.h"
#include "services/prefs_store.h"
#include "web/web_jobs.h"
#include "ui/confirm_popup.h"
#include "ui/tare_entry.h"
#include "ui/tare_missing_popup.h"
#include "ui/new_spool_done_popup.h"
#include "ui/weight_popup.h"
#include "services/weight_write_rules.h"
#include "ui/ble_devices_screen.h"
#include "ui/bluetooth_screen.h"
#include "ui/connection_screen.h"
#include "ui/dried_action.h"
#include "ui/drying_reminder_screen.h"
#include "ui/num_pad.h"
#include "ui/extra_fields_screen.h"
#include "ui/tag_field_screen.h"
#include "ui/timezone_screen.h"
#include "ui/language_screen.h"
#include "ui/factor_screen.h"
#include "ui/live_zone.h"
#include "ui/setup_done_screen.h"
#include "ui/header_status.h"
#include "ui/info_screen.h"
#include "ui/last_used_screen.h"
#include "ui/main_screen.h"
#include "ui/main_screen_helpers.h"
#include "ui/more_info_screen.h"
#include "ui/navigation.h"
#include "ui/ota_menu.h"
#include "ui/pc_print_popup.h"
#include "ui/printer_screen.h"
#include "ui/scale_menu.h"
#include "ui/settings_screen.h"
#include "ui/setup_welcome_screen.h"
#include "ui/spool_flow.h"
#include "ui/spoolman_lookup.h"
#include "ui/spoolman_screen.h"
#include "ui/wifi_setup_screen.h"
#include "ui/wifi_menu_screen.h"
#include "ui/system_screen.h"
#include "ui/tag_display.h"
#include "ui/tag_view.h"
#include "ui/weight_format.h"
#include "lang.h"
#include "ui/theme.h"
#include "ui/unknown_spool_popup.h"
#include "ui/spool_id_pad.h"
#include "ui/status_scroll.h"
#include "app/id_spool.h"
#include "ui/status_clear.h"
#include "app/wifi_fallback.h"
#include "ui/wifi_saved_screen.h"


namespace {
constexpr unsigned long NO_TAG_CLEAR_MS = 60000;

constexpr unsigned long LOC_DEBOUNCE_MS = 2500;
// With the drop confirmed the removal itself is settled, so this only covers
// a spool lifted to be set down again a moment later. It used to be 1200 ms,
// counted after the NFC grace period of 2.5 s: the question came four seconds
// after the lift (Nikolai, 27.09.2026: too slow).
constexpr unsigned long LOC_DEBOUNCE_FAST_MS = 500;

}  // namespace

// Weight while the tag was last actually readable. Frozen at the first miss,
// not at the point where the tag counts as removed: by then the spool may
// already be off the scale and the reference would have followed it down.
float loc_weight_ref   = 0.0f;
static bool  loc_weight_valid = false;

// Set on the first sample of a new tag presence, cleared when the tag is
// gone. Only used to know when a fresh spool has arrived.
static unsigned long loc_weight_since_ms = 0;

// The weight left the pad while the tag was unreadable. Proof that the next
// placement is a real one, which is what lets the location question be asked
// again for a spool that was already asked about once.
bool loc_left_pad = false;
// The reader lost the tag but the spool stayed: the questions were held back.
// They stay pending and fire when the weight goes, because the reader, having
// lost the tag already, will report no removal when the spool is lifted.
static bool loc_kept = false;
// The tag went silent but the weight on the pad did not move: the spool is
// still there, so it stays present (13.10.2026, hardware: tags read off-centre
// on a side-mounted reader stop answering after a few seconds). Released the
// moment the weight changes or the tag answers again. While set, the weight
// reference stays frozen at what the pad carried when the tag was last read.
bool tag_kept_by_weight = false;

// Did the spool actually leave, or did the reader merely lose the tag?
//
// Two callers ask exactly this: the location and AMS popups below, and the
// NTAG removal handler, which has to decide whether a returning tag is news.
// Written once here so the two can never answer it differently.
static bool weightSpeaks() {
  return loc_weight_valid && (loc_weight_ref >= LOC_WEIGHT_MIN_G);
}
// Still carrying what it carried while the tag was last readable.
bool weightSaysSpoolStayed() {
  if (!weightSpeaks()) return false;
  const float drop = loc_weight_ref - scale_weight_g;
  return (drop < LOC_WEIGHT_TOLERANCE_G) && (drop > -LOC_WEIGHT_TOLERANCE_G);
}
// Lost more than half the reference. Nothing but taking the spool off does that.
bool weightSaysSpoolGone() {
  if (!weightSpeaks()) return false;
  return (loc_weight_ref - scale_weight_g) > loc_weight_ref * LOC_WEIGHT_GONE_FRACTION;
}

namespace {
// A spool taken on for weighing through the FilaMan trigger when no tag ever
// turned up. Automatic weighing keys on tag_present, which is precisely what
// this case does not have, so the intent is carried here instead.
//
// It needs an end as much as a beginning. "No tag" is also the condition that
// clears auto_weight_done for the next spool, so marking the spool weighable without
// also saying when that stops would save it again on every pass through the
// loop, for as long as it sat there.
static bool aw_adopted      = false;
static bool aw_adopted_seen = false;   // a real load has been on the pad since

// The pad is too light for the spool whose tag is read: say so on the button,
// and in the log once per spool.
static void autoWeightNoSpool(float gross) {
  static int logged_id = 0;
  if (logged_id != sm_id) {
    logSDf("Auto-Weight: %.0f g is too light for spool %d (under %.0f g) - not on the pad, nothing written",
           gross, sm_id, AUTO_WEIGHT_EMPTY_PAD_G);
    logged_id = sm_id;
  }
  weightButtonShow(WL_NO_SPOOL);
}

// The spool has lain still long enough. What happens to the reading depends
// on how it compares with what the backend holds (Nikolai, 26.10.2026):
// heavier by more than AUTO_WEIGHT_RISE_G is held back and the button asks,
// since filament only ever leaves a spool; within AUTO_WEIGHT_MIN_CHANGE_G
// is the same value and costs no request; anything else is written. Never
// minus the bag: a spool in use is weighed bare, and the popup has the
// switch for the other case.
static void autoWeightSettled(float gross) {
  float netto = gross - (float)sm_spool_weight;
  if (netto < 0.0f) netto = 0.0f;
  const float diff = netto - sm_remaining;
  if (diff > AUTO_WEIGHT_RISE_G) {
    logSDf("Auto-Weight: spool %d reads %.0f g, %.0f g over the backend - not sent",
           sm_id, netto, diff);
    weightButtonShow(WL_RISE, diff);
    return;
  }
  const bool unchanged = fabsf(diff) < AUTO_WEIGHT_MIN_CHANGE_G;
  if (unchanged) {
    logSDf("Auto-Weight: spool %d unchanged at %.0f g - not sent", sm_id, netto);
    weightButtonShow(WL_UNCHANGED, netto);
    // No beep: nothing was updated, and a tag that keeps dropping out under
    // a spool lying still would otherwise beep on every return.
  }
  // The button says "sent" only once the server has the weight.
  const int code = unchanged ? 0 : patchSpoolmanWeight(netto);
  if (!unchanged) {
    weightButtonAfterWrite(code, netto);
    if (backendWriteOk(code)) soundPlay(SND_WEIGHT_OK);
    else if (code != PATCH_WEIGHT_ASKING) soundPlay(SND_WEIGHT_FAIL);
  }
  // Remembered either way, so a yes on removal can still open the window;
  // a value that has not gone out (unchanged, or refused) is sent by that yes.
  if (amsAskActive()) amsNoteMeasurement(sm_id, netto, gross, !unchanged && backendWriteOk(code));
  if (amsPickActive()) amsPickNote(sm_id, sm_filament_name);
}

// A gross weight that has demonstrably settled, tracked whether or not auto
// weighing is switched on. The AMS question reports this when nothing was
// weighed on purpose, and that value gets written to FilaMan - so it must not
// be a number the average was still chasing: within AUTO_WEIGHT_THRESH_G for
// AUTO_WEIGHT_STABLE_MS, stricter than the automatic weighing's own band.
static float         ams_settle_last  = -9999.0f;
static unsigned long ams_settle_since = 0;
static float         ams_settled_g    = 0.0f;
static bool          ams_settled_ok   = false;
constexpr unsigned long WIFI_RETRY_INTERVAL_MS = 10000;
// While the link is down the retries go on every 10 s, but the log gets the
// loss, then a line this often, then the reconnect. One line per retry filled
// the 240 line session ring in 40 minutes with nothing else.
constexpr unsigned long WIFI_OUTAGE_LOG_MS = 5UL * 60UL * 1000UL;
// What counts as nobody using the scale, for the roaming check: this long
// without a touch or a weight change, with the display dimmed or dark, and no
// browser on the web interface for WIFI_ROAM_WEB_QUIET_MS.
constexpr unsigned long WIFI_ROAM_IDLE_MS      = 10UL * 60UL * 1000UL;
constexpr unsigned long WIFI_ROAM_WEB_QUIET_MS = 2UL * 60UL * 1000UL;

// ── Scale on the bus ───────────────────────────────────────────────────────
// Bringing the ADC back is only attempted for one that dropped off or never
// came up at boot, and only a few times per loss or "Check again". A chip that answers on its address but
// never finishes its internal calibration - a dead load cell does that - would
// otherwise stall the loop for the three seconds scaleHardwareBegin() spends
// retrying, every five seconds, for as long as the device is switched on. A
// scale that stays down is bad; a device that hitches every five seconds and
// still has no scale is worse.
constexpr uint8_t SCALE_RECOVER_ATTEMPTS = 3;
static bool    scale_lost = false;
static uint8_t scale_recover_tries = 0;

}

// The WiFi setup screen scans for networks, and wifiManagerPrepareScan() calls
// WiFi.disconnect(true) first because scanNetworks() returns 0 after a failed
// WiFi.begin(). Nothing reconnects unless the user completes the whole setup
// flow, so merely opening that screen left the device offline until the next
// reboot and every Spoolman call failed with HTTPC_ERROR_CONNECTION_REFUSED.
// This watchdog restores the connection. WiFi.begin() is non-blocking, the
// association happens in the background and is picked up on a later pass.
// It stays out of the way while any WiFi setup screen is on display.
static bool wifiUiVisible() {
  return (scr_wifi_setup     && !lv_obj_has_flag(scr_wifi_setup,     LV_OBJ_FLAG_HIDDEN)) ||
         (scr_wifi_pass      && !lv_obj_has_flag(scr_wifi_pass,      LV_OBJ_FLAG_HIDDEN)) ||
         (scr_wifi_connecting && !lv_obj_has_flag(scr_wifi_connecting, LV_OBJ_FLAG_HIDDEN));
}

// The link as the watchdog last saw it, and the outage it is in, if any.
static bool          wifi_link_up         = false;
static bool          wifi_outage          = false;
static unsigned long wifi_outage_start_ms = 0;
static unsigned long wifi_outage_log_ms   = 0;
static uint32_t      wifi_outage_attempts = 0;

// One line when the link comes up: which access point, on which channel, how
// strong. With several access points on one SSID that is the first thing to
// know about any WiFi trouble.
static void noteWifiUp() {
  if (wifi_link_up) return;
  wifi_link_up = true;
  char line[64];
  wifiManagerLinkLine(line, sizeof(line));
  if (wifi_outage) {
    logSDf("WiFi: reconnected to %s after %lus and %u attempts, %s", cfg_wifi_ssid,
           (millis() - wifi_outage_start_ms) / 1000, (unsigned)wifi_outage_attempts, line);
  } else {
    logSDf("WiFi: connected to %s, %s", cfg_wifi_ssid, line);
  }
  wifi_outage = false;
}

static void noteWifiDown() {
  if (wifi_outage) return;
  // A boot that never got a link is no loss; only a link that was up is.
  if (wifi_link_up) soundPlay(SND_LINK_LOST);
  wifi_link_up = false;
  wifi_outage = true;
  wifi_outage_start_ms = millis();
  wifi_outage_log_ms = millis();
  wifi_outage_attempts = 0;
  const uint8_t reason = wifiManagerLastDisconnectReason();
  logSDf("WiFi: connection lost (reason %u, %s), reconnecting to %s",
         reason, wifiManagerReasonName(reason), cfg_wifi_ssid);
}

static bool wifiRoamQuiet();

static void handleWifiReconnect() {
  if (cfg_wifi_ssid[0] == '\0') return;
  // The browser is trying a network of its own; a begin() with the stored
  // one would cancel that attempt.
  if (improvSerialBusy()) return;
  // The setup portal's access point is the network while it runs.
  if (setupPortalActive()) return;
  if (wifiUiVisible()) return;
  // Joining the access point the roaming check chose. A begin() of our own
  // would cancel that; if it fails, the roaming check lets go.
  if (wifiRoamSwitching()) return;
  // Trying a network chosen in the browser, or scanning for its list.
  if (wifiRemoteBusy()) return;

  if (WiFi.status() == WL_CONNECTED) {
    noteWifiUp();
    // Remembers the network, and looks for the preferred one from another.
    wifiFallbackTick(true, wifiRoamQuiet());
    // Connected, but boot gave up before the network answered, so nothing that
    // a connection starts has run yet. The guards above apply here as well:
    // each of those flows sets wifi_ok on its own once it succeeds.
    if (!wifi_ok) {
      logSD("WiFi: connected after boot, starting network services");
      wifiOnConnected();
    }
    return;
  }

  noteWifiDown();
  // Gone for a while: another known network may be in range.
  if (wifiFallbackTick(false, false)) return;

  static unsigned long last_retry_ms = 0;
  if (last_retry_ms != 0 && millis() - last_retry_ms < WIFI_RETRY_INTERVAL_MS) return;
  last_retry_ms = millis();
  wifi_outage_attempts++;

  if (millis() - wifi_outage_log_ms >= WIFI_OUTAGE_LOG_MS) {
    wifi_outage_log_ms = millis();
    const uint8_t reason = wifiManagerLastDisconnectReason();
    logSDf("WiFi: still offline after %lu min, %u attempts, last reason %u (%s)",
           (millis() - wifi_outage_start_ms) / 60000, (unsigned)wifi_outage_attempts,
           reason, wifiManagerReasonName(reason));
  }
  // Through the manager rather than WiFi.begin(): the scan over every channel
  // that joins the strongest access point is set there. Called directly, the
  // core's fast scan went back to the first one it heard, every time.
  wifiManagerBegin(cfg_wifi_ssid, cfg_wifi_password);
}

// Nobody is using the scale, so a scan for a better access point cannot get
// in anyone's way. See services/wifi_roam.h.
static bool wifiRoamQuiet() {
  if (!displayIdleFor(WIFI_ROAM_IDLE_MS)) return false;
  if (webBrowserSeenWithin(WIFI_ROAM_WEB_QUIET_MS)) return false;
  if (improvSerialBusy() || setupPortalActive() || wifiUiVisible()) return false;
  if (wifiRemoteBusy()) return false;
  if (gh_flash_active || otaWebUploadActive() || updateCheckBusy()) return false;
  if (webJobState() == WJS_RUNNING || backendListBusy()) return false;
  if (amsWeightsBusy() || driedBatchBusy()) return false;
  return true;
}

static unsigned long tare_msg_ms = 0;
lv_obj_t *lbl_ok_ptr = nullptr;

unsigned long last_tag_seen_ms = 0;    // last NFC detection
static unsigned long last_scale_ms = 0;
static int  loc_popup_pending_id = -1;              // debounced popup: sm_id scheduled, fires after 1500ms
static int  ams_popup_pending_id = -1;              // same, for the AMS question; answered first when both are due
static int  pick_popup_pending_id = -1;             // same, for the AMS bay picker; only one of the three is ever set per backend

// A spool shown by its id has no tag to leave the reader, so its own lift
// raises the questions a lifted tag gets, by the same switches, and the block
// in appLoop() asks them as it does for a tag. The tag path is untouched.
// One rule is the id's own: the AMS question only follows a weight sent with
// "Update weight". The settled reading the tag path stands in would be a
// weight written, unasked, to a spool picked by a typed number.
static void idSpoolLiftQuestions() {
  float load_g = 0.0f;
  if (!idSpoolTakeLift(&load_g)) return;
  if (!wifi_ok || !sm_found || sm_archived || sm_id <= 0) return;
  // The block cross-checks the lift against what the pad carried, as for a tag.
  loc_weight_ref   = load_g;
  loc_weight_valid = true;
  loc_kept         = false;
  if (g_auto_loc_popup && g_loc_popup_shown_for_id != sm_id) loc_popup_pending_id = sm_id;
  if (amsAskActive() && amsHasPending() && amsPendingSpoolId() == sm_id) {
    ams_popup_pending_id = sm_id;
  }
  if (amsPickActive()) {
    if (!amsPickHasPending()) amsPickNote(sm_id, sm_filament_name);
    if (amsPickPendingSpoolId() == sm_id) pick_popup_pending_id = sm_id;
  }
  logSDf("IdSpool: spool %d lifted from %.0fg, asking location=%d ams=%d bay=%d", sm_id,
         load_g, (int)(loc_popup_pending_id > 0), (int)(ams_popup_pending_id > 0),
         (int)(pick_popup_pending_id > 0));
}

// See app_loop_shared.h. Beside idSpoolLiftQuestions(), which raises the same
// three questions for a spool shown by its id.
void onTagRemoved() {
  // Auto location popup: if enabled, spool is linked, and not shown for this spool yet
  // Debounce: only trigger after 1500ms - avoids spurious remove during NTAG read
  // Not for an archived spool: asking where to store something that
  // was just taken out of the inventory is a question about a spool
  // nobody is looking for.
  // None of the three questions below without a load cell. They hang
  // off the weight - it confirms the spool really left, and FilaMan's
  // needs it outright - and without one a removal is only a tag
  // leaving the reader, every time anyone looks at a spool. Zone 4's
  // AMS button and the location button ask the same on a tap.
  if (g_scale_fitted && g_auto_loc_popup && sm_found && !sm_archived && sm_id > 0 && wifi_ok &&
      g_loc_popup_shown_for_id != sm_id) {
    loc_popup_pending_id = sm_id;  // schedule - will fire after debounce in loop
    logSDf("[verbose] LOC: tag removed, popup scheduled id=%d (debounce 2500ms)", sm_id);
  } else if (g_scale_fitted && g_auto_loc_popup) {
    logSDf("[verbose] LOC: tag removed, popup suppressed id=%d shown_for=%d sm_found=%d wifi=%d", sm_id, g_loc_popup_shown_for_id, (int)sm_found, (int)wifi_ok);
  }
  // The AMS question hangs off the same removal, on the same
  // debounce and the same weight cross-check.
  // Same for the AMS question, and here it matters more than tidiness:
  // it notes a measurement against the spool id, which turns into a
  // weight write later on.
  if (g_scale_fitted && amsAskActive() && wifi_ok && sm_found && !sm_archived && sm_id > 0) {
    // On Serial, not through logSD(): that one returns early when no
    // SD card is present, so on a card-less scale none of this exists.
    Serial.printf("AMS: removal id=%d settled=%d %.0fg pending=%d\n",
                  sm_id, (int)ams_settled_ok, ams_settled_g, (int)amsHasPending());
    if (!amsHasPending() && ams_settled_ok && ams_settled_g >= LOC_WEIGHT_MIN_G) {
      // Nothing was weighed on purpose this time, so the settled
      // reading stands in for the report that never happened. That is
      // what makes the question independent of auto weighing.
      float ams_netto = ams_settled_g - (float)sm_spool_weight;
      if (ams_netto < 0) ams_netto = 0;
      amsNoteMeasurement(sm_id, ams_netto, ams_settled_g, false);
    } else if (!amsHasPending()) {
      Serial.printf("AMS: no usable weight, no question (needs >= %.0fg)\n",
                    (double)LOC_WEIGHT_MIN_G);
    }
    if (amsHasPending() && amsPendingSpoolId() == sm_id) {
      ams_popup_pending_id = sm_id;
      Serial.printf("AMS: question scheduled for id=%d\n", sm_id);
    }
  }
  // The bay picker hangs off the same removal. Its own branch rather
  // than a shared one: this flow has no measurement to stand in for
  // anything, it only needs to know which spool was just taken off.
  if (g_scale_fitted && amsPickActive() && wifi_ok && sm_found && !sm_archived && sm_id > 0) {
    if (!amsPickHasPending()) amsPickNote(sm_id, sm_filament_name);
    if (amsPickPendingSpoolId() == sm_id) {
      pick_popup_pending_id = sm_id;
      Serial.printf("AMSPICK: picker scheduled for id=%d\n", sm_id);
    }
  }
}

// The AMS button on a device without a load cell, one pass after the tap.
// Asked again rather than trusted: a spool can have left the screen between
// the tap and this pass.
static void amsMainAssignRun() {
  if (!amsMainCanAssign()) {
    logSD("AMS: button assign dropped, the spool is no longer offered");
    return;
  }
  if (backendCanAssignAmsSlot()) {
    amsPickOpenFor(sm_id, sm_filament_name);
    return;
  }
  // FilaMan. The stored weight stands in for a weighing: the value does not
  // change, the spool log gains one measurement, and the window opens.
  logSDf("AMS: no load cell, stored %.0fg reported to open the window for id=%d",
         sm_remaining, sm_id);
  amsNoteMeasurement(sm_id, sm_remaining, sm_remaining + sm_spool_weight, false);
  if (!amsCommitWithWindow()) {
    showInfoPopup(STR_AMSV_TITLE, STR_AMSV_ASSIGN_FAIL, INFO_WARN);
  }
}

void appLoop() {
  // Overwritten every pass, so a crumb from a marked section only stands while
  // that section runs. Three stores and a short copy into RTC memory.
  crumbSet("loop");
  // No lv_tick_inc() here: the tick comes from millis() via LV_TICK_CUSTOM, so
  // LVGL keeps correct time even while a blocking call holds up this loop.
  //
  // Settings changed by a button are parked while LVGL dispatches and written
  // the moment it is done, so no flash write runs inside an event callback.
  prefsDeferWrites(true);
  perfLoopMark();
  perfSection("ui");
  lv_timer_handler();
  perfUiDone();
  renderBenchTick();
  screenshotTick();
  perfSection("prefs");
  prefsDeferWrites(false);
  prefsFlush();
  perfSection("power");
  handlePowerManagement();

  // ── Stack watermark of the loop task ─────────────────────
  // uxTaskGetStackHighWaterMark reports the lowest free stack seen since
  // boot, in bytes. That is exactly what is needed here: the deepest moment
  // happens inside an LVGL callback, and by the time any logging runs the
  // stack is shallow again. The watermark still remembers it.
  //
  // The warning is deliberately outside the verbose guard. Running out of
  // stack is a panic reboot, not a detail, so it must show up in a normal log
  // as well. It fires once per new low so it cannot flood the file.
  static unsigned long last_stack_check_ms = 0;
  static uint32_t stack_min_bytes = 0xFFFFFFFF;
  if (millis() - last_stack_check_ms >= 2000) {
    last_stack_check_ms = millis();
    uint32_t free_stack = (uint32_t)uxTaskGetStackHighWaterMark(NULL);
    if (free_stack < stack_min_bytes) {
      bool was_ok = (stack_min_bytes >= 3072);
      stack_min_bytes = free_stack;
      if (free_stack < 3072) {
        logSDf("%s loop task stack down to %u bytes free",
               was_ok ? "STACK WARNING:" : "STACK:", (unsigned)free_stack);
      }
    }
  }

  // ── Loop heartbeat (checked every 5s, verbose only) ──────
  // Helps diagnose freezes: last heartbeat timestamp = roughly when loop
  // stopped. Checked at the old rate, but written only when it has something
  // to say. An idle scale repeats the same figures for hours, and a day of
  // that was 978 kB of a 1 MB log - 90 % of the heartbeat lines byte
  // identical to the one before, crowding out the 70 kB that showed what the
  // device actually did.
  //
  // RSSI deliberately takes no part in the decision. It jitters by a dB or
  // two continuously, so including it would mark every single line as
  // changed and save nothing. It is still printed on the lines that do get
  // written.
  static unsigned long last_heartbeat_ms = 0;
  static unsigned long last_hb_logged_ms = 0;
  static uint32_t heartbeat_count = 0;
  static bool     hb_have_prev    = false;
  static uint32_t hb_prev_heap    = 0;
  static uint32_t hb_prev_lv_int  = 0;
  static uint32_t hb_prev_lv_ps   = 0;
  static uint32_t hb_prev_stack   = 0;
  static uint32_t hb_prev_ps_allocs = 0;
  static bool     hb_prev_wifi    = false;
  if (sd_verbose && millis() - last_heartbeat_ms >= 5000) {
    last_heartbeat_ms = millis();
    heartbeat_count++;
    // LVGL takes its memory from the heap, internal RAM under a budget and
    // PSRAM past it (hardware/lvgl_mem.h). A screen leak shows as lv_int
    // climbing, a crowded heap as lv_psallocs rising.
    const LvMemStats lv_mem = lvMemStats();
    // Free blocks of the internal heap: how many pieces the free memory lies
    // in. With LVGL's blocks now in the same heap, this number and heap_big
    // are what shows fragmentation. One walk of the heap every 5 s.
    multi_heap_info_t heap_info;
    heap_caps_get_info(&heap_info, MALLOC_CAP_INTERNAL);
    bool wifi_up = (WiFi.status() == WL_CONNECTED);

    const uint32_t heap    = (uint32_t)ESP.getFreeHeap();
    const uint32_t stack   = (uint32_t)stack_min_bytes;

    // Small drifts are normal and not worth a line. A kilobyte is well below
    // anything that matters and well above the noise.
    auto moved = [](uint32_t a, uint32_t b) {
      return (a > b ? a - b : b - a) >= HEARTBEAT_QUIET_DELTA_B;
    };
    const bool changed = !hb_have_prev
                      || moved(heap, hb_prev_heap)
                      || moved(lv_mem.int_used, hb_prev_lv_int)
                      || moved(lv_mem.ps_used, hb_prev_lv_ps)
                      || stack < hb_prev_stack          // only ever falls
                      || lv_mem.ps_allocs != hb_prev_ps_allocs
                      || wifi_up != hb_prev_wifi;
    // A line every so often even when nothing moves, so that the last
    // timestamp still says how far the loop got before it stopped - which is
    // the whole point of a heartbeat.
    const bool due = (millis() - last_hb_logged_ms) >= HEARTBEAT_KEEPALIVE_MS;

    if (changed || due) {
      last_hb_logged_ms = millis();
      hb_have_prev    = true;
      hb_prev_heap    = heap;
      hb_prev_lv_int  = lv_mem.int_used;
      hb_prev_lv_ps   = lv_mem.ps_used;
      hb_prev_stack   = stack;
      hb_prev_ps_allocs = lv_mem.ps_allocs;
      hb_prev_wifi    = wifi_up;
      logSDf("[verbose] heartbeat #%u heap=%d PSRAM=%d uptime=%lus "
             "heap_big=%u heap_holes=%u lv_int=%u lv_peak=%u lv_used=%u%% lv_ps=%u "
             "lv_psallocs=%u stack_min=%u wifi=%s rssi=%d",
        heartbeat_count, ESP.getFreeHeap(), ESP.getFreePsram(), millis() / 1000,
        (unsigned)heap_info.largest_free_block, (unsigned)heap_info.free_blocks,
        (unsigned)lv_mem.int_used, (unsigned)lv_mem.int_peak,
        (unsigned)lv_mem.used_pct, (unsigned)lv_mem.ps_used,
        (unsigned)lv_mem.ps_allocs,
        (unsigned)stack_min_bytes,
        wifi_up ? "up" : "DOWN", wifi_up ? WiFi.RSSI() : 0);
      perfLogWindow();
    }
  }

  // Before the watchdog, so a connect attempt from the browser is already
  // known to be running when the watchdog asks.
  perfSection("improv");
  improvSerialTick();
  // DNS answers for the setup portal, and the hand-off of what its form sent.
  perfSection("portal");
  setupPortalTick();
  perfSection("wifi");
  handleWifiReconnect();
  // Not beside a scan of the network switching: both read the same results.
  if (!wifiFallbackBusy()) wifiRoamTick(wifiRoamQuiet(), cfg_wifi_ssid, cfg_wifi_password);
  // What the browser asked of the WiFi, once nothing else is on the radio.
  wifiRemoteTick(!improvSerialBusy() && !setupPortalActive() && !wifiUiVisible() &&
                 !wifiRoamBusy() && !wifiFallbackBusy());

  // OTA web server bedienen wenn aktiv
  perfSection("web");
  handleOtaServerClient();
  perfSection("tagwrite");
  tagWriteTick();
  tagLinkTick();
  // Says a freshly linked tag once more, so a paired browser opens the spool
  // instead of being left with the unknown-tag toast the first scan produced.
  perfSection("rescan");
  spoolmanRescanTick();
  // Asks again while an unknown tag sits on the pad, so linking it in a
  // browser shows up here without lifting the spool off and back on.
  perfSection("recheck");
  spoolmanRecheckTick();
  // Collects the inventory an unknown tag's lookup handed to the backend
  // worker, and reads the verdict out of it.
  perfSection("lookup");
  lookupScanTick();
  perfSection("sdlog");
  sdLoggerTick();
  // Keeps a sector erased ahead of the ring in flash, so a log line never
  // waits for one, and carries out a clear a sector at a time.
  perfSection("flashlog");
  flashLogTick();
  perfSection("jobs");
  webJobsTick();
  // Gives the kept spool list back once it is too old or was called off. Two
  // comparisons while there is none.
  spoolCacheTick();
  // The same for the identifiers the last full scan saw, which live two
  // minutes, and for an index a lookup opened and left unfinished.
  // Not while a scan still has to add its archive pass to an index it opened.
  if (!lookupScanBusy()) uidIndexTick();
  // And once the spool is known, whether the tag still says the same thing it
  // does. Costs a request only while the switch for it is on.
  tagMismatchTick();
  // While the credential screen is open the user types into the browser, so
  // the two rows have to follow along without a keypress on the device.
  refreshWebCredentialRows();

  // Background update check. Cheap: a few comparisons per pass, and the actual
  // request happens in its own task on the other core.
  perfSection("updchk");
  updateCheckTick();
  bambuCatalogSyncTick();
  dryingSyncTick();
  driedMigrateTick();
  backendConnTick();

  firmwareStampTick();
  otaWebGithubTick();

  // A confirmed downgrade. Same download and same restart as an update, only
  // it was asked about first.
  if (gh_downgrade_pending) {
    gh_downgrade_pending = false;
    doGithubOtaFlash(gh_latest_version);
  }
  if (gh_flash_pending) {
    gh_flash_pending = false;
    doGithubOtaFlash(gh_latest_version);
  }

  // A manual check that ran into the background task. Retried as soon as the
  // TLS connection is free again, dropped after GH_CHECK_WAIT_MS so a task that
  // never returns cannot leave the screen waiting on it.
  // The web worker holds a TLS connection of its own at times; two handshakes
  // at once want more internal heap than there is.
  if (gh_check_pending) {
    if (!updateCheckBusy() && webJobState() != WJS_RUNNING) {
      gh_check_pending = false;
      doGithubOtaCheck();
    } else if (millis() - gh_check_wait_since > GH_CHECK_WAIT_MS) {
      gh_check_pending = false;
      logSD("OTA check: gave up waiting for the background check");
    }
  }

  // Extra fields check/create - deferred from LVGL event callback to loop
  perfSection("deferred");
  handleExtraFieldsDeferredActions();
  handleSpoolmanScreenDeferredActions();
  // Before the WiFi setup actions: a form the portal handed over becomes their
  // connect in the same pass.
  handleWifiPortalDeferredActions();
  handleWifiSetupDeferredActions();
  wifiSavedScreenTick();
  wifiMenuScreenTick();
  handleBluetoothDeferredActions();
  handleBleDevicesDeferredActions();
  handlePrinterDeferredActions();
  handleConfirmPopupDeferredActions();
  handleDriedDeferredAction();
  // Bringing an archived spool back. Out here rather than in the button's
  // callback because it reaches the network, and it carries the weight the
  // button named so the screen and the database agree on one number.
  if (reactivate_pending) {
    reactivate_pending = false;
    if (!reactivateSpool(reactivate_weight_g)) {
      logSDf("Reactivate failed for spool %d", sm_id);
      if (lbl_status) {
        char buf[48];
        copyT(buf, sizeof(buf), STR_CU_NOT_WRITTEN);
        lv_label_set_text(lbl_status, buf);
        lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_BAD_TEXT), 0);
      }
    }
  }

  if (cal_reminder_pending) {
    cal_reminder_pending = false;
    // The setup's scale step, after its other screens have been freed. With
    // no load cell there is nothing to calibrate, so the chain ends here.
    if (g_scale_fitted) { releaseSetupScreens(); showFactorScreen(); }
    else                showSetupDoneScreen();
  }
  if (setup_done_pending) {
    setup_done_pending = false;
    showSetupDoneScreen();
  }
  if (cal_setup_back_pending) {
    cal_setup_back_pending = false;
    factorBackToSetupStep();
  }
  handleSpoolFlowDeferredActions();
  // After the flow's own actions, so a way the card opens is taken this pass.
  unknownSpoolTick();
  if (show_bag_pending) {
    show_bag_pending = false;
    showBagPad();
  }
  if (show_factor_pending) {
    show_factor_pending = false;
    showFactorScreen();
  }
  // "Check again" in the diagnosis popup. The bus probe belongs to the loop
  // task, so the popup only asked - this is where it happens. The full sweep
  // refreshes the line the status page and the boot log share; the diagnosis
  // re-evaluates on the same pass so the answer is on screen before the user
  // has let go of the button.
  if (i2c_rescan_pending) {
    i2c_rescan_pending = false;
    i2cScanRefresh(I2C_EXT);
    logSDf("I2C_EXT rescan (diagnosis): %s", i2cScanLast());
    // The second writer of scl_ok, and it has to ask the same question as the
    // 5 s probe: a chip that is wired but switched off in the settings must
    // not come back as present, or the header lights up again.
    if (g_scale_fitted) scl_ok = scaleHardwarePresent();
    // Someone who just touched the wiring gets a fresh set of attempts at
    // bringing the scale back, not the remainder of an old one. The 5 s
    // watchdog makes them, so the stall stays where it always was.
    if (scale_lost) scale_recover_tries = 0;
    diagnosticsRecheckNow();
    perfSection("diag");
  diagnosticsTick();
    updateDiagBanner();
    updateHeaderStatus();
  }
  // Confirmed on the scale menu. Rebuilt rather than patched: the calibration
  // row carries the factor in its subtitle, so the screen has to say the new
  // one - and that means deleting the screen the button lives on, which is
  // exactly what must not happen inside its own callback.
  if (cal_reset_pending) {
    cal_reset_pending = false;
    saveCalFactor(CAL_FACTOR_DEFAULT);
    saveTareOffset(0);
    resetScaleFilter();
    scale_weight_g = 0.0f;
    logSD("Calibration reset to defaults");
    // Asked for on the scale menu, which shows the factor in its row.
    scale_sub_rebuild_pending = true;
  }
  // A scale menu row changed a setting and wants the screen to say so. The
  // rebuild deletes the row that asked for it, so it cannot happen in that
  // row's own callback.
  if (scale_sub_rebuild_pending) {
    scale_sub_rebuild_pending = false;
    if (scr_scale_sub) {
      // So the row that was just tapped is still under the finger afterwards.
      scaleSubScrollRemember();
      lv_obj_del(scr_scale_sub); scr_scale_sub = nullptr;
      buildScaleSubScreen();
      lv_obj_clear_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN);
    }
  }
  if (live_zone_rebuild_pending) {
    live_zone_rebuild_pending = false;
    rebuildLiveZone();
  }
  // After the rebuild above, never before it: that one hides every overlay.
  if (show_reboot_pending) {
    show_reboot_pending = false;
    showRebootPopup();
  }
  // Asked before a weight lands that BamBuddy would clamp. Built here because
  // the write path that noticed it must not create a screen.
  if (show_bb_cap_pending) {
    show_bb_cap_pending = false;
    showBamBuddyCapPopup(bb_cap_measured_g, bb_cap_label_g);
  }
  if (show_drying_reminder_pending) {
    show_drying_reminder_pending = false;
    numPadDropParked();   // the threshold pad, if it led back here
    showDryingReminderScreen();
    lv_obj_clear_flag(scr_drying_reminder, LV_OBJ_FLAG_HIDDEN);
  }
  if (dry_pad_pending >= 0) {
    const int target = dry_pad_pending;
    dry_pad_pending = -1;
    showDryingPad(target);
  }
  if (show_lastused_pending) {
    show_lastused_pending = false;
    // Always rebuild for fresh button states (active mode highlighting)
    if (scr_lastused) { lv_obj_del(scr_lastused); scr_lastused = nullptr; }
    buildLastUsedScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_lastused, LV_OBJ_FLAG_HIDDEN);
  }
  // The web asked for a different backend. Applied here rather than in the
  // handler, and before the screen rebuild below, so an open backend screen
  // redraws with the new mode instead of standing there stale.
  if (backend_mode_change_pending) {
    backend_mode_change_pending = false;
    backendApplyMode((BackendMode)pending_backend_mode);
    if (scr_backend && !lv_obj_has_flag(scr_backend, LV_OBJ_FLAG_HIDDEN)) {
      show_backend_pending = true;
    }
  }
  if (backend_profile_change_pending) {
    backend_profile_change_pending = false;
    backendApplyProfile(pending_backend_profile);
    if (scr_backend && !lv_obj_has_flag(scr_backend, LV_OBJ_FLAG_HIDDEN)) {
      show_backend_pending = true;
    }
  }
  // A row of the online page: the switch, then the browser for the key, in one
  // pass so the home screen does not flash in between.
  if (online_pick_pending) {
    online_pick_pending = false;
    const bool palette_moves = !setup_active && uiThemeFollowMoves(BACKEND_SPOOLMAN, pending_backend_profile);
    backendApplyProfile(pending_backend_profile);
    showOtaBrowserScreen(setup_active ? WEB_CTX_SETUP : WEB_CTX_BACKEND);
    if (palette_moves) {
      logSD("Theme: the backend switch moves the palette, restart offered");
      show_reboot_pending = true;
    }
  }
  // The same for the server set: the backend screen shows the new address.
  if (server_set_swap_pending) {
    server_set_swap_pending = false;
    backendApplySetSwap();
    if (scr_backend && !lv_obj_has_flag(scr_backend, LV_OBJ_FLAG_HIDDEN)) {
      show_backend_pending = true;
    }
  }
  if (server_access_change_pending) {
    server_access_change_pending = false;
    backendApplyAccessChange();
  }
  if (show_backend_pending) {
    show_backend_pending = false;
    buildBackendScreen();          // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_backend, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_online_pending) {
    show_online_pending = false;
    buildOnlineScreen();           // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_online, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_filaman_options_pending) {
    show_filaman_options_pending = false;
    buildFilaManOptionsScreen();   // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_filaman_options, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_spoolman_options_pending) {
    show_spoolman_options_pending = false;
    buildSpoolmanOptionsScreen();  // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_spoolman_options, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_tag_comp_pending) {
    show_tag_comp_pending = false;
    buildTagCompanionScreen();     // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_tag_comp, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_extra_fields_pending) {
    show_extra_fields_pending = false;
    // from_options so the back button returns to the switch that sent us here.
    showExtraFieldsScreen(false, /*from_options=*/true);
  }
  if (create_tag_field_pending) {
    create_tag_field_pending = false;
    // HTTP, so it happens here rather than in the button callback. The screen
    // is rebuilt afterwards either way: the row has to stop offering an action
    // that has already succeeded, and has to keep offering one that failed.
    int c = backendCreateSpoolField(cfg_spoolman_base, tagFieldKey(), 5000);
    logSDf("tag field: create '%s' HTTP %d", tagFieldKey(), c);
    show_tag_field_pending = true;
  }
  if (show_tag_field_pending) {
    show_tag_field_pending = false;
    buildTagFieldScreen();         // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_tag_field, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_bambuddy_options_pending) {
    show_bambuddy_options_pending = false;
    buildBamBuddyOptionsScreen();  // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_bambuddy_options, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_bambuddy_dried_pending) {
    show_bambuddy_dried_pending = false;
    buildBamBuddyDriedScreen();    // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_bambuddy_dried, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_tagwrite_pending) {
    show_tagwrite_pending = false;
    buildTagWriteScreen();         // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_tagwrite, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_timezone_pending) {
    show_timezone_pending = false;
    // The language screen is not part of the overlay set, so hiding the
    // overlays does not touch it. It has to go explicitly or it stays alive
    // underneath and comes back when this one is closed.
    closeLanguageScreen();
    buildTimeZoneScreen();         // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_timezone, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_language_pending) {
    show_language_pending = false;
    hideAllOverlays();
    // Rebuilt rather than revealed: the zone button has to show what was just
    // picked.
    showLanguageScreen();
  }
  if (show_welcome_pending) {
    show_welcome_pending = false;
    // Back from the zone picker to the setup's welcome, rebuilt to show the pick.
    buildFirstBootScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_first_boot, LV_OBJ_FLAG_HIDDEN);
  }
  if (ams_main_assign_pending) {
    ams_main_assign_pending = false;
    amsMainAssignRun();
  }
  if (show_ams_assign_pending) {
    show_ams_assign_pending = false;
    numPadDropParked();            // the window pad, if it led back here
    buildAmsAssignScreen();        // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_ams_assign, LV_OBJ_FLAG_HIDDEN);
  }
  if (ams_window_pad_pending) {
    ams_window_pad_pending = false;
    showAmsWindowPad();
  }
  if (show_filaman_fields_pending) {
    show_filaman_fields_pending = false;
    buildFilaManFieldsScreen();    // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_filaman_fields, LV_OBJ_FLAG_HIDDEN);
  }
  // An online service has its address on its own page, never on the pad.
  if (show_spoolman_pending && backendProfileIsOnline()) {
    show_spoolman_pending = false;
    show_online_pending = true;
  }
  if (show_spoolman_pending) {
    show_spoolman_pending = false;
    // Always rebuild - sp_ip_input is reset on entry
    closeSpoolmanScreen();
    buildSpoolmanScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_spoolman, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_connection_from_spoolman_pending) {
    show_connection_from_spoolman_pending = false;
    closeSpoolmanScreen();
    closeConnectionScreen();
    buildConnectionScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_wifi_menu_pending) {
    show_wifi_menu_pending = false;
    buildWifiMenuScreen();         // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_wifi_menu, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_bluetooth_pending) {
    show_bluetooth_pending = false;
    buildBluetoothScreen();        // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_bluetooth, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_ble_devices_pending) {
    show_ble_devices_pending = false;
    buildBleDevicesScreen();       // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_ble_devices, LV_OBJ_FLAG_HIDDEN);
    // A list that was never filled scans on the way in; the button in the
    // header is for scanning again.
    if (!bleDevicesScanned()) ble_scan_pending = true;
  }
  if (show_printer_pending) {
    show_printer_pending = false;
    buildPrinterScreen();          // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_printer, LV_OBJ_FLAG_HIDDEN);
  }
  // Shown once the device has settled, not during boot: a modal that appears
  // while the first screen is still assembling reads as a fault.
  static bool hint_checked = false;
  static bool nfc_hint_this_boot = false;
  if (!hint_checked && millis() > 12000) {
    hint_checked = true;
    if (nfcResetHintDue()) { showNfcResetHint(); nfc_hint_this_boot = true; }
  }
  // The storage note waits for a boot on which the reader has nothing to say,
  // except when an update was found that no longer fits: then it comes at
  // once, over whatever screen asked.
  if (hint_checked && partitionHintDue() &&
      (!nfc_hint_this_boot || partitionTooBigVersion()[0]))
    showPartitionHint();

  if (nfc_reset_probe_pending) {
    nfc_reset_probe_pending = false;
    // Runs here rather than in the button's own callback: the probe holds a
    // line low and talks to the reader over I2C, and that bus belongs to this
    // task.
    const bool works = nfcResetSelfTest();
    showInfoPopup(works ? STR_NFCRST_OK_TITLE  : STR_NFCRST_FAIL_TITLE,
                  works ? STR_NFCRST_OK_TEXT   : STR_NFCRST_FAIL_TEXT,
                  works ? INFO_DONE : INFO_WARN);
  }

  if (show_ota_pending) {
    show_ota_pending = false;
    if (scr_ota) { lv_obj_del(scr_ota); scr_ota = nullptr; }
    buildOtaScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_ota, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_info_pending) {
    show_info_pending = false;
    if (scr_info) { lv_obj_del(scr_info); scr_info = nullptr; }
    showInfoScreen();  // builds + shows scr_info
  }
  // Before the two screens that use it: it releases its overlay in one pass
  // and hands the answer over in the next, and the handler that acts on that
  // answer should see it in the same pass rather than the one after.
  perfSection("deferred2");
  handleStatusPickerDeferredActions();
  handleMoreInfoDeferredActions();
  pcPrintTick();
  handleAmsAssignDeferredActions();
  handleAmsViewDeferredActions();
  handleAmsDetailDeferredActions();
  handleTagViewDeferredActions();
  // A request found no server, see server_reach.h. After every handler above,
  // so the popup comes up over whatever the failed action left on screen, and
  // the header badge turns red now instead of on the next health check. An
  // info popup already showing keeps the request waiting for the next pass.
  if (!isInfoPopupOpen() && serverReachPopupTake()) {
    updateHeaderStatus();
    showInfoPopup(STR_SERVER_DOWN_TITLE, STR_SERVER_DOWN_TEXT, INFO_WARN);
  }
  // The server answered and said no, see server_refusal.h. The same wait.
  if (!isInfoPopupOpen()) {
    const ServerRefusal refused = serverRefusalPopupTake();
    if (refused != REFUSAL_NONE) {
      showInfoPopup(serverRefusalTitleId(refused), serverRefusalTextId(refused), INFO_WARN);
    }
  }
  if (weight_write_problem_pending != WEIGHT_WRITE_FINE && !isInfoPopupOpen()) {
    const uint8_t problem = weight_write_problem_pending;
    weight_write_problem_pending = WEIGHT_WRITE_FINE;
    if (problem == WEIGHT_WRITE_NO_TARE) showTareMissingPopup();
    else showInfoPopup(STR_WEIGHT_NOT_SAVED, STR_WEIGHT_NOT_SAVED_TEXT, INFO_WARN);
  }
  // Right after the card's own handler, so a batch that finished inline (as
  // it does in the simulator) is collected in the pass that started it.
  perfSection("ams");
  amsDetailBatchTick();
  amsPickTick();
  amsPresenceTick();
  // Watches the reader for the tag on the other flange while its question
  // stands. It has to run every pass, not only when something happened: the
  // countdown is what it is mostly doing.
  handleSecondTagDeferredActions();
  // Before the questions below: a spool lifted while its empty weight is being
  // typed in takes the entry down unsaved first, and is asked about after.
  tareEntryTick();
  weightPopupTick();
  tareMissingTick();
  newSpoolDoneTick();
  spoolIdPadTick();
  idSpoolTick();
  idSpoolLiftQuestions();
  if (!tag_present && weightSaysSpoolGone()) loc_left_pad = true;
  // Debounced popups after a removal, cross-checked against the scale.
  // The AMS question and the location question hang off the same event, so
  // the verdict is worked out once and the AMS side gets it first: a spool
  // on its way into a printer has no shelf worth asking about. The "no"
  // branch of that popup raises the location question again.
  // Held, not dropped, while the empty spool weight is being entered: the
  // questions wait for that dialog like for any other modal.
  if ((loc_popup_pending_id > 0 || ams_popup_pending_id > 0 ||
       pick_popup_pending_id > 0) && !tag_present &&
      !isTareEntryOpen() && !isSpoolWeightScopeOpen()) {
    const unsigned long since = millis() - last_tag_seen_ms;
    const bool weight_says_gone = weightSaysSpoolGone();
    const bool weight_says_stay = weightSaysSpoolStayed();

    // A clear drop needs no further waiting, the spool is demonstrably off.
    const bool due = loc_kept
      ? weight_says_gone   // held back: only the weight leaving ends it
      : (since >= LOC_DEBOUNCE_MS) || (weight_says_gone && since >= LOC_DEBOUNCE_FAST_MS);

    if (due && weight_says_stay) {
      // The reader lost the tag but the spool never moved. Typical for
      // NTAGs. Not a removal, so no popup yet - but the questions stay
      // pending rather than being dropped: this was the only removal event
      // the reader will report, and the real lift later must still ask.
      if (!loc_kept) {
        loc_kept = true;
        logSDf("LOC: popup held back, weight unchanged (%.0fg vs %.0fg), spool still on the scale",
               scale_weight_g, loc_weight_ref);
      }
    } else if (due) {
      loc_kept = false;
      int pending_id = loc_popup_pending_id;
      int ams_id     = ams_popup_pending_id;
      int pick_id    = pick_popup_pending_id;
      loc_popup_pending_id  = -1;
      ams_popup_pending_id  = -1;
      pick_popup_pending_id = -1;

      if (pick_id > 0 && amsPickHasPending() &&
                 amsPickPendingSpoolId() == pick_id) {
        logSDf("AMSPICK: asking after %lums id=%d (weight %.0fg -> %.0fg%s)",
               since, pick_id, loc_weight_ref, scale_weight_g,
               weight_says_gone ? ", removal confirmed" : ", no weight signal");
        amsPickShow();
      } else if (ams_id > 0 && amsHasPending() && amsPendingSpoolId() == ams_id) {
        logSDf("AMS: asking after %lums id=%d (weight %.0fg -> %.0fg%s)",
               since, ams_id, loc_weight_ref, scale_weight_g,
               weight_says_gone ? ", removal confirmed" : ", no weight signal");
        showAmsAssignPopup(ams_id, amsPendingNetto(), sm_filament_name,
                           amsPendingAlreadyReported());
      } else if (g_loc_popup_shown_for_id != pending_id && sm_id == pending_id) {
        logSDf("LOC: fired after %lums id=%d (weight %.0fg -> %.0fg%s)",
               since, pending_id, loc_weight_ref, scale_weight_g,
               weight_says_gone ? ", removal confirmed" : ", no weight signal");
        g_loc_popup_shown_for_id = pending_id;
        requestLocationPicker(true);
      } else {
        logSDf("[verbose] LOC: debounce cancelled id=%d shown_for=%d sm_id=%d",
               pending_id, g_loc_popup_shown_for_id, sm_id);
      }
    }
  }
  // Cancel pending popups if tag came back
  perfSection("tagstate");
  if (tag_present) {
    loc_kept = false;
    if (loc_popup_pending_id > 0) {
      logSDf("[verbose] LOC: debounce cancelled - tag back id=%d", loc_popup_pending_id);
      loc_popup_pending_id = -1;
    }
    if (ams_popup_pending_id > 0) {
      logSDf("[verbose] AMS: debounce cancelled - tag back id=%d", ams_popup_pending_id);
      ams_popup_pending_id = -1;
    }
    if (pick_popup_pending_id > 0) {
      logSDf("[verbose] AMSPICK: debounce cancelled - tag back id=%d",
             pick_popup_pending_id);
      pick_popup_pending_id = -1;
    }
  }

  // ── FilaMan remote link ──────────────────────────────────
  // A trigger arrived on /api/v1/rfid/write and is waiting for a tag. The web
  // handler only parked it, everything that talks HTTP or touches LVGL has to
  // happen here.
  if (remote_link_reject_pending) {
    remote_link_reject_pending = false;
    remoteLinkReportUnsupported("locations are not supported by this device");
  }
  if (remoteLinkPendingActive()) {
    resetActivityTimer();   // a remote trigger counts as activity
    if (isRemoteLinkPopupOpen()) {
      // The user is looking at the question. No timeout while they decide,
      // the answer reports the outcome either way. FilaMan's own frontend
      // stops polling after a minute regardless.
    } else if (remoteLinkPendingAgeMs() >= REMOTE_LINK_TIMEOUT_MS) {
      logSD("RemoteLink: timed out waiting for a tag");
      remoteLinkReport(false, nullptr, "timed out waiting for a tag");
      if (lbl_status) {
        char buf[48];
        copyT(buf, sizeof(buf), STR_REMOTE_LINK_TIMEOUT);
        lv_label_set_text(lbl_status, buf);
        lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_WARN), 0);
      }
    } else if (tag_present && !isConfirmPopupOpen() &&
               !isSpoolFlowIdInputOpen() && !isSpoolFlowLinkEntryOpen()) {
      showRemoteLinkPopup(remoteLinkPendingSpoolId());
    } else if (g_flm_tagless && !tag_present &&
               remoteLinkPendingAgeMs() >= REMOTE_LINK_TAGLESS_MS &&
               !isConfirmPopupOpen() && !isSpoolFlowIdInputOpen() &&
               !isSpoolFlowLinkEntryOpen()) {
      // No tag turned up. The spool was picked deliberately in the web UI, so
      // load it and let the scale weigh it instead of reporting a failure for
      // a spool that simply has no tag on it. Nothing is bound: this lasts
      // until the next scan, which is the same lifetime a scanned tag has.
      const int id = remoteLinkPendingSpoolId();
      logSDf("RemoteLink: no tag, adopting spool %d for weighing", id);
      remoteLinkReport(true, nullptr, nullptr);
      querySpoolmanById(id);
      // Weighable from here, by hand or on its own, until the pad is empty
      // again. Starting a fresh cycle as well, so a spool weighed before this
      // one does not leave its "already saved" behind.
      aw_adopted      = true;
      aw_adopted_seen = false;
      auto_weight_done = false;
      // Start the settling window here rather than inheriting one. A spool
      // that had already been sitting still for three seconds when the
      // trigger arrived would otherwise be written on the very first pass,
      // with no countdown on the button and no moment to put a tag on after
      // all. Now the quiet second and the countdown run from the adoption.
      auto_weight_stable_ms = millis();
      auto_weight_last_val  = scale_weight_g;
      if (lbl_status) {
        char buf[48];
        copyT(buf, sizeof(buf), STR_REMOTE_LINK_WEIGH);
        lv_label_set_text(lbl_status, buf);
        lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_GOOD), 0);
      }
    }
  }
  handleRemoteLinkDeferredActions();
  handleTagWritePopupDeferredActions();
  // A write from the web page just bound the tag on the reader to a spool.
  // Showing it is the confirmation that matters - the browser reports the
  // write, but the scale kept displaying whatever was there before.
  // A link from the tag page that wrote nothing ends the same way.
  int linked_id = tagWriteTakeLinkedSpool();
  if (!linked_id) linked_id = tagLinkTakeLinkedSpool();
  if (linked_id) {
    if (!isSpoolFlowIdInputOpen() && !isSpoolFlowLinkEntryOpen() &&
        !isConfirmPopupOpen()) {
      logSDf("TagWrite: showing spool %d after the link", linked_id);
      // Asked here, on the loop, so the tag page can read the answer from a
      // web handler without reaching the server: see backendSecondTagKnown().
      backendCanHoldSecondTag();
      tagLookupForget();
      querySpoolmanById(linked_id);
      spoolFlowAskSecondTag(linked_id);
    }
  }
  if (show_system_pending) {
    show_system_pending = false;
    // Coming back from OTA / Info / Language to System screen
    deleteOtaScreens();
    if (scr_info)        { lv_obj_del(scr_info);        scr_info        = nullptr; }
    if (scr_system)      { lv_obj_del(scr_system);      scr_system      = nullptr; }
    lbl_fw_badge = nullptr;
    buildSystemScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_system, LV_OBJ_FLAG_HIDDEN);
  }
  if (skip_setup_pending) {
    skip_setup_pending = false;
    if (scr_welcome)    { lv_obj_del(scr_welcome);    scr_welcome    = nullptr; }
    if (scr_first_boot) { lv_obj_del(scr_first_boot); scr_first_boot = nullptr; }
    showMainScreen();
  }
  if (finish_setup_pending) {
    finish_setup_pending = false;
    showMainScreen();
  }
  // Hide tare confirmation
  if (tare_msg_ms > 0 && millis() - tare_msg_ms > 800) {
    if (lbl_ok_ptr) { lv_obj_del(lbl_ok_ptr); lbl_ok_ptr = nullptr; }
    tare_msg_ms = 0;
  }

  // No-tag timer: clear display if no tag detected for too long.
  // Only clear if truly no tag present (tag_present=false).
  // This used to require sm_found, so a spool that is not in the backend left
  // its data on screen indefinitely. The timer applies to every tag now,
  // linked or not, and regardless of which backend is active. Setting
  // last_tag_seen_ms to 0 below keeps this a one-shot until the next tag.
  // A spool shown by its id has no tag to wait for and ends on its own terms.
  // A lifted one waits out the timer, or the clear button behind the status
  // text, which both kinds get: that button only ends the wait early.
  const bool lifted_shown = !tag_present && !idSpoolActive() && last_tag_seen_ms > 0;
  // Only over something to clear: the timer may still run for a display that
  // was emptied another way.
  const bool lifted_on_screen = lifted_shown && (sm_found || g_tag.uid_str[0]);
  statusClearSync(lifted_on_screen || idSpoolActive());
  if (lifted_shown &&
      (millis() - last_tag_seen_ms > NO_TAG_CLEAR_MS || statusClearTaken())) {
    // clearTagDisplay() drops sm_id, so the note loses the spool it refers
    // to. Nothing is lost by forgetting it, the weight was written already.
    if (amsHasPending() && !isAmsAssignPopupOpen()) amsDropPending();
    clearTagDisplay();
    last_tag_seen_ms = 0;
  }

  // Fill display with new tag data
  if (g_tag_ready) {
    g_tag_ready = false;
    g_tag_displayed = true;
    g_tag_shown_ms = millis();
    updateDisplay();
    // While the second tag question stands the tag belongs to it, in all four
    // places this test appears. The chip on the other flange is not a new
    // spool to look up - on a Bambu spool the lookup would merely repeat
    // itself, and a second NTAG would come back "not in Spoolman" and clear
    // sm_id, taking the target of the question away with it. Only the lookup
    // is held off; scanTag() still runs, because the popup needs the decoded
    // chip uid.
    if (!isSpoolFlowIdInputOpen() && !isSecondTagPopupOpen() &&
        strlen(g_tag.tray_uuid) == 32 && strcmp(g_tag.uid_str, spoolman_queried_uid) != 0) {
      querySpoolman(g_tag.tray_uuid, LOOKUP_FROM_BAMBU);
      strncpy(spoolman_queried_uid, g_tag.uid_str, sizeof(spoolman_queried_uid)-1);
      spoolman_queried_uid[sizeof(spoolman_queried_uid)-1] = '\0';
      if (!lookupPending()) lookupFollowUp(LOOKUP_FROM_BAMBU, g_tag.tray_uuid);
    }
  }

  // After 10s reset status line to "searching" (data stays visible!)
  if (g_tag_displayed && millis() - g_tag_shown_ms > 10000) {
    g_tag_displayed = false;
    lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
    lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(UI_COL_WARN), 0);  // yellow
    lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
    lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_WARN), 0);
  }

  // The ADC can leave the bus while the device is running - a plug working
  // loose is the usual way. Caught here rather than left to the 5 s probe
  // below, because until it is noticed the firmware invents weights: a failed
  // register read is all ones through Adafruit_BusIO, which available() reads
  // as "conversion ready" and read() as a sample of -1. Tare or calibrate on
  // that and the nonsense is stored for good.
  perfSection("scale");
  if (scale_ready && millis() - last_scale_ms >= 200 && !scaleHardwarePresent()) {
    last_scale_ms = millis();
    scale_ready = false;
    scl_ok = false;
    scale_lost = true;
    scale_recover_tries = 0;
    resetScaleFilter();
    scale_weight_g = 0.0f;
    if (lbl_scale_weight) lv_label_set_text(lbl_scale_weight, "---");
    updateHeaderStatus();
    Serial.printf("Scale: %s stopped answering, readings suspended\n", scaleHardwareName());
    logSDf("Scale: %s stopped answering", scaleHardwareName());
  }

  // NAU7802: read weight every 200ms and update labels.
  // The availability check matters when the loop stalls, for example during a
  // long NFC scan: without it the same ADC sample is read twice and counted
  // twice in the moving average below.
  if (scale_ready && millis() - last_scale_ms >= 200 && scaleHardwareAvailable()) {
    last_scale_ms = millis();
    int32_t raw = scaleHardwareReadRaw();
    float raw_g = (float)(raw - zero_offset) / cal_factor;

    // Moving average over SCALE_FILTER_SIZE readings
    scale_filter_buf[scale_filter_idx] = raw_g;
    scale_filter_idx = (scale_filter_idx + 1) % SCALE_FILTER_SIZE;
    if (scale_filter_idx == 0) scale_filter_full = true;
    int count = scale_filter_full ? SCALE_FILTER_SIZE : scale_filter_idx;
    float sum = 0;
    // Peak to peak of the same window, for free: the diagnosis and the
    // auto-tare need to know how far the readings scatter, and this loop
    // already walks every one of them to build the average.
    float lo = scale_filter_buf[0], hi = scale_filter_buf[0];
    for (int i = 0; i < count; i++) {
      const float v = scale_filter_buf[i];
      sum += v;
      if (v < lo) lo = v;
      if (v > hi) hi = v;
    }
    scale_weight_g = sum / count;

    // A window that is not full yet spans a tare or a fresh start, so its
    // spread says nothing about the wiring. Reported as zero until it fills,
    // which keeps the sustain timer from arming on the way up.
    diagnosticsNoteSample(scale_weight_g, scale_filter_full ? (hi - lo) : 0.0f);

    // A load appearing on the pad counts as activity, so the panel
    // comes back without having to touch it first.
    displayNoteWeight(scale_weight_g);

    // Empty-pad drift correction. Held off while anything could be on the pad
    // deliberately: a tag in range, a spool adopted without one, or a popup
    // that is about to use the weight, or the calibration screen, where the
    // zero the user just set has to hold until the factor is computed.
    const bool calibrating = scr_factor && !lv_obj_has_flag(scr_factor, LV_OBJ_FLAG_HIDDEN);
    // Nor while an empty spool is taken off by hand: the pad then reads near
    // zero with that very spool on it, and a re-zero would drop the spool.
    scaleAutoTareTick(!tag_present && !aw_adopted && !idSpoolActive() && !calibrating && !isConfirmPopupOpen() &&
                      !isTareEntryOpen() && !isSpoolWeightScopeOpen() && g_spool_offset_g == 0.0f,
                      scale_filter_full ? (hi - lo) : 0.0f);

    // Keep the reference fresh only while the tag is genuinely being read.
    // The guard used to ask nfc_absent_count, which is written to 0 at every
    // one of its sites and never incremented - so it was always true and the
    // reference followed the spool all the way down as it was lifted, which
    // also left the location cross-check below permanently mute.
    // nfc_fast_polls is the counter that actually rises on a missed read.
    if (tag_present && nfc_fast_polls == 0 && !tag_kept_by_weight) {
      if (loc_weight_since_ms == 0) {
        // A fresh presence: start the stability window over, and do not carry
        // the previous spool's settled value into it.
        loc_weight_since_ms = millis();
        ams_settle_last  = -9999.0f;
        ams_settle_since = 0;
        ams_settled_ok   = false;
      }
      loc_weight_ref   = scale_weight_g;
      loc_weight_valid = scale_filter_full;   // only once the average is filled

      // Kept up to date for as long as the pad stays still, so the stored
      // value is always the most recent settled one. The moment the spool is
      // lifted the reading moves and this stops updating, which is what makes
      // the last value safe to report.
      if (fabsf(scale_weight_g - ams_settle_last) > AMS_SETTLE_TOL_G) {
        ams_settle_last  = scale_weight_g;
        ams_settle_since = millis();
      } else if (ams_settle_since > 0 &&
                 millis() - ams_settle_since >= AMS_SETTLE_MS) {
        ams_settled_g  = scale_weight_g;
        ams_settled_ok = true;
        // Once per reading that actually changed. A pad standing still says
        // nothing, which is the point: the log has to stay quiet when the
        // scale is idle.
        static float logged_settle = -9999.0f;
        if (fabsf(ams_settled_g - logged_settle) > AMS_SETTLE_TOL_G) {
          logged_settle = ams_settled_g;
          // -0 g is what a bare pad reads as, and it looks like a fault.
          const float shown = (fabsf(ams_settled_g) < 0.5f) ? 0.0f : ams_settled_g;
          logSDf("Weight settled: %.0f g on the pad", shown);
        }
      }
    } else if (!tag_present) {
      // Only the presence marker is cleared. The settled value has to survive
      // this pass: the removal is declared further down in the same one.
      loc_weight_since_ms = 0;
    }

    char w_str[16];
    // Fix 4: show filament netto (without spool) as big scale value
    if (sm_spool_weight > 0) {
      float netto = scale_weight_g - sm_spool_weight;
      if (netto < 0) netto = 0;
      fmtG(w_str, sizeof(w_str), netto);
    } else {
      // No empty spool known for what is on the pad: the one taken off by
      // holding Tare, on the number shown only. scale_weight_g stays the
      // reading, so nothing written to a backend carries it.
      fmtG(w_str, sizeof(w_str), scale_weight_g - g_spool_offset_g);
    }
    lv_label_set_text(lbl_scale_weight, w_str);
    // Also update live weight in calibration screen if open
    if (lbl_factor_cal_weight && scr_factor && !lv_obj_has_flag(scr_factor, LV_OBJ_FLAG_HIDDEN)) {
      char cal_str[48];
      factorLiveText(cal_str, sizeof(cal_str), scale_weight_g);
      lv_label_set_text(lbl_factor_cal_weight, cal_str);
    }

    // Fix 4: update live/bag below, SM diff next to netto
    if (sm_found && sm_tare_source != TARE_NONE) {
      float netto = scale_weight_g - sm_spool_weight;
      if (netto < 0) netto = 0;

      // SM diff: filament netto vs Spoolman remaining
      if (lbl_raw_info && sm_remaining > 0) {
        float sm_diff = netto - sm_remaining;
        char sd_str[16];
        snprintf(sd_str, sizeof(sd_str), sm_diff >= 0 ? "+%.0f g" : "%.0f g", sm_diff);
        lv_label_set_text(lbl_raw_info, sd_str);
        lv_obj_set_style_text_color(lbl_raw_info,
          sm_diff >= 0 ? lv_color_hex(UI_COL_OK_TEXT_2) : lv_color_hex(UI_COL_BAD), 0);
      }

      // Live total (with spool)
      if (lbl_spoolman_dried) {
        char lt_str[16];
        fmtG(lt_str, sizeof(lt_str), scale_weight_g);
        lv_label_set_text(lbl_spoolman_dried, lt_str);
        lv_obj_set_style_text_color(lbl_spoolman_dried, lv_color_hex(UI_COL_VALUE_BLUE), 0);
      }
      // The spool weight behind the netto, so the sum is on the screen.
      // Only the bag-free layout has a row for it.
      if (lbl_spool_tare) {
        char st_str[16];
        fmtG(st_str, sizeof(st_str), sm_spool_weight);
        lv_label_set_text(lbl_spool_tare, st_str);
      }

      // Fix 4: ohne Beutel = live - spool - bag; fixed color like scale netto; diff green/red
      if (lbl_keys) {
        float ohne_beutel = scale_weight_g - sm_spool_weight - bag_weight_g;
        if (ohne_beutel < 0) ohne_beutel = 0;
        char b_str[16];
        fmtG(b_str, sizeof(b_str), ohne_beutel);
        lv_label_set_text(lbl_keys, b_str);
        lv_obj_set_style_text_color(lbl_keys, lv_color_hex(UI_COL_WARN), 0);  // same as scale netto

        // bag SM diff
        if (lbl_bag_sm_diff && sm_remaining > 0) {
          float bag_diff = ohne_beutel - sm_remaining;
          char bd_str[16];
          snprintf(bd_str, sizeof(bd_str), bag_diff >= 0 ? "+%.0f g" : "%.0f g", bag_diff);
          lv_label_set_text(lbl_bag_sm_diff, bd_str);
          lv_obj_set_style_text_color(lbl_bag_sm_diff,
            bag_diff >= 0 ? lv_color_hex(UI_COL_OK_TEXT_2) : lv_color_hex(UI_COL_BAD), 0);
        }
      }
    } else if (sm_found) {
      if (lbl_raw_info) lv_label_set_text(lbl_raw_info, "");
      if (lbl_bag_sm_diff) lv_label_set_text(lbl_bag_sm_diff, "");
      if (lbl_spoolman_dried) {
        char lt_str[16];
        fmtG(lt_str, sizeof(lt_str), scale_weight_g);
        lv_label_set_text(lbl_spoolman_dried, lt_str);
      }
      if (lbl_keys) lv_label_set_text(lbl_keys, "");
      // No spool weight on record: the dash says why netto equals total.
      if (lbl_spool_tare) lv_label_set_text(lbl_spool_tare, "-");
    } else {
      if (lbl_raw_info) lv_label_set_text(lbl_raw_info, "");
      if (lbl_bag_sm_diff) lv_label_set_text(lbl_bag_sm_diff, "");
      if (lbl_spoolman_dried) lv_label_set_text(lbl_spoolman_dried, "");
      if (lbl_keys) lv_label_set_text(lbl_keys, "");
      if (lbl_spool_tare) lv_label_set_text(lbl_spool_tare, "");
    }
  }

  // The adoption ends when the pad is empty again, or the moment a tag turns
  // up and takes over. Kept outside the g_auto_weight block on purpose: it
  // decides what the display is showing, and switching the automatic off must
  // not leave a spool adopted forever.
  if (aw_adopted) {
    if (tag_present) {
      aw_adopted = false;
    } else if (scale_weight_g >= LOC_WEIGHT_MIN_G) {
      aw_adopted_seen = true;          // something is really on there
    } else if (aw_adopted_seen) {
      logSD("RemoteLink: adopted spool taken off, weighing ends");
      aw_adopted = false;
    }
  }

  if (g_auto_weight) {
    // Spool taken off: ready for the next one.
    if (!tag_present && !aw_adopted && auto_weight_done) {
      auto_weight_done = false;
      auto_weight_stable_ms = 0;
      auto_weight_last_val = -9999.0f;
      weightButtonIdle();
    }

    // A spool adopted without a tag counts as present: it was picked
    // deliberately in the web UI, which says more about intent than a tag
    // lying on the reader does.
    // sm_archived is excluded on purpose: an archived spool reads 0 g by
    // definition, so weighing it silently would file a full spool as empty
    // stock. Bringing it back is a decision, and it has its own button.
    // Nor while an empty spool weight is being entered: the weighing would
    // be computed against the tare that is about to be replaced.
    if (!auto_weight_done && !isConfirmPopupOpen() && !isTareEntryOpen() && !isSpoolWeightScopeOpen() &&
        sm_found && !sm_archived && sm_id > 0 && scale_ready &&
        (tag_present || aw_adopted)) {
      const float cur = scale_weight_g;
      const unsigned long now = millis();
      if (auto_weight_stable_ms == 0 || fabsf(cur - auto_weight_last_val) > AUTO_WEIGHT_BAND_G) {
        // First look, or still moving: the window starts again, and a
        // countdown already on the button goes back to the waiting look.
        auto_weight_last_val = cur;
        auto_weight_stable_ms = now;
        weightButtonIdleIfWaiting();
      } else if (autoWeightPadTooLight(cur)) {
        // A tag held to the reader without its spool - a loose sticker, a
        // spool tilted off the pad - reads as present over an empty pad, and
        // used to file the spool as 0 g (16.10.2026, spool 27). No countdown,
        // nothing written: the button says the spool is missing, and the
        // window starts again with the next reading.
        autoWeightNoSpool(cur);
        auto_weight_stable_ms = now;
      } else {
        const unsigned long still_ms = now - auto_weight_stable_ms;
        if (still_ms >= AUTO_WEIGHT_QUIET_MS + AUTO_WEIGHT_STABLE_MS) {
          auto_weight_done = true;
          auto_weight_stable_ms = 0;
          autoWeightSettled(cur);
        } else if (still_ms >= AUTO_WEIGHT_QUIET_MS) {
          const float netto = cur - (float)sm_spool_weight;
          weightButtonShow(WL_COUNTING, netto < 0.0f ? 0.0f : netto);
          weightButtonFill(AUTO_WEIGHT_QUIET_MS + AUTO_WEIGHT_STABLE_MS - still_ms);
        }
      }
    } else if (!auto_weight_done && (tag_present || aw_adopted)) {
      // A spool is there but weighing is held off: a popup that uses the
      // weight, a scale that is not ready, a spool not looked up yet. The
      // window starts again afterwards; left running it would send the
      // moment the popup closed, without the quiet second or the countdown.
      if (auto_weight_stable_ms > 0) {
        auto_weight_stable_ms = 0;
        auto_weight_last_val = -9999.0f;
        weightButtonIdleIfWaiting();
      }
    } else if (!auto_weight_done && !tag_present && !idSpoolActive()) {
      // No spool, no countdown: the idle look.
      // Not for a spool shown by its id: nothing is saved on its own there.
      if (auto_weight_stable_ms > 0) {
        auto_weight_stable_ms = 0;
        auto_weight_last_val = -9999.0f;
      }
      // While a window is running the button belongs to its countdown. A new
      // spool takes it back, which is right: that one matters more.
      if (!amsWindowOpen()) weightButtonIdle();
    }
  } else {
    // Auto off: keep the timer clean.
    if (auto_weight_stable_ms > 0) {
      auto_weight_stable_ms = 0;
      auto_weight_last_val = -9999.0f;
    }
  }

  // The offer goes stale when the spool is left sitting on the pad. Only the
  // note is dropped, the weight went out when it was measured.
  if (amsHasPending() && !isAmsAssignPopupOpen() &&
      amsPendingAgeMs() > AMS_PENDING_MAX_MS) {
    logSDf("AMS: offer expired after %lums, forgotten", amsPendingAgeMs());
    amsDropPending();
  }

  // Assignment window countdown, in the status line. It belongs there and not
  // on the weight button: that button is never disabled, its callback does not
  // read its label, so anything written on it turns into a weight popup on the
  // next tap. The status line is the place that says what is happening right
  // now, and a tag arriving overwrites it on its own - which is correct, the
  // new spool matters more than a window that keeps running anyway.
  {
    static int  ams_last_shown_s = -1;
    static bool ams_owns_status = false;
    const bool open = amsWindowOpen() && !tag_present;
    if (open) {
      const int rem = amsWindowRemainingS();
      if (rem != ams_last_shown_s && lbl_status) {
        ams_last_shown_s = rem;
        ams_owns_status = true;
        char wbuf[48];
        snprintf(wbuf, sizeof(wbuf), T(STR_AMS_WINDOW_RUNNING), rem);
        lv_label_set_text(lbl_status, wbuf);
        lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_WARN), 0);
      }
    } else if (ams_owns_status) {
      // Hand the line back once, not on every pass. Only when the pad is still
      // empty: with a tag on it the NFC branch owns the line already.
      ams_owns_status = false;
      ams_last_shown_s = -1;
      if (lbl_status && !tag_present && !idSpoolActive()) {
        lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
        lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_WARN), 0);
      }
    }
  }

  // The AMS button without a load cell: its caption follows the spool on
  // screen, and its fill the window the button opened. Another spool on
  // screen means the last one is dealt with, so its countdown ends and the
  // button is free for the new one; a new window replaces the old on the
  // server anyway. Only without a load cell, where the button opened it.
  if (!g_scale_fitted && amsWindowOpen() && sm_found && sm_id != amsWindowSpoolId()) {
    amsWindowEnd("another spool");
  }
  updateAmsMainButton();

  // Fix 10: Spoolman health check every 30s
  perfSection("netsvc");
  if (wifi_ok) {
    static unsigned long last_sm_check_ms = 0;
    if (millis() - last_sm_check_ms >= 30000 && !isSpoolFlowIdInputOpen()) {
      last_sm_check_ms = millis();
      int code = backendGetHealthCode(backendBaseUrl(), 3000);
      bool was_reachable = sm_reachable;
      sm_reachable = (code == 200);
      if (sm_reachable != was_reachable) updateHeaderStatus();
      if (sm_reachable && !was_reachable) serverReachRestored();
      if (!sm_reachable && was_reachable) serverReachLost();
      // What another service calls itself, asked once per address. The boot and
      // the address screen ask too, but a switch from the browser passes neither.
      static uint32_t s_name_asked_for = 0;
      if (sm_reachable && backendProfileWantsServerName() &&
          s_name_asked_for != backendGeneration() + 1) {
        s_name_asked_for = backendGeneration() + 1;
        char ver[32];
        backendGetVersion(backendBaseUrl(), ver, sizeof(ver), 3000);
      }
      // Someone can switch BamBuddy's filament manager while the scale is
      // running. That does not fail on our side, it just starts addressing
      // the other database - so the mode is re-asked here rather than only
      // at boot.
      // Not while a drying batch writes on the other core: its requests read
      // the inventory mode, and a refresh in their middle is a second writer.
      if (sm_reachable && !driedBatchBusy()) backendRefreshMode();
    }
  }

  // FilaMan presence. The server marks a device offline after 180 seconds
  // without a heartbeat, so this runs once a minute. Only sent when a device
  // token exists, otherwise it would fail on every pass.
  if (wifi_ok && backendIsFilaMan() && filamanDeviceToken()[0]) {
    static unsigned long last_hb_ms = 0;
    static bool last_hb_ok = false;
    if (last_hb_ms == 0 || millis() - last_hb_ms >= 60000) {
      last_hb_ms = millis();
      int code = filamanHeartbeat(backendBaseUrl(), filamanDeviceToken(),
                                  wifiManagerLocalIP().toString().c_str(), 4000);
      bool ok = (code == 200);
      // Only log on change, a line every minute would drown the log.
      if (ok != last_hb_ok) {
        logSDf("FilaMan: heartbeat %s (HTTP %d)", ok ? "OK" : "FAILED", code);
        last_hb_ok = ok;
      }
      // One corrective write once the server is known to be reachable. A
      // crash between the two PUTs of an AMS commit would otherwise leave
      // auto_assign_enabled standing, and "ask" or "off" would behave like
      // "always".
      static bool ams_reconciled = false;
      if (ok && !ams_reconciled) {
        ams_reconciled = true;
        amsBootReconcile();
      }
    }
  }

  // BamBuddy presence: registration, heartbeat, queued commands, live weight
  // and tag removal. Paces itself, so it is called unconditionally and costs
  // a mode check on the passes where it has nothing to do.
  perfSection("bambuddy");
  bambuddyDeviceTick();

  // The one owner of port 80. Derived from the conditions once a second, so
  // a flipped master switch, a backend switch, a freshly entered device
  // token and a returning WiFi all take effect without extra wiring.
  {
    static unsigned long last_web_sync_ms = 0;
    if (millis() - last_web_sync_ms >= 1000) {
      last_web_sync_ms = millis();
      webServerSyncState();
      // Right after, not before: the advertised _http._tcp service follows
      // whether the socket is actually listening.
      mdnsSyncState();
      // Last of the three: the address the interface prints depends on
      // whether the responder came up, and the DNS check on the address.
      deviceNameTick();
    }
  }

  // Periodic NAU7802 I2C ping every 5s (independent of WiFi), and the way
  // back: a chip that returns has been through a power cycle, so it lost its
  // LDO, gain and rate settings and has to be set up again. Same shape as the
  // NFC reader watchdog further down - the alternative is a device that stays
  // dead until someone restarts it, over a plug that is already seated again.
  {
    static unsigned long last_scl_check_ms = 0;
    // A scale that failed at boot counts as lost from the first pass on. It
    // used to be skipped, so a plug pushed back in after the diagnosis said
    // "NAU7802 missing" only took effect after a restart. Decided once, here:
    // a scale switched on in the settings later is still the restart's job,
    // because the home screen was built without it.
    static bool boot_state_seen = false;
    if (!boot_state_seen) {
      boot_state_seen = true;
      if (g_scale_fitted && !scale_ready) scale_lost = true;
    }
    // Nothing to find and nothing to bring back on a device that was built
    // without the load cell, so the bus is left alone entirely.
    if (g_scale_fitted && millis() - last_scl_check_ms >= 5000) {
      last_scl_check_ms = millis();
      bool prev = scl_ok;
      scl_ok = scaleHardwarePresent();
      if (scl_ok && !scale_ready && scale_lost &&
          scale_recover_tries < SCALE_RECOVER_ATTEMPTS) {
        scale_recover_tries++;
        // The callback keeps the UI alive: the internal calibration can take
        // up to three seconds, and this runs in the loop task.
        if (scaleHardwareBegin(&I2C_EXT, [](){ delay(100); lv_timer_handler(); })) {
          scale_ready = true;
          scale_lost = false;
          resetScaleFilter();
          Serial.printf("Scale: %s back\n", scaleHardwareName());
          logSDf("Scale: %s recovered", scaleHardwareName());
        } else {
          scl_ok = false;
          Serial.printf("Scale: re-init failed (%u/%u)\n",
                        scale_recover_tries, SCALE_RECOVER_ATTEMPTS);
          logSDf("Scale: re-init failed (%u/%u)",
                 scale_recover_tries, SCALE_RECOVER_ATTEMPTS);
        }
      }
      if (scl_ok != prev) updateHeaderStatus();
    }
  }

  tagReaderRecoverTick();

  // What the device would tell its owner if it could talk. Paces itself, so it
  // is called unconditionally; the banner call below is a compare on every
  // pass where the finding has not changed.
  diagnosticsTick();
  updateDiagBanner();
  // A status message too long for its line scrolls now and then (status_scroll.h).
  statusScrollTick();

  tagScanTick();

  // The button bar is derived state (tag_present && !sm_found) but used to be
  // recomputed only as a side effect of a backend lookup. A tag put back with
  // an unchanged UID never re-queries, so after a cancelled link flow the pair
  // stayed gone for good. Driven from the live state it cannot get stuck; the
  // edge check keeps it from invalidating four LVGL objects every pass.
  {
    static int link_bar_state = -1;
    // A lookup waiting for its inventory is a state of its own: no buttons
    // until the verdict is in, see updateLinkButton().
    // Nothing on screen at all is the fourth: "Spool by ID" in the left slot.
    const int s = (tag_present && lookupPending()) ? 2
                : (tag_present && !sm_found)       ? 1
                : (!tag_present && !sm_found)      ? 3 : 0;
    if (s != link_bar_state) { link_bar_state = s; updateLinkButton(); }
  }

  perfSection("tail");
  delay(5);
}
