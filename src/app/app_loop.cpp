#include "app_loop.h"

#include <Arduino.h>
#include <WiFi.h>
#include <Wire.h>
#include <lvgl.h>
#include <cmath>
#include <cstring>

#include "app_config.h"
#include "app/app_boot.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "bambu/bambu_scan.h"
#include "bambu/bambu_tag.h"
#include "hardware/display_power.h"
#include "hardware/nfc.h"
#include "hardware/scale.h"
#include "hardware/sd_logger.h"
#include "hardware/spoolscale_tag.h"
#include "services/auto_weight_state.h"
#include "services/location_state.h"
#include "services/ota_web_server.h"
#include "services/remote_link.h"
#include "services/user_options.h"
#include "ui/ota_github.h"
#include "services/update_check.h"
#include "ui/ota_browser.h"
#include "ui/remote_link_popup.h"
#include "services/ams_assign.h"
#include "services/spoolman_actions.h"
#include "services/backend_api.h"
#include "services/bambuddy_device.h"
#include "services/wifi_manager.h"
#include "services/filaman_api.h"
#include "services/backend.h"
#include "ui/ams_assign_popup.h"
#include "ui/ams_assign_screen.h"
#include "ui/backend_screen.h"
#include "ui/filaman_options_screen.h"
#include "ui/bag_screen.h"
#include "ui/cal_reminder_screen.h"
#include "ui/bambuddy_options_screen.h"
#include "ui/spoolman_options_screen.h"
#include "ui/confirm_popup.h"
#include "ui/connection_screen.h"
#include "ui/dried_action.h"
#include "ui/drying_reminder_screen.h"
#include "ui/extra_fields_screen.h"
#include "ui/factor_screen.h"
#include "ui/header_status.h"
#include "ui/info_screen.h"
#include "ui/last_used_screen.h"
#include "ui/main_screen.h"
#include "ui/main_screen_helpers.h"
#include "ui/more_info_screen.h"
#include "ui/navigation.h"
#include "ui/ota_menu.h"
#include "ui/scale_menu.h"
#include "ui/settings_screen.h"
#include "ui/setup_welcome_screen.h"
#include "ui/spool_flow.h"
#include "ui/spoolman_lookup.h"
#include "ui/spoolman_screen.h"
#include "ui/system_screen.h"
#include "ui/tag_display.h"
#include "ui/weight_format.h"
#include "lang.h"

namespace {
constexpr unsigned long NO_TAG_CLEAR_MS = 60000;

// ── Weight cross-check for the location-on-removal popup ────────
//
// The NFC reader loses an NTAG now and then even when the spool has not
// moved, and every one of those glitches used to look like a removal. The
// scale is a second, independent witness: if the spool is still sitting on
// it, the weight has not changed, and there was no removal no matter what
// the reader says.
//
// Below this the scale carries nothing meaningful, so it cannot testify
// either way and the timer alone decides, exactly as before.
constexpr float LOC_WEIGHT_MIN_G = 50.0f;
// Noise of the moving average plus a nudge of the table.
constexpr float LOC_WEIGHT_TOLERANCE_G = 30.0f;
// Losing more than half the reference is unambiguous: nothing but taking the
// spool off does that. Then the popup need not wait for the full debounce.
constexpr float LOC_WEIGHT_GONE_FRACTION = 0.5f;
constexpr unsigned long LOC_DEBOUNCE_MS = 2500;
// The filter averages 8 samples at 200 ms, so after 1200 ms it has taken in
// six readings of the new weight. That is far more than enough to tell a
// removed spool from a flickering tag.
constexpr unsigned long LOC_DEBOUNCE_FAST_MS = 1200;

// Weight while the tag was last actually readable. Frozen at the first miss,
// not at the point where the tag counts as removed: by then the spool may
// already be off the scale and the reference would have followed it down.
static float loc_weight_ref   = 0.0f;
static bool  loc_weight_valid = false;

// Set on the first sample of a new tag presence, cleared when the tag is
// gone. Only used to know when a fresh spool has arrived.
static unsigned long loc_weight_since_ms = 0;

// A gross weight that has demonstrably settled, tracked whether or not auto
// weighing is switched on. The AMS question reports this when nothing was
// weighed on purpose, and that value gets written to FilaMan - so it must not
// be a number the average was still chasing. Same criterion the auto weight
// path uses: within AUTO_WEIGHT_THRESH_G for AUTO_WEIGHT_STABLE_MS.
static float         ams_settle_last  = -9999.0f;
static unsigned long ams_settle_since = 0;
static float         ams_settled_g    = 0.0f;
static bool          ams_settled_ok   = false;
constexpr int NFC_MAX_RETRIES = 5;
constexpr unsigned long WIFI_RETRY_INTERVAL_MS = 10000;

// ── NFC polling (v0.6.1-beta) ──────────────────────────────────────────────
// A single missed read used to count as a miss straight away. NTAG couples
// more weakly than Bambu's MIFARE Classic, so those single dropouts are common
// even when the spool has not moved. Instead of retrying inside the same loop
// pass - which would block lv_timer_handler() for twice the timeout - a miss
// shortens the next poll interval. Every retry is therefore a separate loop
// pass and the UI keeps running between them.
constexpr unsigned long NFC_POLL_SLOW_MS   = 500;
constexpr unsigned long NFC_POLL_FAST_MS   = 60;
constexpr uint16_t      NFC_TIMEOUT_SLOW_MS = 150;
constexpr uint16_t      NFC_TIMEOUT_FAST_MS = 100;
// Raised from 5 to 7 after hardware testing: three of four recovered dropouts
// needed all five attempts and ran 1.2 to 1.4 s, so the old limit was only
// just sufficient. Costs nothing when reads succeed.
constexpr int           NFC_FAST_POLL_MAX   = 7;

// Removal is decided on elapsed time, not on a miss count. With a variable
// poll interval a count no longer maps to a fixed duration.
constexpr unsigned long NFC_ABSENT_BAMBU_MS = 1500;
constexpr unsigned long NFC_ABSENT_NTAG_MS  = 2500;

// An idle reader misses continuously because there is simply no tag, so a
// blind re-init after N misses would fire every few seconds while the scale
// sits empty. Probe first, and only re-init when the probe fails.
constexpr int NFC_HEALTHCHECK_AFTER_MISSES = 60;

// Aggregate NFC statistics go to the SD log on this interval, and only when
// verbose logging is on. Per-event lines stay on Serial.
constexpr unsigned long NFC_STATS_LOG_INTERVAL_MS = 300000;

// A Bambu tag that will not authenticate used to be retried back to back, and
// a full failing scan takes several seconds. Five of those in a row froze the
// UI for roughly 17 seconds. Hammering a tag that is not responding does not
// help it, so the retries are spaced out.
constexpr unsigned long NFC_BAMBU_RETRY_BACKOFF_MS = 1500;

// A tag that has used up its retries must stay given up on. Clearing the retry
// counter on every removal let a tag that never authenticates restart the
// count each time and re-scan forever. The counter is only cleared once the
// tag has really been gone for a while, or when a different tag shows up.
constexpr unsigned long NFC_RETRY_RESET_ABSENT_MS = 10000;
}

// The WiFi setup screen scans for networks, and wifiManagerPrepareScan() calls
// WiFi.disconnect(true) first because scanNetworks() returns 0 after a failed
// WiFi.begin(). Nothing reconnects unless the user completes the whole setup
// flow, so merely opening that screen left the device offline until the next
// reboot and every Spoolman call failed with HTTPC_ERROR_CONNECTION_REFUSED.
// This watchdog restores the connection. WiFi.begin() is non-blocking, the
// association happens in the background and is picked up on a later pass.
// It stays out of the way while any WiFi setup screen is on display.
static void handleWifiReconnect() {
  if (cfg_wifi_ssid[0] == '\0') return;
  if (WiFi.status() == WL_CONNECTED) return;

  bool wifi_ui_visible =
    (scr_wifi_setup     && !lv_obj_has_flag(scr_wifi_setup,     LV_OBJ_FLAG_HIDDEN)) ||
    (scr_wifi_pass      && !lv_obj_has_flag(scr_wifi_pass,      LV_OBJ_FLAG_HIDDEN)) ||
    (scr_wifi_connecting && !lv_obj_has_flag(scr_wifi_connecting, LV_OBJ_FLAG_HIDDEN));
  if (wifi_ui_visible) return;

  static unsigned long last_retry_ms = 0;
  if (last_retry_ms != 0 && millis() - last_retry_ms < WIFI_RETRY_INTERVAL_MS) return;
  last_retry_ms = millis();

  logSDf("WiFi: connection lost, reconnecting to %s", cfg_wifi_ssid);
  WiFi.begin(cfg_wifi_ssid, cfg_wifi_password);
}

static unsigned long tare_msg_ms = 0;
lv_obj_t *lbl_ok_ptr = nullptr;

static unsigned long last_tag_seen_ms = 0;    // last NFC detection
static unsigned long last_bambu_retry_ms = 0; // backoff between Bambu re-scans
static unsigned long first_miss_ms = 0;       // start of the current detection gap
static unsigned long tag_absent_since_ms = 0; // when the last removal was declared
static unsigned long last_scale_ms = 0;
static int  loc_popup_pending_id = -1;              // debounced popup: sm_id scheduled, fires after 1500ms
static int  ams_popup_pending_id = -1;              // same, for the AMS question; answered first when both are due

void appLoop() {
  // No lv_tick_inc() here: the tick comes from millis() via LV_TICK_CUSTOM, so
  // LVGL keeps correct time even while a blocking call holds up this loop.
  lv_timer_handler();
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

  // ── Loop heartbeat (every 5s, verbose only) ──────────────
  // Helps diagnose freezes: last heartbeat timestamp = roughly when loop stopped
  static unsigned long last_heartbeat_ms = 0;
  static uint32_t heartbeat_count = 0;
  if (sd_verbose && millis() - last_heartbeat_ms >= 5000) {
    last_heartbeat_ms = millis();
    heartbeat_count++;
    // LVGL runs on its own pool (LV_MEM_SIZE), separate from the ESP heap.
    // Exhausting it triggers LV_ASSERT_MALLOC, which halts in while(1) with
    // no reboot and no panic output. Log it so screen leaks become visible.
    lv_mem_monitor_t lv_mem;
    lv_mem_monitor(&lv_mem);
    bool wifi_up = (WiFi.status() == WL_CONNECTED);
    logSDf("[verbose] heartbeat #%u heap=%d PSRAM=%d uptime=%lus "
           "lv_free=%u lv_biggest=%u lv_used=%u%% lv_frag=%u%% "
           "stack_min=%u wifi=%s rssi=%d",
      heartbeat_count, ESP.getFreeHeap(), ESP.getFreePsram(), millis() / 1000,
      (unsigned)lv_mem.free_size, (unsigned)lv_mem.free_biggest_size,
      (unsigned)lv_mem.used_pct, (unsigned)lv_mem.frag_pct,
      (unsigned)stack_min_bytes,
      wifi_up ? "up" : "DOWN", wifi_up ? WiFi.RSSI() : 0);
  }

  handleWifiReconnect();

  // OTA web server bedienen wenn aktiv
  handleOtaServerClient();
  // While the credential screen is open the user types into the browser, so
  // the two rows have to follow along without a keypress on the device.
  refreshWebCredentialRows();

  // Background update check. Cheap: a few comparisons per pass, and the actual
  // request happens in its own task on the other core.
  updateCheckTick();

  // A manual check that ran into the background task. Retried as soon as the
  // TLS connection is free again, dropped after GH_CHECK_WAIT_MS so a task that
  // never returns cannot leave the screen waiting on it.
  if (gh_check_pending) {
    if (!updateCheckBusy()) {
      gh_check_pending = false;
      doGithubOtaCheck();
    } else if (millis() - gh_check_wait_since > GH_CHECK_WAIT_MS) {
      gh_check_pending = false;
      logSD("OTA check: gave up waiting for the background check");
    }
  }

  // Extra fields check/create — deferred from LVGL event callback to loop
  handleExtraFieldsDeferredActions();
  handleDriedDeferredAction();
  if (cal_reminder_pending) {
    cal_reminder_pending = false;
    showCalReminderScreen();
  }
  handleSpoolFlowDeferredActions();
  if (show_bag_pending) {
    show_bag_pending = false;
    if (!scr_bag) buildBagScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_bag, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_factor_pending) {
    show_factor_pending = false;
    showFactorScreen();
  }
  // Asked before a weight lands that BamBuddy would clamp. Built here because
  // the write path that noticed it must not create a screen.
  if (show_bb_cap_pending) {
    show_bb_cap_pending = false;
    showBamBuddyCapPopup(bb_cap_measured_g, bb_cap_label_g);
  }
  if (show_drying_reminder_pending) {
    show_drying_reminder_pending = false;
    showDryingReminderScreen();
    lv_obj_clear_flag(scr_drying_reminder, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_lastused_pending) {
    show_lastused_pending = false;
    // Always rebuild for fresh button states (active mode highlighting)
    if (scr_lastused) { lv_obj_del(scr_lastused); scr_lastused = nullptr; }
    buildLastUsedScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_lastused, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_backend_pending) {
    show_backend_pending = false;
    buildBackendScreen();          // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_backend, LV_OBJ_FLAG_HIDDEN);
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
  if (show_ams_assign_pending) {
    show_ams_assign_pending = false;
    buildAmsAssignScreen();        // releases the previous instance itself
    hideAllOverlays();
    lv_obj_clear_flag(scr_ams_assign, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_spoolman_pending) {
    show_spoolman_pending = false;
    // Always rebuild — sp_ip_input is reset on entry
    if (scr_spoolman) { lv_obj_del(scr_spoolman); scr_spoolman = nullptr; }
    if (scr_spoolman_fail) { lv_obj_del(scr_spoolman_fail); scr_spoolman_fail = nullptr; }
    buildSpoolmanScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_spoolman, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_connection_from_spoolman_pending) {
    show_connection_from_spoolman_pending = false;
    if (scr_spoolman)   { lv_obj_del(scr_spoolman);   scr_spoolman   = nullptr; }
    if (scr_connection) { lv_obj_del(scr_connection); scr_connection = nullptr; }
    buildConnectionScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
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
  handleMoreInfoDeferredActions();
  handleAmsAssignDeferredActions();
  // Debounced popups after a removal, cross-checked against the scale.
  // The AMS question and the location question hang off the same event, so
  // the verdict is worked out once and the AMS side gets it first: a spool
  // on its way into a printer has no shelf worth asking about. The "no"
  // branch of that popup raises the location question again.
  if ((loc_popup_pending_id > 0 || ams_popup_pending_id > 0) && !tag_present) {
    const unsigned long since = millis() - last_tag_seen_ms;
    const float drop = loc_weight_ref - scale_weight_g;
    // Only meaningful when there was something on the scale to begin with.
    const bool weight_speaks = loc_weight_valid && (loc_weight_ref >= LOC_WEIGHT_MIN_G);
    const bool weight_says_gone = weight_speaks && (drop > loc_weight_ref * LOC_WEIGHT_GONE_FRACTION);
    const bool weight_says_stay = weight_speaks &&
                                  (drop < LOC_WEIGHT_TOLERANCE_G) && (drop > -LOC_WEIGHT_TOLERANCE_G);

    // A clear drop needs no further waiting, the spool is demonstrably off.
    const bool due = (since >= LOC_DEBOUNCE_MS) ||
                     (weight_says_gone && since >= LOC_DEBOUNCE_FAST_MS);

    if (due) {
      int pending_id = loc_popup_pending_id;
      int ams_id     = ams_popup_pending_id;
      loc_popup_pending_id = -1;
      ams_popup_pending_id = -1;

      if (weight_says_stay) {
        // The reader lost the tag but the spool never moved. Typical for
        // NTAGs. Not a removal, so no popup and no note that it was already
        // shown: the real removal later still deserves one. A parked
        // measurement stays parked for exactly the same reason.
        logSDf("LOC: popup suppressed, weight unchanged (%.0fg vs %.0fg), spool still on the scale",
               scale_weight_g, loc_weight_ref);
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
  if (tag_present) {
    if (loc_popup_pending_id > 0) {
      logSDf("[verbose] LOC: debounce cancelled - tag back id=%d", loc_popup_pending_id);
      loc_popup_pending_id = -1;
    }
    if (ams_popup_pending_id > 0) {
      logSDf("[verbose] AMS: debounce cancelled - tag back id=%d", ams_popup_pending_id);
      ams_popup_pending_id = -1;
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
        strncpy(buf, T(STR_REMOTE_LINK_TIMEOUT), sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        lv_label_set_text(lbl_status, buf);
        lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
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
      if (lbl_status) {
        char buf[48];
        strncpy(buf, T(STR_REMOTE_LINK_WEIGH), sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        lv_label_set_text(lbl_status, buf);
        lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
      }
    }
  }
  handleRemoteLinkDeferredActions();
  if (show_system_pending) {
    show_system_pending = false;
    // Coming back from OTA / Info / Language to System screen
    if (scr_ota)         { lv_obj_del(scr_ota);         scr_ota         = nullptr; }
    if (scr_ota_browser) { lv_obj_del(scr_ota_browser); scr_ota_browser = nullptr; }
    if (scr_ota_github)  { lv_obj_del(scr_ota_github);  scr_ota_github  = nullptr; }
    if (scr_info)        { lv_obj_del(scr_info);        scr_info        = nullptr; }
    if (scr_system)      { lv_obj_del(scr_system);      scr_system      = nullptr; }
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
    stopOtaServer();
    showMainScreen();
  }
  if (lang_selected_no_reboot) {
    lang_selected_no_reboot = false;
    if (scr_welcome) { lv_obj_del(scr_welcome); scr_welcome = nullptr; }
    showFirstBootScreen();
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
  if (!tag_present &&
      last_tag_seen_ms > 0 && millis() - last_tag_seen_ms > NO_TAG_CLEAR_MS) {
    // clearTagDisplay() drops sm_id, so the note loses the spool it refers
    // to. Nothing is lost by forgetting it, the weight was written already.
    if (amsHasPending() && !isAmsAssignPopupOpen()) amsDropPending();
    clearTagDisplay();
    last_tag_seen_ms = 0;
    spoolman_queried_uid[0] = '\0';
  }

  // Fill display with new tag data
  if (g_tag_ready) {
    g_tag_ready = false;
    g_tag_displayed = true;
    g_tag_shown_ms = millis();
    updateDisplay();
    if (!isSpoolFlowIdInputOpen() && strlen(g_tag.tray_uuid) == 32 && strcmp(g_tag.uid_str, spoolman_queried_uid) != 0) {
      querySpoolman(g_tag.tray_uuid);
      strncpy(spoolman_queried_uid, g_tag.uid_str, sizeof(spoolman_queried_uid)-1);
      spoolman_queried_uid[sizeof(spoolman_queried_uid)-1] = '\0';
      if (!sm_found && wifi_ok) {
        link_tag_first_seen_ms = millis();
        link_popup_dismissed = false;
      }
    }
  }

  // After 10s reset status line to "searching" (data stays visible!)
  if (g_tag_displayed && millis() - g_tag_shown_ms > 10000) {
    g_tag_displayed = false;
    lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
    lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0xf0b838), 0);  // yellow
    lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
    lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
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
    for (int i = 0; i < count; i++) sum += scale_filter_buf[i];
    scale_weight_g = sum / count;

    // A load appearing on the pad counts as activity, so the panel
    // comes back without having to touch it first.
    displayNoteWeight(scale_weight_g);

    // Keep the reference fresh only while the tag is genuinely being read.
    // The guard used to ask nfc_absent_count, which is written to 0 at every
    // one of its sites and never incremented - so it was always true and the
    // reference followed the spool all the way down as it was lifted, which
    // also left the location cross-check below permanently mute.
    // nfc_fast_polls is the counter that actually rises on a missed read.
    if (tag_present && nfc_fast_polls == 0) {
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
      fmtG(w_str, sizeof(w_str), scale_weight_g);
    }
    lv_label_set_text(lbl_scale_weight, w_str);
    // Also update live weight in calibration screen if open
    if (lbl_factor_cal_weight && scr_factor && !lv_obj_has_flag(scr_factor, LV_OBJ_FLAG_HIDDEN)) {
      char cal_str[16];
      fmtG(cal_str, sizeof(cal_str), scale_weight_g);  // Fix 6: raw weight
      lv_label_set_text(lbl_factor_cal_weight, cal_str);
    }

    // Fix 4: update live/bag below, SM diff next to netto
    if (sm_found && sm_spool_weight > 0) {
      float netto = scale_weight_g - sm_spool_weight;
      if (netto < 0) netto = 0;

      // SM diff: filament netto vs Spoolman remaining
      if (lbl_raw_info && sm_remaining > 0) {
        float sm_diff = netto - sm_remaining;
        char sd_str[16];
        snprintf(sd_str, sizeof(sd_str), sm_diff >= 0 ? "+%.0f g" : "%.0f g", sm_diff);
        lv_label_set_text(lbl_raw_info, sd_str);
        lv_obj_set_style_text_color(lbl_raw_info,
          sm_diff >= 0 ? lv_color_hex(0x40c080) : lv_color_hex(0xe04040), 0);
      }

      // Live total (with spool)
      if (lbl_spoolman_dried) {
        char lt_str[16];
        fmtG(lt_str, sizeof(lt_str), scale_weight_g);
        lv_label_set_text(lbl_spoolman_dried, lt_str);
        lv_obj_set_style_text_color(lbl_spoolman_dried, lv_color_hex(0x8ab0d8), 0);
      }

      // Fix 4: ohne Beutel = live - spool - bag; fixed color like scale netto; diff green/red
      if (lbl_keys) {
        float ohne_beutel = scale_weight_g - sm_spool_weight - bag_weight_g;
        if (ohne_beutel < 0) ohne_beutel = 0;
        char b_str[16];
        fmtG(b_str, sizeof(b_str), ohne_beutel);
        lv_label_set_text(lbl_keys, b_str);
        lv_obj_set_style_text_color(lbl_keys, lv_color_hex(0xf0b838), 0);  // same as scale netto

        // bag SM diff
        if (lbl_bag_sm_diff && sm_remaining > 0) {
          float bag_diff = ohne_beutel - sm_remaining;
          char bd_str[16];
          snprintf(bd_str, sizeof(bd_str), bag_diff >= 0 ? "+%.0f g" : "%.0f g", bag_diff);
          lv_label_set_text(lbl_bag_sm_diff, bd_str);
          lv_obj_set_style_text_color(lbl_bag_sm_diff,
            bag_diff >= 0 ? lv_color_hex(0x40c080) : lv_color_hex(0xe04040), 0);
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
    } else {
      if (lbl_raw_info) lv_label_set_text(lbl_raw_info, "");
      if (lbl_bag_sm_diff) lv_label_set_text(lbl_bag_sm_diff, "");
      if (lbl_spoolman_dried) lv_label_set_text(lbl_spoolman_dried, "");
      if (lbl_keys) lv_label_set_text(lbl_keys, "");
    }
  }

  // aw_done: einmal gespeichert -> kein weiterer Patch bis Spule abgenommen
  if (g_auto_weight) {
    static int  aw_last_shown_s = -1;  // verhindert unnoetige Label-Updates
    static bool aw_done = false;       // diese Spule bereits gespeichert?

    // Spule abgenommen -> Reset fuer naechste Spule
    if (!tag_present && aw_done) {
      aw_done = false;
      auto_weight_stable_ms = 0;
      auto_weight_last_val = -9999.0f;
      aw_last_shown_s = -1;
      if (lbl_weight_main_lbl) {
        char wmbuf[48];
        snprintf(wmbuf, sizeof(wmbuf), "%s (A)", T(STR_BTN_WEIGHT));
        lv_label_set_text(lbl_weight_main_lbl, wmbuf);
        lv_obj_set_style_text_color(lbl_weight_main_lbl, lv_color_hex(0x28d49a), 0);
      }
    }

    if (!aw_done && !isConfirmPopupOpen() && sm_found && sm_id > 0 && scale_ready && tag_present) {
      float cur = scale_weight_g;
      if (fabsf(cur - auto_weight_last_val) > AUTO_WEIGHT_THRESH_G) {
        // Gewicht bewegt sich -> Timer neu starten
        auto_weight_last_val = cur;
        auto_weight_stable_ms = millis();
        aw_last_shown_s = -1;
      } else if (auto_weight_stable_ms > 0 &&
                 millis() - auto_weight_stable_ms >= AUTO_WEIGHT_STABLE_MS) {
        // 3 Sekunden stabil -> einmalig speichern
        aw_done = true;
        auto_weight_stable_ms = 0;
        aw_last_shown_s = -1;
        float netto = cur - (float)sm_spool_weight;
        if (netto < 0) netto = 0;
        // Haekchen im Button — bleibt bis Spule abgenommen wird
        if (lbl_weight_main_lbl) {
          char wmbuf[48];
          snprintf(wmbuf, sizeof(wmbuf), "%s " LV_SYMBOL_OK, T(STR_BTN_WEIGHT));
          lv_label_set_text(lbl_weight_main_lbl, wmbuf);
          lv_obj_set_style_text_color(lbl_weight_main_lbl, lv_color_hex(0x40ff80), 0);
        }
        patchSpoolmanWeight(netto);
        // Remembered, not held back: the value is in FilaMan now, this only
        // lets a yes on removal report it once more to open the window.
        if (amsAskActive()) amsNoteMeasurement(sm_id, netto, cur, true);
      } else if (auto_weight_stable_ms == 0) {
        auto_weight_last_val = cur;
        auto_weight_stable_ms = millis();
      } else {
        // Countdown: sekuendlich Button-Text aktualisieren
        unsigned long elapsed = millis() - auto_weight_stable_ms;
        int rem = (int)((AUTO_WEIGHT_STABLE_MS - elapsed) / 1000) + 1;
        if (rem < 1) rem = 1;
        if (rem != aw_last_shown_s && lbl_weight_main_lbl) {
          aw_last_shown_s = rem;
          char wmbuf[48];
          snprintf(wmbuf, sizeof(wmbuf), "%s %ds", T(STR_BTN_WEIGHT), rem);
          lv_label_set_text(lbl_weight_main_lbl, wmbuf);
          lv_obj_set_style_text_color(lbl_weight_main_lbl, lv_color_hex(0x60f0c0), 0);
        }
      }
    } else if (!aw_done && !tag_present) {
      // Kein Tag, kein Countdown -> Idle-Text "(A)"
      if (auto_weight_stable_ms > 0) {
        auto_weight_stable_ms = 0;
        auto_weight_last_val = -9999.0f;
        aw_last_shown_s = -1;
      }
      // While a window is running the button belongs to its countdown. A new
      // spool takes it back, which is right: that one matters more.
      if (aw_last_shown_s != 0 && lbl_weight_main_lbl && !amsWindowOpen()) {
        aw_last_shown_s = 0;
        char wmbuf[48];
        snprintf(wmbuf, sizeof(wmbuf), "%s (A)", T(STR_BTN_WEIGHT));
        lv_label_set_text(lbl_weight_main_lbl, wmbuf);
        lv_obj_set_style_text_color(lbl_weight_main_lbl, lv_color_hex(0x28d49a), 0);
      }
    }
  } else {
    // Auto AUS: Timer sauber halten
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
        lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
      }
    } else if (ams_owns_status) {
      // Hand the line back once, not on every pass. Only when the pad is still
      // empty: with a tag on it the NFC branch owns the line already.
      ams_owns_status = false;
      ams_last_shown_s = -1;
      if (lbl_status && !tag_present) {
        lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
        lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
      }
    }
  }

  // Fix 10: Spoolman health check every 30s
  if (wifi_ok) {
    static unsigned long last_sm_check_ms = 0;
    if (millis() - last_sm_check_ms >= 30000 && !isSpoolFlowIdInputOpen()) {
      last_sm_check_ms = millis();
      int code = backendGetHealthCode(backendBaseUrl(), 3000);
      bool was_reachable = sm_reachable;
      sm_reachable = (code == 200);
      if (sm_reachable != was_reachable) updateHeaderStatus();
      // Someone can switch BamBuddy's filament manager while the scale is
      // running. That does not fail on our side, it just starts addressing
      // the other database - so the mode is re-asked here rather than only
      // at boot.
      if (sm_reachable) backendRefreshMode();
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
      // auto_assign_enabled standing, and "ask" would behave like "always".
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
  bambuddyDeviceTick();

  // The web server has to be up whenever FilaMan might trigger a link, and
  // has to stay down in Spoolman mode. Derived from the conditions once a
  // second so a backend switch or a returning WiFi needs no extra wiring.
  {
    static unsigned long last_web_sync_ms = 0;
    if (millis() - last_web_sync_ms >= 1000) {
      last_web_sync_ms = millis();
      webServerSyncState();
    }
  }

  // Periodic NAU7802 I2C ping every 5s (independent of WiFi)
  {
    static unsigned long last_scl_check_ms = 0;
    if (millis() - last_scl_check_ms >= 5000) {
      last_scl_check_ms = millis();
      I2C_EXT.beginTransmission(0x2A);
      bool prev = scl_ok;
      scl_ok = (I2C_EXT.endTransmission() == 0);
      if (scl_ok != prev) updateHeaderStatus();
    }
  }

  // ============================================================
  //  NFC SCAN LOGIC (0.4.21)
  //  - uidLen==4: MIFARE Classic → Bambu flow (unchanged)
  //  - uidLen==7: NTAG detected:
  //      "SPSC" magic → SpoolScale tag → querySpoolman by ID
  //      Blank (0x00) → show spool list + link
  //      Unknown      → ignore
  // ============================================================
  if (nfc_ok) {
    static unsigned long last_nfc_check_ms = 0;
    static unsigned long last_nfc_stats_ms = 0;
    static uint8_t last_uid_len = 0;   // 4 = Bambu, 7 = NTAG, for the removal delay

    // Fast re-poll only makes sense while a tag is believed to be on the
    // reader. With nothing on the scale the slow interval is the right one.
    const bool fast_mode = (tag_present && nfc_fast_polls > 0);
    const unsigned long poll_interval = fast_mode ? NFC_POLL_FAST_MS : NFC_POLL_SLOW_MS;
    const uint16_t poll_timeout = fast_mode ? NFC_TIMEOUT_FAST_MS : NFC_TIMEOUT_SLOW_MS;

    if (millis() - last_nfc_check_ms >= poll_interval) {
      last_nfc_check_ms = millis();
      uint8_t uid[7], uidLen = 0;
      bool found = nfcReadPassiveTarget(uid, &uidLen, poll_timeout);

      nfc_stat_scans++;
      if (found) {
        last_uid_len = uidLen;
        // Only a genuinely long absence earns a fresh set of retries. Without
        // this a tag that keeps failing to authenticate would be re-scanned
        // indefinitely, five seconds per attempt.
        if (tag_absent_since_ms != 0) {
          if (millis() - tag_absent_since_ms > NFC_RETRY_RESET_ABSENT_MS) nfc_retry_count = 0;
          tag_absent_since_ms = 0;
        }
        if (nfc_fast_polls > 0) {
          nfc_stat_recovered++;
          Serial.printf("NFC: recovered after %d fast re-poll(s) (%u ms gap)\n",
            nfc_fast_polls, (unsigned)(millis() - first_miss_ms));
          nfc_fast_polls = 0;
        }
        nfc_miss_streak = 0;
      } else {
        nfc_stat_misses++;
        nfc_miss_streak++;
      }

      // Aggregate statistics to SD, verbose only.
      if (sd_verbose && millis() - last_nfc_stats_ms >= NFC_STATS_LOG_INTERVAL_MS) {
        last_nfc_stats_ms = millis();
        logSDf("[verbose] NFC stats: scans=%lu misses=%lu recovered=%lu removals=%lu reinits=%lu",
          nfc_stat_scans, nfc_stat_misses, nfc_stat_recovered,
          nfc_stat_removals, nfc_stat_reinits);
      }

      if (found && uidLen == 4) {
        // ── MIFARE Classic (Bambu) ────────────────────────────
        last_tag_seen_ms = millis();
        tag_present = true;
        // A successful read means zero consecutive misses, by definition.
        // This used to be reset only when the UID changed, so after the very
        // first read of a spool the counter never went back to zero. The
        // "4 consecutive misses" below then counted misses that were minutes
        // apart, and the fifth glitch of a session declared the spool removed
        // while it was still lying on the scale.
        nfc_absent_count = 0;
        resetActivityTimer();

        char uid_str[24];
        snprintf(uid_str, sizeof(uid_str), "%02X:%02X:%02X:%02X",
          uid[0], uid[1], uid[2], uid[3]);

        bool uid_changed = (strcmp(uid_str, g_tag.uid_str) != 0);
        int bambu_blocks_read = countBambuDataBlocksRead(g_tag);
        bool uuid_missing = (strlen(g_tag.tray_uuid) < 32);
        bool contents_incomplete = (bambu_blocks_read < 48);

        if (uid_changed) {
          Serial.printf("NFC: New Bambu UID %s\n", uid_str);
          nfc_retry_count = 0; nfc_absent_count = 0;
          last_bambu_retry_ms = 0;
          lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
          lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0x28d49a), 0);
          lv_label_set_text(lbl_status, T(STR_READING_TAG));
          lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
          scanTag(uid, uidLen);
        } else if ((uuid_missing || contents_incomplete) && nfc_retry_count < NFC_MAX_RETRIES &&
                   millis() - last_bambu_retry_ms >= NFC_BAMBU_RETRY_BACKOFF_MS) {
          last_bambu_retry_ms = millis();
          nfc_retry_count++;
          Serial.printf("NFC: Bambu contents incomplete (%d/48 blocks, tray_uuid %s), retry %d/%d\n",
            bambu_blocks_read,
            uuid_missing ? "missing" : "present",
            nfc_retry_count,
            NFC_MAX_RETRIES);
          lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
          lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0x28d49a), 0);
          lv_label_set_text(lbl_status, T(STR_READING_TAG));
          lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
          scanTag(uid, uidLen);
        } else {
          if ((uuid_missing || contents_incomplete) && nfc_retry_count >= NFC_MAX_RETRIES &&
              bambu_blocks_read == 0) {
            // Not a Bambu tag at all. Every sector failed authentication, so
            // there is nothing here to decode and no amount of retrying will
            // change that. It is a plain 4 byte card, the kind sold as an RFID
            // button and stuck to spools by SpoolLink users.
            //
            // Those never reached the backend: the branch below insists on a
            // 32 character tray uuid, so they sat in "waiting" forever. Looking
            // them up by their UID is the whole point.
            //
            // Keyed off zero blocks rather than off the retry count alone. A
            // real Bambu tag that only read partially still has dozens of
            // blocks and belongs in the branch above, where "waiting" is the
            // honest answer rather than "not in Spoolman".
            if (wifi_ok && !isSpoolFlowIdInputOpen() &&
                strcmp(uid_str, spoolman_queried_uid) != 0) {
              querySpoolman(uid_str);
              strncpy(spoolman_queried_uid, uid_str, sizeof(spoolman_queried_uid)-1);
              spoolman_queried_uid[sizeof(spoolman_queried_uid)-1] = '\0';
              if (!sm_found) {
                strncpy(link_tag_uid, uid_str, sizeof(link_tag_uid)-1);
                link_tag_uid[sizeof(link_tag_uid)-1] = '\0';
                link_tag_first_seen_ms = millis();
                link_popup_dismissed = false;
              } else {
                // Stays shorter than 32 characters, so everything that tells a
                // Bambu tag apart by that length keeps saying no.
                strncpy(g_tag.tray_uuid, uid_str, sizeof(g_tag.tray_uuid)-1);
                g_tag.tray_uuid[sizeof(g_tag.tray_uuid)-1] = '\0';
                updateLinkButton();
              }
            }
            lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
            lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0x28d49a), 0);
            { char sb[48]; backendText(sm_found ? T(STR_TAG_FOUND) : T(STR_NOT_IN_SPOOLMAN), sb, sizeof(sb));
              lv_label_set_text(lbl_status, sb); }
            lv_obj_set_style_text_color(lbl_status,
              sm_found ? lv_color_hex(0x28d49a) : lv_color_hex(0xf0b838), 0);
          } else if ((uuid_missing || contents_incomplete) && nfc_retry_count >= NFC_MAX_RETRIES) {
            lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
            lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0xf0b838), 0);
            lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
            lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
          } else {
            // tray_uuid present — query Spoolman if not done yet
            if (!isSpoolFlowIdInputOpen() && strcmp(g_tag.uid_str, spoolman_queried_uid) != 0 && strlen(g_tag.tray_uuid) == 32) {
              querySpoolman(g_tag.tray_uuid);
              strncpy(spoolman_queried_uid, g_tag.uid_str, sizeof(spoolman_queried_uid)-1);
              spoolman_queried_uid[sizeof(spoolman_queried_uid)-1] = '\0';
              if (!sm_found && wifi_ok) {
                link_tag_first_seen_ms = millis();  // Start timer
                link_popup_dismissed = false;
              }
            } else if (!sm_found && !link_popup_dismissed && !isSpoolFlowLinkEntryOpen() &&
                       wifi_ok && strlen(g_tag.tray_uuid) == 32) {
              // Auto-popup disabled — user uses the Link/Copy buttons in Zone 5
              (void)link_tag_first_seen_ms;
            }
            lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
            lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0x28d49a), 0);
            { char sb[48]; backendText(sm_found ? T(STR_TAG_FOUND) : T(STR_NOT_IN_SPOOLMAN), sb, sizeof(sb)); lv_label_set_text(lbl_status, sb); }
            lv_obj_set_style_text_color(lbl_status,
              sm_found ? lv_color_hex(0x28d49a) : lv_color_hex(0xf0b838), 0);
          }
        }

      } else if (found && uidLen == 7) {
        // ── NTAG detected ──────────────────────────────────────
        last_tag_seen_ms = millis();
        tag_present = true;
        nfc_absent_count = 0;   // see the comment in the Bambu branch above
        resetActivityTimer();

        char uid_str[24];
        snprintf(uid_str, sizeof(uid_str), "%02X:%02X:%02X:%02X:%02X:%02X:%02X",
          uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6]);

        Serial.printf("NFC: NTAG UID=%s\n", uid_str);

        bool uid_changed_ntag_log = (strcmp(uid_str, g_tag.uid_str) != 0);
        if (uid_changed_ntag_log) logSDf("NFC: NTAG UID=%s", uid_str);

        lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
        lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0x28d49a), 0);

        bool uid_changed_ntag = (strcmp(uid_str, g_tag.uid_str) != 0);

        if (uid_changed_ntag) {
          // New UID — clear old tag data
          strncpy(g_tag.uid_str, uid_str, sizeof(g_tag.uid_str)-1);
          g_tag.uid_str[sizeof(g_tag.uid_str)-1] = '\0';
          g_tag.tray_uuid[0] = '\0';
          g_tag.material[0] = '\0';
          g_tag.color_hex[0] = '\0';
          g_tag.vendor[0] = '\0';
          spoolman_queried_uid[0] = '\0';
          lv_label_set_text(lbl_uid, uid_str);
          lv_label_set_text(lbl_tray_uuid, "-");
          lv_label_set_text(lbl_material, "-");
          lv_label_set_text(lbl_filament_name, "-");
          lv_label_set_text(lbl_vendor, "-");
          lv_label_set_text(lbl_detail, "-");
          lv_label_set_text(lbl_last_used, "-");
          lv_label_set_text(lbl_spoolman_dried_val, "-");
        if (lbl_dried_sym) lv_obj_add_flag(lbl_dried_sym, LV_OBJ_FLAG_HIDDEN);
          lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(0x333333), 0);
          lv_label_set_text(lbl_status, T(STR_READING_TAG));
          lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
          lv_timer_handler();

          if (wifi_ok && !isSpoolFlowIdInputOpen()) {
            querySpoolman(uid_str);
            strncpy(spoolman_queried_uid, uid_str, sizeof(spoolman_queried_uid)-1);
            spoolman_queried_uid[sizeof(spoolman_queried_uid)-1] = '\0';

            if (!sm_found) {
              Serial.println("NTAG: not in Spoolman -> waiting for delay");
              strncpy(link_tag_uid, uid_str, sizeof(link_tag_uid)-1);
              link_tag_uid[sizeof(link_tag_uid)-1] = '\0';
              link_tag_first_seen_ms = millis();
              link_popup_dismissed = false;
            } else {
              lv_label_set_text(lbl_status, T(STR_TAG_FOUND));
              lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
              strncpy(g_tag.tray_uuid, uid_str, sizeof(g_tag.tray_uuid)-1);
              g_tag.tray_uuid[sizeof(g_tag.tray_uuid)-1] = '\0';
              updateLinkButton();
            }
          } else {
            lv_label_set_text(lbl_status, T(STR_TAG_FOUND));
            lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
          }
        } else {
          // Same UID — show popup after delay if not dismissed
          // Auto-popup disabled — user uses the Link/Copy buttons in Zone 5
          (void)link_tag_first_seen_ms;
          { char sb[48]; backendText(sm_found ? T(STR_TAG_FOUND) : T(STR_NOT_IN_SPOOLMAN), sb, sizeof(sb)); lv_label_set_text(lbl_status, sb); }
          lv_obj_set_style_text_color(lbl_status,
            sm_found ? lv_color_hex(0x28d49a) : lv_color_hex(0xf0b838), 0);
        }

      } else {
        // No tag found
        if (tag_present) {
          // First close the gap with a few short-interval retries. Most NTAG
          // dropouts are a single missed read and come back on the next one.
          if (nfc_fast_polls < NFC_FAST_POLL_MAX) {
            if (nfc_fast_polls == 0) first_miss_ms = millis();
            nfc_fast_polls++;
            return;   // next poll follows in NFC_POLL_FAST_MS
          }
          // Retries exhausted. NTAG gets the longer grace period because it is
          // the flakier of the two protocols.
          //
          // The grace period is measured from the first missed read, not from
          // the last successful one. A full Bambu scan blocks for about five
          // seconds, and last_tag_seen_ms does not advance while it runs, so
          // measuring from there declared every tag removed the moment the
          // scan returned - which restarted the retry counter and looped
          // forever on a tag that would not authenticate.
          const unsigned long absent_limit =
            (last_uid_len == 7) ? NFC_ABSENT_NTAG_MS : NFC_ABSENT_BAMBU_MS;
          if (millis() - first_miss_ms < absent_limit) return;

          nfc_stat_removals++;
          nfc_fast_polls = 0;
          Serial.printf("NFC: tag removed (gap %u ms, %d fast re-polls exhausted)\n",
            (unsigned)(millis() - first_miss_ms), NFC_FAST_POLL_MAX);
          logSD("NFC: tag removed");
          tag_present = false;
          tag_absent_since_ms = millis();
          nfc_absent_count = 0;
          last_tag_seen_ms = millis();
          spoolman_queried_uid[0] = '\0';  // allow re-query when same tag is placed again
          link_popup_dismissed = false;   // Reset flag → next spool can show popup
          link_tag_first_seen_ms = 0;
          lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
          lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0xf0b838), 0);
          lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
          lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
          // Auto location popup: if enabled, spool is linked, and not shown for this spool yet
          // Debounce: only trigger after 1500ms — avoids spurious remove during NTAG read
          if (g_auto_loc_popup && sm_found && sm_id > 0 && wifi_ok && g_loc_popup_shown_for_id != sm_id) {
            loc_popup_pending_id = sm_id;  // schedule — will fire after debounce in loop
            logSDf("[verbose] LOC: tag removed, popup scheduled id=%d (debounce 2500ms)", sm_id);
          } else if (g_auto_loc_popup) {
            logSDf("[verbose] LOC: tag removed, popup suppressed id=%d shown_for=%d sm_found=%d wifi=%d", sm_id, g_loc_popup_shown_for_id, (int)sm_found, (int)wifi_ok);
          }
          // The AMS question hangs off the same removal, on the same
          // debounce and the same weight cross-check.
          if (amsAskActive() && wifi_ok && sm_found && sm_id > 0) {
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
          // Do NOT close list — user should be able to select spool
          // even if tag is temporarily removed
        }

        // ── Reader watchdog ───────────────────────────────────────────────
        // A long miss streak is normal with an empty scale, so it is not by
        // itself evidence of a problem. Probe the reader instead: a PN532 that
        // has locked up stops answering GetFirmwareVersion, and because it
        // shares I2C_EXT with the NAU7802 it would take the scale down too.
        if (nfc_miss_streak >= NFC_HEALTHCHECK_AFTER_MISSES) {
          nfc_miss_streak = 0;
          if (!nfcHardwarePing()) {
            uint32_t ver = 0;
            bool recovered = nfcHardwareReinit(&ver);
            nfc_stat_reinits++;
            Serial.printf("NFC: reader not responding, re-init %s (fw 0x%08lX)\n",
              recovered ? "ok" : "FAILED", (unsigned long)ver);
            logSDf("NFC: reader re-init %s (fw 0x%08lX)",
              recovered ? "ok" : "failed", (unsigned long)ver);
            nfc_ok = recovered;
            updateHeaderStatus();
          }
        }
      }
    }
  }

  // The button bar is derived state (tag_present && !sm_found) but used to be
  // recomputed only as a side effect of a backend lookup. A tag put back with
  // an unchanged UID never re-queries, so after a cancelled link flow the pair
  // stayed gone for good. Driven from the live state it cannot get stuck; the
  // edge check keeps it from invalidating four LVGL objects every pass.
  {
    static int link_bar_state = -1;
    const int s = (tag_present && !sm_found) ? 1 : 0;
    if (s != link_bar_state) { link_bar_state = s; updateLinkButton(); }
  }

  delay(5);
}
