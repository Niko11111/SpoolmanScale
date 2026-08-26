#include "ota_github.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>

#include "app_config.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/github_release.h"
#include "services/ota_state.h"
#include "services/prefs_store.h"
#include "services/update_check.h"
#include "services/version_compare.h"
#include "confirm_popup.h"
#include "update_badges.h"
#include "ui_common.h"



static lv_obj_t *lbl_gh_status      = nullptr;
static lv_obj_t *lbl_gh_installed   = nullptr;
static lv_obj_t *lbl_gh_latest      = nullptr;
static lv_obj_t *btn_gh_update      = nullptr;
static lv_obj_t *lbl_gh_update_btn  = nullptr;

// The download overlay. File scope so the progress callback can reach it - it
// is a plain function pointer, not a closure - and so both callers raise the
// same one instead of growing a second.
// What the last check found, for the button that acts on it. The label alone
// cannot be read back, and the direction decides whether it asks first.
static bool gh_found_older = false;

static lv_obj_t *gh_overlay = nullptr;
static lv_obj_t *gh_bar     = nullptr;
static lv_obj_t *gh_hint    = nullptr;

void otaGithubOverlayShow() {
  if (gh_overlay) return;

  gh_overlay = lv_obj_create(lv_layer_top());
  lv_obj_set_size(gh_overlay, 480, 320);
  lv_obj_set_pos(gh_overlay, 0, 0);
  lv_obj_set_style_bg_color(gh_overlay, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_bg_opa(gh_overlay, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(gh_overlay, 0, 0);
  lv_obj_set_style_pad_all(gh_overlay, 0, 0);
  lv_obj_clear_flag(gh_overlay, LV_OBJ_FLAG_SCROLLABLE);
  // Clickable on purpose, though nothing on it reacts. A non-clickable object
  // drops out of LVGL's hit test and the touch lands on the screen underneath,
  // which is still live and still running its callbacks. The back button of
  // the OTA screen would delete that screen mid-download, and lbl_gh_status is
  // written again once the download returns.
  lv_obj_add_flag(gh_overlay, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *ico = lv_label_create(gh_overlay);
  lv_label_set_text(ico, LV_SYMBOL_DOWNLOAD);
  lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(ico, LV_ALIGN_CENTER, 0, -52);

  lv_obj_t *lbl_ov = lv_label_create(gh_overlay);
  char buf_ov[64]; strncpy(buf_ov, T(STR_GH_OTA_FLASHING), sizeof(buf_ov)-1); buf_ov[sizeof(buf_ov)-1]=0;
  lv_label_set_text(lbl_ov, buf_ov);
  lv_obj_set_style_text_color(lbl_ov, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_ov, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(lbl_ov, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_ov, LV_ALIGN_CENTER, 0, -14);

  // The overlay used to say "~30-60 sec" and then nothing for a minute, which
  // answers neither of the two questions a wait like this raises: how far along
  // it is, and whether anything is still moving. The loop below already knew
  // both - it counted the remaining bytes down and told nobody.
  gh_bar = lv_bar_create(gh_overlay);
  lv_obj_set_size(gh_bar, 300, 8);
  lv_obj_align(gh_bar, LV_ALIGN_CENTER, 0, 18);
  lv_obj_set_style_bg_color(gh_bar, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_bg_color(gh_bar, lv_color_hex(0x28d49a), LV_PART_INDICATOR);
  lv_obj_set_style_radius(gh_bar, 4, 0);
  lv_obj_set_style_radius(gh_bar, 4, LV_PART_INDICATOR);
  lv_bar_set_range(gh_bar, 0, 100);
  lv_bar_set_value(gh_bar, 0, LV_ANIM_OFF);

  gh_hint = lv_label_create(gh_overlay);
  lv_label_set_text(gh_hint, "");
  lv_obj_set_style_text_color(gh_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(gh_hint, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(gh_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(gh_hint, LV_ALIGN_CENTER, 0, 42);

  lv_obj_t *lbl_keep = lv_label_create(gh_overlay);
  char buf_keep[48];
  strncpy(buf_keep, T(STR_OTA_KEEP_POWER), sizeof(buf_keep)-1);
  buf_keep[sizeof(buf_keep)-1] = 0;
  lv_label_set_text(lbl_keep, buf_keep);
  lv_obj_set_style_text_color(lbl_keep, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_keep, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_keep, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_keep, LV_ALIGN_CENTER, 0, 70);

  lv_refr_now(NULL);
  lv_timer_handler();
}

void otaGithubOverlayProgress(uint32_t done, uint32_t total) {
  char line[48];
  otaProgressLine(line, sizeof(line), done, total);
  if (gh_hint) lv_label_set_text(gh_hint, line);
  // No total means no Content-Length, and a bar without an end lies about
  // where it is. The counter alone is honest.
  if (gh_bar) {
    if (total) lv_bar_set_value(gh_bar, (int)((uint64_t)done * 100 / total), LV_ANIM_OFF);
    else       lv_obj_add_flag(gh_bar, LV_OBJ_FLAG_HIDDEN);
  }
  // Redraws without running timers or handling input, which is what this
  // overlay wants: nothing on it is interactive and the socket is waiting.
  lv_refr_now(NULL);
}

void otaGithubOverlayHide() {
  if (!gh_overlay) return;
  // Not from a callback of its own - this runs in the loop, after the download
  // returned. Leaving it up was what made a failed download look like a frozen
  // device.
  lv_obj_del(gh_overlay);
  gh_overlay = nullptr;
  gh_bar     = nullptr;
  gh_hint    = nullptr;
}

// The silent variant that used to live here is gone. It ran blocking in the
// boot path and now lives in services/update_check.cpp, in its own task.
// gh_latest_version moved to ota_state.h because both checks write it.

bool otaGithubScreenVisible() {
  return scr_ota_github != nullptr &&
         !lv_obj_has_flag(scr_ota_github, LV_OBJ_FLAG_HIDDEN);
}

void doGithubOtaCheck() {
  if (!lbl_gh_status) return;

  if (!wifi_ok) {
    char buf[64]; strncpy(buf, T(STR_GH_OTA_NO_WIFI), sizeof(buf)-1); buf[sizeof(buf)-1]=0;
    lv_label_set_text(lbl_gh_status, buf);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    return;
  }

  char buf[64]; strncpy(buf, T(STR_GH_OTA_CHECKING), sizeof(buf)-1); buf[sizeof(buf)-1]=0;
  lv_label_set_text(lbl_gh_status, buf);
  lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0x4a6fa0), 0);
  lv_timer_handler();

  // The background check holds its own TLS connection, and two handshakes want
  // roughly 40 kB each. Rather than open a second one, hand this off to the
  // loop and let it come back once the task is done - the screen already says
  // "checking", so nothing looks stuck.
  if (updateCheckBusy()) {
    gh_check_pending = true;
    gh_check_wait_since = millis();
    logSD("OTA check: deferred, background check running");
    return;
  }

  char tag[40] = "", cerr[80] = "";
  if (!githubLatestTag(gh_prerelease, tag, sizeof(tag), nullptr, 0,
                       cerr, sizeof(cerr))) {
    lv_label_set_text(lbl_gh_status, cerr[0] ? cerr : T(STR_GH_OTA_FLASH_FAIL));
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    return;
  }

  strncpy(gh_latest_version, tag, sizeof(gh_latest_version)-1);
  gh_latest_version[sizeof(gh_latest_version)-1] = 0;

  if (lbl_gh_installed) {
    char inst[48]; snprintf(inst, sizeof(inst), T(STR_GH_OTA_INSTALLED), FW_VERSION);
    lv_label_set_text(lbl_gh_installed, inst);
    lv_obj_clear_flag(lbl_gh_installed, LV_OBJ_FLAG_HIDDEN);
  }
  if (lbl_gh_latest) {
    char lat[48]; snprintf(lat, sizeof(lat), T(STR_GH_OTA_LATEST), gh_latest_version);
    lv_label_set_text(lbl_gh_latest, lat);
    lv_obj_clear_flag(lbl_gh_latest, LV_OBJ_FLAG_HIDDEN);
  }

  uint64_t cur = parseVersion(FW_VERSION);
  uint64_t remote = parseVersion(gh_latest_version);

  gh_found_older = (remote < cur);

  if (remote == cur) {
    char upd[48]; strncpy(upd, T(STR_GH_OTA_UP_TO_DATE), sizeof(upd)-1); upd[sizeof(upd)-1]=0;
    lv_label_set_text(lbl_gh_status, upd);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0x40c080), 0);
    update_available = false;
    showUpdateBadges(false);
  } else {
    // Older is also an answer worth acting on: someone testing a pre-release
    // and moving the channel back wants the release below, and it is the same
    // download either way. What differs is that going back gets asked about.
    char avail[80];
    snprintf(avail, sizeof(avail),
             T(gh_found_older ? STR_GH_OTA_OLDER : STR_GH_OTA_UPDATE_AVAIL),
             gh_latest_version);
    lv_label_set_text(lbl_gh_status, avail);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xf0b838), 0);
    if (btn_gh_update) {
      lv_obj_clear_state(btn_gh_update, LV_STATE_DISABLED);
      lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x1a3020), 0);
      lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(btn_gh_update, lv_color_hex(0x28d49a), 0);
      if (lbl_gh_update_btn) {
        char ubtn[48];
        strncpy(ubtn, T(gh_found_older ? STR_GH_OTA_DOWNGRADE_BTN
                                       : STR_GH_OTA_UPDATE_BTN), sizeof(ubtn)-1);
        ubtn[sizeof(ubtn)-1]=0;
        lv_label_set_text(lbl_gh_update_btn, ubtn);
        lv_obj_set_style_text_color(lbl_gh_update_btn, lv_color_hex(0x40c080), 0);
      }
    }
    // The badge means an update is waiting, so an older release must not light
    // it - and a check that found nothing newer has to take it down again.
    update_available = !gh_found_older;
    showUpdateBadges(!gh_found_older);
  }
}

void doGithubOtaFlash(const char* version) {
  if (!lbl_gh_status) return;

  // The release to download, taken from the check that just ran rather than
  // from GitHub's "latest" alias - see the URL below for why that matters.
  const char* tag = (version && version[0]) ? version : gh_latest_version;
  if (tag[0] == '\0') {
    lv_label_set_text(lbl_gh_status, T(STR_GH_OTA_FLASH_FAIL));
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    return;
  }

  otaGithubOverlayShow();

  char buf[64]; strncpy(buf, T(STR_GH_OTA_FLASHING), sizeof(buf)-1); buf[sizeof(buf)-1]=0;
  lv_label_set_text(lbl_gh_status, buf);
  lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xf0b838), 0);
  if (btn_gh_update) lv_obj_add_flag(btn_gh_update, LV_OBJ_FLAG_HIDDEN);
  lv_timer_handler();

  char ferr[80] = "";
  const bool flashed = githubFlashTag(tag, otaGithubOverlayProgress, ferr, sizeof(ferr));
  if (!flashed) otaGithubOverlayHide();

  if (flashed) {
    char okmsg[64]; strncpy(okmsg, T(STR_GH_OTA_FLASH_OK), sizeof(okmsg)-1); okmsg[sizeof(okmsg)-1]=0;
    lv_label_set_text(lbl_gh_status, okmsg);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0x40c080), 0);
    lv_timer_handler();
    delay(2000);
    logSD("Reboot: GitHub update written");
    ESP.restart();
  } else {
    snprintf(buf, sizeof(buf), "%s%s%s", T(STR_GH_OTA_FLASH_FAIL),
             ferr[0] ? " - " : "", ferr);
    lv_label_set_text(lbl_gh_status, buf);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
  }
}

void showOtaGithubScreen() {
  logSD("SHOW: OtaGithubScreen");
  logSD("UI: Screen -> OTA GitHub");
  lbl_gh_status     = nullptr;
  lbl_gh_installed  = nullptr;
  lbl_gh_latest     = nullptr;
  btn_gh_update     = nullptr;
  lbl_gh_update_btn = nullptr;
  if (!update_available) gh_latest_version[0] = '\0';

  if (scr_ota_github) { lv_obj_del(scr_ota_github); scr_ota_github = nullptr; }
  buildOtaGithubScreen();
  hideAllOverlays();
  lv_obj_clear_flag(scr_ota_github, LV_OBJ_FLAG_HIDDEN);
}

void buildOtaGithubScreen() {
  logSD("BUILD: OtaGithubScreen");
  releaseScreen(&scr_ota_github);
  scr_ota_github = buildOverlayScreen();

  char buf_title[32];
  strncpy(buf_title, T(STR_GH_OTA_TITLE), sizeof(buf_title)-1); buf_title[sizeof(buf_title)-1]=0;
  buildSubHeader(scr_ota_github, buf_title,
    [](lv_event_t *e){ logSD("BTN: OtaGithub -> Back"); show_ota_pending = true; });

  lv_obj_t *btn_check = lv_btn_create(scr_ota_github);
  lv_obj_set_size(btn_check, 280, 44);
  lv_obj_align(btn_check, LV_ALIGN_TOP_MID, 0, 56);
  lv_obj_set_style_bg_color(btn_check, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_check, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_check, 8, 0);
  lv_obj_set_style_shadow_width(btn_check, 0, 0);
  lv_obj_set_style_border_width(btn_check, 1, 0);
  lv_obj_set_style_border_color(btn_check, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn_check, [](lv_event_t *e){ doGithubOtaCheck(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_check = lv_label_create(btn_check);
  char buf_check[48]; strncpy(buf_check, T(STR_GH_OTA_CHECK_BTN), sizeof(buf_check)-1); buf_check[sizeof(buf_check)-1]=0;
  lv_label_set_text(lbl_check, buf_check);
  lv_obj_set_style_text_color(lbl_check, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_check, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_check, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_check, LV_ALIGN_CENTER, 0, 0);

  lbl_gh_status = lv_label_create(scr_ota_github);
  lv_label_set_text(lbl_gh_status, "");
  lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_gh_status, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_gh_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_gh_status, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_gh_status, 440);
  lv_obj_align(lbl_gh_status, LV_ALIGN_TOP_MID, 0, 112);

  lbl_gh_installed = lv_label_create(scr_ota_github);
  lv_label_set_text(lbl_gh_installed, "");
  lv_obj_set_style_text_color(lbl_gh_installed, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_gh_installed, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_gh_installed, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_gh_installed, LV_ALIGN_TOP_MID, 0, 148);
  lv_obj_add_flag(lbl_gh_installed, LV_OBJ_FLAG_HIDDEN);

  lbl_gh_latest = lv_label_create(scr_ota_github);
  lv_label_set_text(lbl_gh_latest, "");
  lv_obj_set_style_text_color(lbl_gh_latest, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_gh_latest, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_gh_latest, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_gh_latest, LV_ALIGN_TOP_MID, 0, 170);
  lv_obj_add_flag(lbl_gh_latest, LV_OBJ_FLAG_HIDDEN);

  // ── Automatic background check ──
  // Sits with the pre-release switch because both decide what the device looks
  // for, not what it does right now.
  lv_obj_t *btn_auto = lv_btn_create(scr_ota_github);
  lv_obj_set_size(btn_auto, 280, 36);
  lv_obj_align(btn_auto, LV_ALIGN_TOP_MID, 0, 200);
  lv_obj_set_style_bg_color(btn_auto, g_upd_autocheck ? lv_color_hex(0x0a2040) : lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_bg_color(btn_auto, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_auto, 8, 0);
  lv_obj_set_style_shadow_width(btn_auto, 0, 0);
  lv_obj_set_style_border_width(btn_auto, 1, 0);
  lv_obj_set_style_border_color(btn_auto, g_upd_autocheck ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a2030), 0);
  lv_obj_add_event_cb(btn_auto, [](lv_event_t *e) {
    g_upd_autocheck = !g_upd_autocheck;
    prefsPutBool("upd_check", g_upd_autocheck);
    if (g_upd_autocheck) {
      // Someone who just switched this on wants to see a result, not to wait
      // out the daily window. The zeroed timestamp makes the next check due.
      g_upd_last_epoch = 0;
      prefsPutUInt("upd_last", 0);
      updateCheckScheduleIn(5000);
    } else {
      update_available = false;
      showUpdateBadges(false);
    }
    if (scr_ota_github) { lv_obj_del(scr_ota_github); scr_ota_github = nullptr; }
    buildOtaGithubScreen();
    if (scr_ota_github) lv_obj_clear_flag(scr_ota_github, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_auto = lv_label_create(btn_auto);
  char auto_buf[64];
  snprintf(auto_buf, sizeof(auto_buf), "%s  %s", T(STR_GH_OTA_AUTOCHECK),
           g_upd_autocheck ? "[ ON ]" : "[ OFF ]");
  lv_label_set_text(lbl_auto, auto_buf);
  lv_obj_set_style_text_color(lbl_auto, g_upd_autocheck ? lv_color_hex(0x28d49a) : lv_color_hex(0x2a3848), 0);
  lv_obj_set_style_text_font(lbl_auto, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_auto, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_auto, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *btn_pre = lv_btn_create(scr_ota_github);
  lv_obj_set_size(btn_pre, 140, 48);
  lv_obj_align(btn_pre, LV_ALIGN_BOTTOM_LEFT, 12, -24);
  lv_obj_set_style_bg_color(btn_pre, gh_prerelease ? lv_color_hex(0x0a2040) : lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_bg_color(btn_pre, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_pre, 8, 0);
  lv_obj_set_style_shadow_width(btn_pre, 0, 0);
  lv_obj_set_style_border_width(btn_pre, 1, 0);
  lv_obj_set_style_border_color(btn_pre, gh_prerelease ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a2030), 0);
  lv_obj_add_event_cb(btn_pre, [](lv_event_t *e) {
    gh_prerelease = !gh_prerelease;
    // Was written to the "spool" namespace while loadPrefs() reads from
    // "spoolscale", so the setting silently reverted on every reboot.
    prefsPutBool("gh_prerelease", gh_prerelease);
    if (scr_ota_github) { lv_obj_del(scr_ota_github); scr_ota_github = nullptr; }
    buildOtaGithubScreen();
    if (scr_ota_github) lv_obj_clear_flag(scr_ota_github, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_pre = lv_label_create(btn_pre);
  char pre_buf[32];
  snprintf(pre_buf, sizeof(pre_buf), "%s\n%s", T(STR_GH_OTA_PRERELEASE), gh_prerelease ? "[ ON ]" : "[ OFF ]");
  lv_label_set_text(lbl_pre, pre_buf);
  lv_obj_set_style_text_color(lbl_pre, gh_prerelease ? lv_color_hex(0x28d49a) : lv_color_hex(0x2a3848), 0);
  lv_obj_set_style_text_font(lbl_pre, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_pre, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_pre, LV_ALIGN_CENTER, 0, 0);

  btn_gh_update = lv_btn_create(scr_ota_github);
  lv_obj_set_size(btn_gh_update, 310, 48);
  lv_obj_align(btn_gh_update, LV_ALIGN_BOTTOM_RIGHT, -12, -24);
  lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x111820), 0);
  lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x111820), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_gh_update, 8, 0);
  lv_obj_set_style_shadow_width(btn_gh_update, 0, 0);
  lv_obj_set_style_border_width(btn_gh_update, 1, 0);
  lv_obj_set_style_border_color(btn_gh_update, lv_color_hex(0x1a2030), 0);
  lv_obj_add_state(btn_gh_update, LV_STATE_DISABLED);
  lv_obj_add_event_cb(btn_gh_update, [](lv_event_t *e){
    // Going back costs the same minute and the same restart as going forward,
    // and nothing about the screen says which direction the button points, so
    // the one that loses features asks first.
    if (gh_found_older) {
      char ask[160];
      snprintf(ask, sizeof(ask), T(STR_GH_OTA_DOWNGRADE_ASK), gh_latest_version);
      showConfirmPopup(ask, 5);
      return;
    }
    doGithubOtaFlash(gh_latest_version);
  }, LV_EVENT_CLICKED, NULL);

  lbl_gh_update_btn = lv_label_create(btn_gh_update);
  char buf_ubtn[48]; strncpy(buf_ubtn, T(STR_GH_OTA_UPDATE_BTN), sizeof(buf_ubtn)-1); buf_ubtn[sizeof(buf_ubtn)-1]=0;
  lv_label_set_text(lbl_gh_update_btn, buf_ubtn);
  lv_obj_set_style_text_color(lbl_gh_update_btn, lv_color_hex(0x2a3848), 0);
  lv_obj_set_style_text_font(lbl_gh_update_btn, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_gh_update_btn, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_gh_update_btn, LV_ALIGN_CENTER, 0, 0);

  if (update_available && gh_latest_version[0] != '\0') {
    lv_obj_clear_state(btn_gh_update, LV_STATE_DISABLED);
    lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x1a3020), 0);
    lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
    lv_obj_set_style_border_color(btn_gh_update, lv_color_hex(0x28d49a), 0);
    char ubtn2[48]; strncpy(ubtn2, T(STR_GH_OTA_UPDATE_BTN), sizeof(ubtn2)-1); ubtn2[sizeof(ubtn2)-1]=0;
    lv_label_set_text(lbl_gh_update_btn, ubtn2);
    lv_obj_set_style_text_color(lbl_gh_update_btn, lv_color_hex(0x40c080), 0);
    char avail[64]; snprintf(avail, sizeof(avail), T(STR_GH_OTA_UPDATE_AVAIL), gh_latest_version);
    lv_label_set_text(lbl_gh_status, avail);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xf0b838), 0);
    char inst[48]; snprintf(inst, sizeof(inst), T(STR_GH_OTA_INSTALLED), FW_VERSION);
    lv_label_set_text(lbl_gh_installed, inst);
    lv_obj_clear_flag(lbl_gh_installed, LV_OBJ_FLAG_HIDDEN);
    char lat[48]; snprintf(lat, sizeof(lat), T(STR_GH_OTA_LATEST), gh_latest_version);
    lv_label_set_text(lbl_gh_latest, lat);
    lv_obj_clear_flag(lbl_gh_latest, LV_OBJ_FLAG_HIDDEN);
  }
}
