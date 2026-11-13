#include "ota_github.h"
#include "ui/theme.h"
#include "services/partition_layout.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>

#include "app_config.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/asset_digest.h"
#include "services/github_release.h"
#include "services/ota_state.h"
#include "services/prefs_store.h"
#include "services/update_check.h"
#include "services/version_compare.h"
#include "confirm_popup.h"
#include "update_badges.h"
#include "ui_common.h"

// The parts of the screen that change after it is built: a ring with one
// symbol, the headline under it, the two setting rows and the one button.
static lv_obj_t *gh_ring            = nullptr;
static lv_obj_t *gh_ring_ico        = nullptr;
static lv_obj_t *lbl_gh_status      = nullptr;
static lv_obj_t *gh_row_auto        = nullptr;
static lv_obj_t *gh_row_pre         = nullptr;
static lv_obj_t *btn_gh_update      = nullptr;
static lv_obj_t *lbl_gh_update_btn  = nullptr;

void otaGithubForgetLabels() {
  gh_ring           = nullptr;
  gh_ring_ico       = nullptr;
  lbl_gh_status     = nullptr;
  gh_row_auto       = nullptr;
  gh_row_pre        = nullptr;
  btn_gh_update     = nullptr;
  lbl_gh_update_btn = nullptr;
}

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
  lv_obj_set_style_bg_color(gh_overlay, lv_color_hex(UI_COL_GROUND), 0);
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
  lv_obj_set_style_text_color(ico, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(ico, LV_ALIGN_CENTER, 0, -52);

  lv_obj_t *lbl_ov = lv_label_create(gh_overlay);
  char buf_ov[64]; copyT(buf_ov, sizeof(buf_ov), STR_GH_OTA_FLASHING); buf_ov[sizeof(buf_ov)-1]=0;
  lv_label_set_text(lbl_ov, buf_ov);
  lv_obj_set_style_text_color(lbl_ov, lv_color_hex(UI_COL_WARN), 0);
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
  lv_obj_set_style_bg_color(gh_bar, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_bg_color(gh_bar, lv_color_hex(UI_COL_ACCENT), LV_PART_INDICATOR);
  lv_obj_set_style_radius(gh_bar, 4, 0);
  lv_obj_set_style_radius(gh_bar, 4, LV_PART_INDICATOR);
  lv_bar_set_range(gh_bar, 0, 100);
  lv_bar_set_value(gh_bar, 0, LV_ANIM_OFF);

  gh_hint = lv_label_create(gh_overlay);
  lv_label_set_text(gh_hint, "");
  lv_obj_set_style_text_color(gh_hint, lv_color_hex(UI_COL_CAPTION), 0);
  lv_obj_set_style_text_font(gh_hint, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(gh_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(gh_hint, LV_ALIGN_CENTER, 0, 42);

  lv_obj_t *lbl_keep = lv_label_create(gh_overlay);
  char buf_keep[48];
  copyT(buf_keep, sizeof(buf_keep), STR_OTA_KEEP_POWER);
  buf_keep[sizeof(buf_keep)-1] = 0;
  lv_label_set_text(lbl_keep, buf_keep);
  lv_obj_set_style_text_color(lbl_keep, lv_color_hex(UI_COL_CAPTION), 0);
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

// What the ring and the headline say. The ring carries the colour and a
// symbol of its own, so the state reads without the colour too.
enum GhLook { GH_LOOK_IDLE, GH_LOOK_BUSY, GH_LOOK_OK, GH_LOOK_NEW, GH_LOOK_WARN, GH_LOOK_BAD };

// The headline's width. A text wider than this - an error from GitHub, the
// too-big note - drops to the small font, where two lines still clear the
// version line below.
static constexpr lv_coord_t GH_STATUS_W_PX = 456;

static void ghShowStatus(GhLook look, const char *text) {
  if (!lbl_gh_status || !gh_ring || !gh_ring_ico) return;
  static const char *const SYMBOLS[] = { "?", LV_SYMBOL_REFRESH, LV_SYMBOL_OK,
                                         LV_SYMBOL_DOWNLOAD, LV_SYMBOL_WARNING,
                                         LV_SYMBOL_CLOSE };
  uint32_t col = UI_COL_CAPTION;
  if (look == GH_LOOK_OK) col = UI_COL_GOOD;
  else if (look == GH_LOOK_NEW || look == GH_LOOK_WARN) col = UI_COL_WARN;
  else if (look == GH_LOOK_BAD) col = UI_COL_BAD;
  lv_obj_set_style_border_color(gh_ring, lv_color_hex(col), 0);
  lv_label_set_text(gh_ring_ico, SYMBOLS[look]);
  lv_obj_set_style_text_color(gh_ring_ico, lv_color_hex(col), 0);

  const lv_font_t *font = UI_FONT_HEADLINE;
  if (lv_txt_get_width(text, strlen(text), font, 0, LV_TEXT_FLAG_NONE) > GH_STATUS_W_PX) {
    font = UI_FONT_SMALL;
  }
  lv_obj_set_style_text_font(lbl_gh_status, font, 0);
  lv_label_set_text(lbl_gh_status, text);
  lv_obj_set_style_text_color(lbl_gh_status,
    lv_color_hex(look == GH_LOOK_BAD ? UI_COL_BAD_TEXT : UI_COL_INK), 0);
}

// One button for the next step: search while nothing is found, install (or
// go back) once something is. The old screen kept a greyed "Install" beside
// the search button, which read as broken.
static bool gh_action_installs = false;

static void ghSetAction(bool installs) {
  gh_action_installs = installs;
  if (!btn_gh_update || !lbl_gh_update_btn) return;
  lv_obj_set_style_bg_color(btn_gh_update,
    lv_color_hex(installs ? UI_COL_ACCENT : UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(btn_gh_update,
    lv_color_hex(installs ? UI_COL_GO_BG_PRESSED : UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_border_color(btn_gh_update,
    lv_color_hex(installs ? UI_COL_ACCENT : UI_COL_LINE), 0);
  const int caption = !installs      ? STR_GH_OTA_CHECK_BTN
                    : gh_found_older ? STR_GH_OTA_DOWNGRADE_BTN
                                     : STR_GH_OTA_UPDATE_BTN;
  char buf[64];
  snprintf(buf, sizeof(buf), "%s  %s", installs ? LV_SYMBOL_DOWNLOAD : LV_SYMBOL_REFRESH,
           T(caption));
  lv_label_set_text(lbl_gh_update_btn, buf);
  lv_obj_set_style_text_color(lbl_gh_update_btn,
    lv_color_hex(installs ? UI_COL_ON_ACCENT : UI_COL_ACCENT), 0);
}

// What the screen says before a search on it: what the background check
// found, else that nothing has been looked for yet.
static void ghShowInitial() {
  if (update_available && gh_latest_version[0] != '\0') {
    // The background check only ever reports a newer release, so whatever an
    // earlier manual check left here, this one is not a step back.
    gh_found_older = false;
    char avail[64];
    snprintf(avail, sizeof(avail), T(STR_GH_OTA_UPDATE_AVAIL), gh_latest_version);
    ghShowStatus(GH_LOOK_NEW, avail);
    ghSetAction(true);
  } else {
    ghShowStatus(GH_LOOK_IDLE, T(STR_GH_OTA_NOT_CHECKED));
    ghSetAction(false);
  }
}

// What a finished check found, shown and acted on. Split from the check so
// each stays readable; `image_size` is what GitHub says the image weighs.
static void ghShowCheckResult(uint32_t image_size) {
  const uint64_t cur = parseVersion(FW_VERSION);
  const uint64_t remote = parseVersion(gh_latest_version);
  gh_found_older = (remote < cur);

  if (remote == cur) {
    ghShowStatus(GH_LOOK_OK, T(STR_GH_OTA_UP_TO_DATE));
    update_available = false;
    showUpdateBadges(false);
    ghSetAction(false);
  } else if (!gh_found_older && !partitionImageFits(image_size)) {
    // Larger than this device's app slot: the old partition table. The
    // download would be refused at the end anyway; saying so now, with the
    // way out, beats a failed update (Nikolai, 26.09.2026).
    char big[96];
    snprintf(big, sizeof(big), T(STR_GH_OTA_TOO_BIG), gh_latest_version);
    ghShowStatus(GH_LOOK_WARN, big);
    partitionNoteTooBig(gh_latest_version, image_size);
    update_available = false;
    showUpdateBadges(false);
    // Back to searching even when an earlier check on this screen offered it.
    ghSetAction(false);
  } else {
    // Older is also an answer worth acting on: someone testing a pre-release
    // and moving the channel back wants the release below, and it is the same
    // download either way. What differs is that going back gets asked about.
    char avail[80];
    snprintf(avail, sizeof(avail),
             T(gh_found_older ? STR_GH_OTA_OLDER : STR_GH_OTA_UPDATE_AVAIL),
             gh_latest_version);
    ghShowStatus(GH_LOOK_NEW, avail);
    ghSetAction(true);
    // The badge means an update is waiting, so an older release must not light
    // it - and a check that found nothing newer has to take it down again.
    update_available = !gh_found_older;
    showUpdateBadges(!gh_found_older);
  }
}

void doGithubOtaCheck() {
  if (!lbl_gh_status) return;

  if (!wifi_ok) {
    ghShowStatus(GH_LOOK_BAD, T(STR_GH_OTA_NO_WIFI));
    return;
  }

  ghShowStatus(GH_LOOK_BUSY, T(STR_GH_OTA_CHECKING));
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

  char tag[40] = "", cerr[80] = "", sha[ASSET_SHA256_HEX_LEN + 1] = "";
  uint32_t image_size = 0;
  if (!githubLatestTag(gh_prerelease, tag, sizeof(tag), nullptr, 0,
                       cerr, sizeof(cerr), &image_size, sha, sizeof(sha))) {
    ghShowStatus(GH_LOOK_BAD, cerr[0] ? cerr : T(STR_GH_OTA_FLASH_FAIL));
    return;
  }

  strncpy(gh_latest_version, tag, sizeof(gh_latest_version)-1);
  gh_latest_version[sizeof(gh_latest_version)-1] = 0;
  // The install checks the image against it (otaExpectedSha()); without the
  // daily check that was TLS alone.
  otaRememberSha(tag, sha);
  ghShowCheckResult(image_size);
}

void doGithubOtaFlash(const char* version) {
  if (!lbl_gh_status) return;

  // The release to download, taken from the check that just ran rather than
  // from GitHub's "latest" alias - see the URL below for why that matters.
  const char* tag = (version && version[0]) ? version : gh_latest_version;
  if (tag[0] == '\0') {
    ghShowStatus(GH_LOOK_BAD, T(STR_GH_OTA_FLASH_FAIL));
    return;
  }
  // A version found too large for this slot - by the browser, say, while this
  // screen still showed an earlier, fitting one. Refused before the download
  // rather than by Update.begin() at its start.
  if (partitionTagTooBig(tag)) {
    char big[96];
    snprintf(big, sizeof(big), T(STR_GH_OTA_TOO_BIG), tag);
    ghShowStatus(GH_LOOK_WARN, big);
    return;
  }

  otaGithubOverlayShow();

  ghShowStatus(GH_LOOK_BUSY, T(STR_GH_OTA_FLASHING));
  if (btn_gh_update) lv_obj_add_flag(btn_gh_update, LV_OBJ_FLAG_HIDDEN);
  lv_timer_handler();

  char ferr[80] = "";
  const bool flashed = githubFlashTag(tag, otaExpectedSha(tag), otaGithubOverlayProgress,
                                      ferr, sizeof(ferr));
  if (!flashed) otaGithubOverlayHide();

  if (flashed) {
    ghShowStatus(GH_LOOK_OK, T(STR_GH_OTA_FLASH_OK));
    lv_timer_handler();
    delay(2000);
    logSD("Reboot: GitHub update written");
    ESP.restart();
  } else {
    char buf[128];
    snprintf(buf, sizeof(buf), "%s%s%s", T(STR_GH_OTA_FLASH_FAIL),
             ferr[0] ? " - " : "", ferr);
    ghShowStatus(GH_LOOK_BAD, buf);
  }
}

void showOtaGithubScreen() {
  logSD("SHOW: OtaGithubScreen");
  logSD("UI: Screen -> OTA GitHub");
  otaGithubForgetLabels();
  if (!update_available) gh_latest_version[0] = '\0';

  if (scr_ota_github) { lv_obj_del(scr_ota_github); scr_ota_github = nullptr; }
  buildOtaGithubScreen();
  hideAllOverlays();
  lv_obj_clear_flag(scr_ota_github, LV_OBJ_FLAG_HIDDEN);
}

// The ring, the headline and the installed version: the top half, which says
// where the device stands.
static void ghBuildStatus(lv_obj_t *scr) {
  gh_ring = lv_obj_create(scr);
  lv_obj_set_size(gh_ring, 48, 48);
  lv_obj_set_pos(gh_ring, 216, 56);
  lv_obj_set_style_radius(gh_ring, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(gh_ring, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_width(gh_ring, 2, 0);
  lv_obj_set_style_pad_all(gh_ring, 0, 0);
  lv_obj_clear_flag(gh_ring, (lv_obj_flag_t)(LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE));

  gh_ring_ico = lv_label_create(gh_ring);
  lv_obj_set_style_text_font(gh_ring_ico, UI_FONT_HEADLINE, 0);
  lv_obj_center(gh_ring_ico);

  lbl_gh_status = lv_label_create(scr);
  lv_label_set_long_mode(lbl_gh_status, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_gh_status, GH_STATUS_W_PX);
  lv_obj_set_style_text_align(lbl_gh_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_gh_status, LV_ALIGN_TOP_MID, 0, 110);

  lv_obj_t *lbl_inst = lv_label_create(scr);
  char inst[48];
  snprintf(inst, sizeof(inst), T(STR_GH_OTA_INSTALLED), FW_VERSION);
  lv_label_set_text(lbl_inst, inst);
  lv_obj_set_style_text_color(lbl_inst, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_style_text_font(lbl_inst, UI_FONT_SMALL, 0);
  lv_obj_align(lbl_inst, LV_ALIGN_TOP_MID, 0, 146);
}

// A setting in a half-width row: its name on the left, ON or OFF on the
// right, the border in the accent while it is on - the printer screen's
// toggle rows, side by side.
static lv_obj_t* ghMakeToggleRow(lv_obj_t *scr, lv_coord_t x, const char *title,
                                 lv_event_cb_t cb) {
  lv_obj_t *row = lv_btn_create(scr);
  lv_obj_set_size(row, 222, 52);
  lv_obj_set_pos(row, x, 176);
  lv_obj_set_style_bg_color(row, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(row, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_radius(row, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(row, 0, 0);
  lv_obj_set_style_border_width(row, 1, 0);
  lv_obj_set_style_pad_all(row, 0, 0);
  lv_obj_add_event_cb(row, cb, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl = lv_label_create(row);
  lv_label_set_text(lbl, title);
  lv_obj_set_style_text_color(lbl, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(lbl, UI_FONT_SMALL, 0);
  lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 14, 0);

  // Last child on purpose: ghPaintToggle() finds it there.
  lv_obj_t *val = lv_label_create(row);
  lv_obj_set_style_text_font(val, UI_FONT_SMALL, 0);
  lv_obj_align(val, LV_ALIGN_RIGHT_MID, -14, 0);
  return row;
}

static void ghPaintToggle(lv_obj_t *row, bool on) {
  if (!row) return;
  lv_obj_set_style_border_color(row, lv_color_hex(on ? UI_COL_ACCENT : UI_COL_ROW_PRESSED), 0);
  lv_obj_t *val = lv_obj_get_child(row, -1);
  lv_label_set_text(val, T(on ? STR_ON : STR_OFF));
  lv_obj_set_style_text_color(val, lv_color_hex(on ? UI_COL_ACCENT : UI_COL_CAPTION), 0);
}

// Both settings decide what the device looks for, not what it does now, so
// a change takes the screen back to its opening state rather than leave a
// result standing that was found under the other setting.
static void ghOnAutoToggle(lv_event_t *e) {
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
  ghPaintToggle(gh_row_auto, g_upd_autocheck);
  ghShowInitial();
}

static void ghOnPreToggle(lv_event_t *e) {
  gh_prerelease = !gh_prerelease;
  // Was written to the "spool" namespace while loadPrefs() reads from
  // "spoolscale", so the setting silently reverted on every reboot.
  prefsPutBool("gh_prerelease", gh_prerelease);
  ghPaintToggle(gh_row_pre, gh_prerelease);
  ghShowInitial();
}

static void ghOnAction(lv_event_t *e) {
  if (!gh_action_installs) {
    // The check is a TLS request of up to eight seconds: from the loop, never
    // from this callback, where "checking" was never drawn and the screen froze.
    ghShowStatus(GH_LOOK_BUSY, T(STR_GH_OTA_CHECKING));
    gh_check_pending = true;
    gh_check_wait_since = millis();
    return;
  }
  // Going back costs the same minute and the same restart as going forward,
  // and only the label says which direction the button points, so the one
  // that loses features asks first.
  if (gh_found_older) {
    char ask[160];
    snprintf(ask, sizeof(ask), T(STR_GH_OTA_DOWNGRADE_ASK), gh_latest_version);
    showConfirmPopup(ask, 5);
    return;
  }
  // Parked, like the downgrade: a minute of TLS download and a flash write
  // do not run from the button that asked for them.
  gh_flash_pending = true;
}

static void ghBuildAction(lv_obj_t *scr) {
  btn_gh_update = lv_btn_create(scr);
  lv_obj_set_size(btn_gh_update, 456, 52);
  lv_obj_set_pos(btn_gh_update, 12, 244);
  lv_obj_set_style_radius(btn_gh_update, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(btn_gh_update, 0, 0);
  lv_obj_set_style_border_width(btn_gh_update, 1, 0);
  lv_obj_add_event_cb(btn_gh_update, ghOnAction, LV_EVENT_CLICKED, NULL);

  lbl_gh_update_btn = lv_label_create(btn_gh_update);
  lv_obj_set_style_text_font(lbl_gh_update_btn, UI_FONT_BODY, 0);
  lv_obj_center(lbl_gh_update_btn);
}

void buildOtaGithubScreen() {
  logSD("BUILD: OtaGithubScreen");
  releaseScreen(&scr_ota_github);
  scr_ota_github = buildOverlayScreen();

  char buf_title[32];
  copyT(buf_title, sizeof(buf_title), STR_GH_OTA_TITLE);
  buildSubHeader(scr_ota_github, buf_title,
    [](lv_event_t *e){ logSD("BTN: OtaGithub -> Back"); show_ota_pending = true; });

  ghBuildStatus(scr_ota_github);
  gh_row_auto = ghMakeToggleRow(scr_ota_github, 12, T(STR_GH_OTA_AUTOCHECK), ghOnAutoToggle);
  gh_row_pre  = ghMakeToggleRow(scr_ota_github, 246, T(STR_GH_OTA_PRERELEASE), ghOnPreToggle);
  ghPaintToggle(gh_row_auto, g_upd_autocheck);
  ghPaintToggle(gh_row_pre, gh_prerelease);
  ghBuildAction(scr_ota_github);
  ghShowInitial();
}
