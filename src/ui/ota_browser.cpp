#include "ota_browser.h"
#include "app_config.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <IPAddress.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/backend.h"
#include "services/backend_profiles.h"
#include "services/device_name.h"
#include "web/web_server.h"
#include "web/web_access.h"
#include "services/wifi_manager.h"
#include "ui_common.h"
#include "setup_frame.h"
#include "theme.h"
#include "icons.h"
#include "extra/libs/qrcode/lv_qrcode.h"

// The address card under the step line: the QR button on its left, the
// address beside it. W5 of the hand-off mock-ups (Nikolai, 26.10.2026).
#define WEB_STEP_Y       58
#define WEB_CARD_X       12
#define WEB_CARD_Y       80
#define WEB_CARD_W      456
#define WEB_CARD_H      124
#define WEB_QR_BTN_PX   108
#define WEB_QR_BTN_INSET  8
#define WEB_TEXT_X      132   // inside the card, right of the button
#define WEB_TEXT_W      314   // to the card's inner edge
#define WEB_PILL_Y      212
// The row of status and action under the card, in halves or across.
#define WEB_ROW_Y       246
#define WEB_ROW_H        54
// In the setup the row moves up and gets lower, so the setup's action bar
// fits under it in its usual place.
#define WEB_SETUP_ROW_Y 212
#define WEB_SETUP_ROW_H  40
#define WEB_HALF_W      222
#define WEB_HALF_X2     246
// The firmware row: status on the left, the installed version on the right.
#define WEB_FW_STATUS_W 290
#define WEB_FW_LINE_DY   10
// The QR page the button opens.
#define WEB_QR_FRAME_PX 200
#define WEB_QR_CODE_PX  180
#define WEB_QR_FRAME_Y   52
#define WEB_QR_URL_Y    262
#define WEB_QR_HINT_Y   290
#define WEB_URL_MAX      96

// Which entry point brought the user here. Kept between show and build
// because buildOtaBrowserScreen() is also reached through the generic
// rebuild path and has no argument of its own.
static WebScreenContext s_web_ctx = WEB_CTX_FIRMWARE;

// Value labels of the two credential rows, refreshed while the user types on
// the other side. Null whenever the rows are not on screen.
static lv_obj_t *s_lbl_key_val   = nullptr;
static lv_obj_t *s_lbl_token_val = nullptr;

// The line under the upload status: the file it wants, or what to do after a
// failure. Only valid while lbl_ota_status is, which is built with it.
static lv_obj_t *s_lbl_ota_hint = nullptr;

// True when opening this screen had to switch something on for the visit.
// Only affects what the screen says; the switching back is webVisitEnd()'s.
static bool s_gate_opened = false;

// Only the two FilaMan entry points need the credential rows. The drying
// thresholds are edited in the browser as well, but have nothing to do with
// tokens, so that context just shows the address.
static bool showsCredentials() {
  // Spoolman has nothing to enter, so the rows are a FilaMan and BamBuddy
  // affair even in the contexts that would otherwise show them.
  if (backendMode() == BACKEND_SPOOLMAN && !backendProfileIsOnline()) return false;
  return s_web_ctx == WEB_CTX_BACKEND || s_web_ctx == WEB_CTX_SETUP ||
         s_web_ctx == WEB_CTX_ADDRESS;
}

// BamBuddy and an online service ask for a single key, FilaMan for two.
static bool oneKeyOnly() { return backendIsBamBuddy() || backendProfileIsOnline(); }

static bool activeKeyPresent() {
  if (backendProfileIsOnline()) return spoolmanAuthActive();
  return backendIsBamBuddy() ? bambuddyApiKey()[0] != '\0' : filamanApiKey()[0] != '\0';
}

// Everything except the firmware upload uses the neutral title and skips the
// upload's status row.
static bool isFirmwareContext() {
  return s_web_ctx == WEB_CTX_FIRMWARE;
}

// What an entry point sends the user to, and which switch has to be on for
// that page to answer at all.
//
// The path used to be a two way "credentials or /ota", which quietly sent the
// drying context to the firmware page - it is neither of the two. Keeping the
// gate next to the path is what lets the screen open the right one below.
struct WebTarget { const char *path; WebGate gate; };

static WebTarget webTargetFor(WebScreenContext ctx) {
  switch (ctx) {
    case WEB_CTX_BACKEND:
    case WEB_CTX_ADDRESS:
    case WEB_CTX_SETUP:   return { "/backend", GATE_CONFIG };
    case WEB_CTX_DRYING:  return { "/drying",  GATE_CONFIG };
    default:              return { "/ota",     GATE_MAINT  };
  }
}

void showOtaBrowserScreen(WebScreenContext ctx) {
  logSD("SHOW: OtaBrowserScreen");
  logSDf("UI: Screen -> Web interface (ctx=%d)", (int)ctx);
  s_web_ctx = ctx;

  // First, because hiding the overlays ends any visit still open - this
  // screen's own included, when it is shown again from itself.
  hideAllOverlays();

  // Pressing the button is the request. Sending someone to an address that
  // answers 403 because a switch they have never seen is off is not a
  // safeguard, it is a dead end - and during the first time setup there is no
  // menu to go and find that switch in. The master has to come with it:
  // webGateOpen() is master_on && config_on, so the sub gate alone changes
  // nothing. Open for the visit only: leaving this screen closes again what
  // it opened, so a maintenance gate nobody switched on in the menu does not
  // stay open for good (Nikolai, 26.10.2026).
  const WebTarget t = webTargetFor(ctx);
  s_gate_opened = webVisitOpen(t.gate);
  if (s_gate_opened) logSDf("Web: gate opened for %s (ctx=%d)", t.path, (int)ctx);

  lbl_ota_status = nullptr;
  s_lbl_key_val = nullptr;
  s_lbl_token_val = nullptr;
  if (scr_ota_browser) {
    lv_obj_del(scr_ota_browser);
    scr_ota_browser = nullptr;
  }
  buildOtaBrowserScreen();
  lv_obj_clear_flag(scr_ota_browser, LV_OBJ_FLAG_HIDDEN);
  // Not "start the server" any more - that belongs to webServerSyncState()
  // alone. This only asks it to settle now rather than within the next
  // second, so the address on screen is reachable the moment it appears.
  webServerSyncState();
}


// The address the QR page encodes, set while the card is built. The IP when
// the scale has one beside its name: a phone that does not resolve .local
// gets there all the same.
static char s_qr_url[WEB_URL_MAX] = "";
static lv_obj_t *s_qr_page = nullptr;

static lv_obj_t* webLabel(lv_obj_t *parent, const char *text, const lv_font_t *font, uint32_t col) {
  lv_obj_t *l = lv_label_create(parent);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(col), 0);
  return l;
}

// A quiet box in the row under the card: what is on, what is waiting.
static lv_obj_t* webRowBox(lv_obj_t *parent, int x, int w) {
  const bool setup = s_web_ctx == WEB_CTX_SETUP;
  lv_obj_t *box = lv_obj_create(parent);
  lv_obj_set_size(box, w, setup ? WEB_SETUP_ROW_H : WEB_ROW_H);
  lv_obj_set_pos(box, x, setup ? WEB_SETUP_ROW_Y : WEB_ROW_Y);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_ROW_PRESSED), 0);
  lv_obj_set_style_radius(box, UI_RADIUS_ROW, 0);
  lv_obj_set_style_pad_hor(box, 14, 0);
  lv_obj_set_style_pad_ver(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_CLICKABLE);
  return box;
}

static void setCredentialRow(lv_obj_t *label, bool present) {
  if (!label) return;
  lv_label_set_text(label, present ? T(STR_BACKEND_SET) : T(STR_BACKEND_MISSING));
  lv_obj_set_style_text_color(label, lv_color_hex(present ? UI_COL_OK_TEXT_2 : UI_COL_WARN), 0);
}

// One credential in a row box: name on the left, state on the right, moved
// off the middle by y_ofs when two share a box. Two in one half take the
// small font: "Jeton d'appareil" and "en mémoire" overlap at 14. Returns the
// state label so it can be updated without rebuilding the screen.
static lv_obj_t* addCredentialLine(lv_obj_t *box, int y_ofs, int name_id, bool present) {
  const lv_font_t *font = y_ofs ? UI_FONT_CAPTION : UI_FONT_SMALL;
  lv_obj_t *l = webLabel(box, T(name_id), font, UI_COL_INK_2);
  lv_obj_align(l, LV_ALIGN_LEFT_MID, 0, y_ofs);
  lv_obj_t *v = webLabel(box, "", font, UI_COL_WARN);
  lv_obj_align(v, LV_ALIGN_RIGHT_MID, 0, y_ofs);
  setCredentialRow(v, present);
  return v;
}

// Remembers what the rows currently say. Rewriting a label invalidates it and
// forces a redraw, and this runs on every pass of the main loop, so the text
// is only touched when it actually changed.
static bool s_key_shown   = false;
static bool s_token_shown = false;

void refreshWebCredentialRows() {
  if (!s_lbl_key_val && !s_lbl_token_val) return;

  // Several navigation paths delete this screen without knowing about the two
  // labels on it. They all null the screen pointer, so that is the reliable
  // signal that the labels are gone too. Dropping them here means this runs
  // on every loop pass without ever reaching freed memory.
  if (!scr_ota_browser) {
    s_lbl_key_val = nullptr;
    s_lbl_token_val = nullptr;
    return;
  }
  if (lv_obj_has_flag(scr_ota_browser, LV_OBJ_FLAG_HIDDEN)) return;

  // BamBuddy has a single key and no second row at all, so the token half
  // stays untouched there.
  const bool bb = oneKeyOnly();
  bool key_now   = activeKeyPresent();
  bool token_now = bb ? false : (filamanDeviceToken()[0] != '\0');

  if (key_now != s_key_shown) {
    s_key_shown = key_now;
    setCredentialRow(s_lbl_key_val, key_now);
    logSDf("Web: API key now %s", key_now ? "set" : "missing");
  }
  if (s_lbl_token_val && token_now != s_token_shown) {
    s_token_shown = token_now;
    setCredentialRow(s_lbl_token_val, token_now);
    logSDf("Web: device token now %s", token_now ? "set" : "missing");
  }
}

// The address as a QR code over the whole screen. A tap anywhere closes it,
// the X included: it is drawn, but the tap goes through it to the page, so it
// closes the page rather than the whole screen.
static void webCloseQrPage(lv_event_t *e) {
  if (s_qr_page) lv_obj_del_async(s_qr_page);
  s_qr_page = nullptr;
}

static void webShowQrPage(lv_event_t *e) {
  if (s_qr_page || !scr_ota_browser) return;
  logSDf("BTN: Web interface -> QR code (%s)", s_qr_url);
  s_qr_page = lv_obj_create(scr_ota_browser);
  lv_obj_set_size(s_qr_page, 480, 320);
  lv_obj_set_pos(s_qr_page, 0, 0);
  lv_obj_set_style_bg_color(s_qr_page, lv_color_hex(UI_COL_GROUND), 0);
  lv_obj_set_style_border_width(s_qr_page, 0, 0);
  lv_obj_set_style_radius(s_qr_page, 0, 0);
  lv_obj_set_style_pad_all(s_qr_page, 0, 0);
  lv_obj_clear_flag(s_qr_page, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(s_qr_page, webCloseQrPage, LV_EVENT_CLICKED, NULL);

  lv_obj_align(webLabel(s_qr_page, T(STR_WEB_QR_BTN), UI_FONT_TITLE, UI_COL_ACCENT), LV_ALIGN_TOP_MID, 0, 12);
  lv_obj_clear_flag(addCloseButton(s_qr_page), LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *frame = lv_obj_create(s_qr_page);
  lv_obj_set_size(frame, WEB_QR_FRAME_PX, WEB_QR_FRAME_PX);
  lv_obj_align(frame, LV_ALIGN_TOP_MID, 0, WEB_QR_FRAME_Y);
  lv_obj_set_style_bg_color(frame, lv_color_hex(UI_COL_QR_LIGHT), 0);
  lv_obj_set_style_border_width(frame, 0, 0);
  lv_obj_set_style_radius(frame, UI_RADIUS_BOX, 0);
  lv_obj_clear_flag(frame, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(frame, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_t *qr = lv_qrcode_create(frame, WEB_QR_CODE_PX, lv_color_hex(UI_COL_QR_DARK), lv_color_hex(UI_COL_QR_LIGHT));
  if (!qr) {
    logSD("Web: no room for the QR code in the LVGL pool");
  } else {
    if (lv_qrcode_update(qr, s_qr_url, strlen(s_qr_url)) != LV_RES_OK) logSD("Web: QR code update failed");
    lv_obj_center(qr);
  }

  lv_obj_align(webLabel(s_qr_page, s_qr_url, UI_FONT_BODY, UI_COL_ACCENT), LV_ALIGN_TOP_MID, 0, WEB_QR_URL_Y);
  lv_obj_align(webLabel(s_qr_page, T(STR_WEB_QR_HINT), UI_FONT_CAPTION, UI_COL_CAPTION), LV_ALIGN_TOP_MID, 0, WEB_QR_HINT_Y);
}

static void webBuildQrButton(lv_obj_t *card) {
  lv_obj_t *b = lv_btn_create(card);
  lv_obj_set_size(b, WEB_QR_BTN_PX, WEB_QR_BTN_PX);
  lv_obj_set_pos(b, WEB_QR_BTN_INSET, WEB_QR_BTN_INSET);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ACCENT_CHIP), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_GO_BG_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(b, 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_radius(b, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_flex_flow(b, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(b, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_row(b, 8, 0);
  lv_obj_add_event_cb(b, webShowQrPage, LV_EVENT_CLICKED, NULL);

  lv_obj_t *img = lv_img_create(b);
  lv_img_set_src(img, &ICON_QR);
  lv_obj_set_style_img_recolor(img, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_img_recolor_opa(img, LV_OPA_COVER, 0);
  webLabel(b, T(STR_WEB_QR_BTN), UI_FONT_SMALL, UI_COL_ACCENT);
}

// The address beside the button: the scheme small, the name large, and the
// IP under it for a phone or a network that does not resolve the name. Some
// Android versions still will not resolve a .local name, a DNS name only
// works where the network serves it, and the person at the scale cannot know
// which before trying.
static void webBuildAddress(lv_obj_t *card, const char *path) {
  char base[DEVICE_FQDN_MAX + 16];
  deviceBrowserUrl(base, sizeof(base));
  char alt[48] = "";
  deviceAltAddress(alt, sizeof(alt));

  const char *scheme_end = strstr(base, "://");
  const char *host = scheme_end ? scheme_end + 3 : base;
  char big[WEB_URL_MAX];
  snprintf(big, sizeof(big), "%s%s", host, path);
  if (alt[0]) snprintf(s_qr_url, sizeof(s_qr_url), "http://%s%s", alt, path);
  else        snprintf(s_qr_url, sizeof(s_qr_url), "%s%s", base, path);

  char scheme[16];
  snprintf(scheme, sizeof(scheme), "%.*s", scheme_end ? (int)(scheme_end - base + 3) : 0, base);
  lv_obj_set_pos(webLabel(card, scheme, UI_FONT_SMALL, UI_COL_CAPTION), WEB_TEXT_X, 16);

  // A long device name drops a size rather than run past the card.
  const lv_font_t *font = UI_FONT_HEADLINE;
  if (lv_txt_get_width(big, strlen(big), font, 0, LV_TEXT_FLAG_NONE) > WEB_TEXT_W) font = UI_FONT_BODY;
  lv_obj_t *name = webLabel(card, big, font, UI_COL_ACCENT);
  lv_label_set_long_mode(name, LV_LABEL_LONG_DOT);
  lv_obj_set_width(name, WEB_TEXT_W);
  lv_obj_set_pos(name, WEB_TEXT_X, 36);
  if (!alt[0]) return;

  char ip[WEB_URL_MAX];
  snprintf(ip, sizeof(ip), "%s%s", alt, path);
  lv_obj_t *or_lbl = webLabel(card, T(STR_WEB_OR), UI_FONT_SMALL, UI_COL_CAPTION);
  lv_obj_set_pos(or_lbl, WEB_TEXT_X, 78);
  lv_obj_t *ip_lbl = webLabel(card, ip, UI_FONT_TITLE, UI_COL_INK_2);
  lv_obj_align_to(ip_lbl, or_lbl, LV_ALIGN_OUT_RIGHT_BOTTOM, 8, 2);
}

static void webBuildCard(lv_obj_t *scr, const char *path) {
  lv_obj_t *card = lv_obj_create(scr);
  lv_obj_set_size(card, WEB_CARD_W, WEB_CARD_H);
  lv_obj_set_pos(card, WEB_CARD_X, WEB_CARD_Y);
  lv_obj_set_style_bg_color(card, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_width(card, 1, 0);
  lv_obj_set_style_border_color(card, lv_color_hex(UI_COL_LINE_SOFT), 0);
  lv_obj_set_style_radius(card, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(card, 0, 0);
  lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(card, LV_OBJ_FLAG_CLICKABLE);
  webBuildQrButton(card);
  webBuildAddress(card, path);
}

// Says what just happened, right under the address it made reachable, in the
// amber this screen uses for "not there yet".
static void webBuildGatePill(lv_obj_t *scr) {
  lv_obj_t *pill = webLabel(scr, T(STR_WEB_GATE_OPENED), UI_FONT_CAPTION, UI_COL_WARN);
  lv_obj_set_style_bg_color(pill, lv_color_hex(UI_COL_AMBER_BG), 0);
  lv_obj_set_style_bg_opa(pill, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(pill, 1, 0);
  lv_obj_set_style_border_color(pill, lv_color_hex(UI_COL_AMBER_LINE), 0);
  lv_obj_set_style_radius(pill, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_pad_hor(pill, 12, 0);
  lv_obj_set_style_pad_ver(pill, 4, 0);
  lv_obj_align(pill, LV_ALIGN_TOP_MID, 0, WEB_PILL_Y);
}

// FilaMan's two credentials in halves, BamBuddy's one across. During the
// setup the step's bar follows under them: later, or on - both lead to the
// scale, the rows only say what is still missing.
static void webBuildCredentials(lv_obj_t *scr) {
  const bool bb = oneKeyOnly();
  s_key_shown   = activeKeyPresent();
  s_token_shown = !bb && (filamanDeviceToken()[0] != '\0');
  s_lbl_token_val = nullptr;

  lv_obj_t *box = webRowBox(scr, WEB_CARD_X, bb ? WEB_CARD_W : WEB_HALF_W);
  s_lbl_key_val = addCredentialLine(box, 0, STR_BACKEND_APIKEY, s_key_shown);
  if (!bb) {
    lv_obj_t *token_box = webRowBox(scr, WEB_HALF_X2, WEB_HALF_W);
    s_lbl_token_val = addCredentialLine(token_box, 0, STR_BACKEND_DEVICE_TOKEN, s_token_shown);
  }
  if (s_web_ctx != WEB_CTX_SETUP) return;

  // Deferred: the next step deletes this very screen, which must not happen
  // while its own button callback is still running.
  char next_buf[32];
  snprintf(next_buf, sizeof(next_buf), "%s  " LV_SYMBOL_RIGHT, T(STR_BTN_NEXT));
  setupActionBar(scr,
    T(STR_SETUP_LATER), [](lv_event_t *e){
      logSD("BTN: Web interface -> Setup: credentials later");
      cal_reminder_pending = true;
    },
    next_buf, [](lv_event_t *e){
      logSD("BTN: Web interface -> Setup: next");
      cal_reminder_pending = true;
    });
}

// The upload's status on the left, written by the web upload from the loop,
// the file it wants under it. The installed version on the right, so the file
// can be checked against it before it is sent. No stop button: leaving the
// screen closes what it opened, see showOtaBrowserScreen().
static void webBuildFirmwareRow(lv_obj_t *scr) {
  lv_obj_t *box = webRowBox(scr, WEB_CARD_X, WEB_CARD_W);
  lbl_ota_status = webLabel(box, T(STR_OTA_WAITING), UI_FONT_BODY, UI_COL_WARN);
  lv_label_set_long_mode(lbl_ota_status, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_ota_status, WEB_FW_STATUS_W);
  lv_obj_align(lbl_ota_status, LV_ALIGN_LEFT_MID, 0, -WEB_FW_LINE_DY);
  s_lbl_ota_hint = webLabel(box, T(STR_OTA_FILE_NAME), UI_FONT_CAPTION, UI_COL_CAPTION);
  lv_obj_align(s_lbl_ota_hint, LV_ALIGN_LEFT_MID, 0, WEB_FW_LINE_DY);

  lv_obj_align(webLabel(box, T(STR_OTA_INSTALLED_CAP), UI_FONT_CAPTION, UI_COL_CAPTION),
               LV_ALIGN_RIGHT_MID, 0, -WEB_FW_LINE_DY);
  lv_obj_align(webLabel(box, FW_VERSION, UI_FONT_SMALL, UI_COL_INK_2),
               LV_ALIGN_RIGHT_MID, 0, WEB_FW_LINE_DY);
}

void otaBrowserShowUploadFailed() {
  if (!lbl_ota_status) return;
  lv_label_set_text(lbl_ota_status, T(STR_OTA_FAIL));
  lv_obj_set_style_text_color(lbl_ota_status, lv_color_hex(UI_COL_BAD_TEXT), 0);
  lv_label_set_text(s_lbl_ota_hint, T(STR_OTA_RETRY_HINT));
}

static void webBuildDryingRow(lv_obj_t *scr) {
  lv_obj_t *box = webRowBox(scr, WEB_CARD_X, WEB_CARD_W);
  lv_obj_t *l = webLabel(box, T(STR_WEB_DRY_HINT), UI_FONT_SMALL, UI_COL_INK_2);
  lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(l, lv_pct(100));
  lv_obj_align(l, LV_ALIGN_LEFT_MID, 0, 0);
}

static void webBuildHeader(lv_obj_t *scr, const char *title) {
  if (s_web_ctx == WEB_CTX_SETUP) {
    // A step of the setup: back to the address it follows on from.
    setupHeader(scr, T(STR_SETUP_CREDS_TITLE), SETUP_STEP_CREDENTIALS, [](lv_event_t *e){
      logSD("BTN: Web interface -> Setup: back to the address");
      // An online service has no address step, its page came before this one.
      if (backendProfileIsOnline()) show_online_pending = true;
      else                          show_spoolman_pending = true;
    });
    return;
  }
  lv_event_cb_t back = [](lv_event_t *e){
    logSD("BTN: Web interface -> Back");
    // Back does not close the server itself. The screen that comes next hides
    // this one, which ends the visit, and the loop's once-a-second
    // webServerSyncState() follows the switches from there.
    // Back goes where the user came from, not always to the update menu.
    switch (s_web_ctx) {
      case WEB_CTX_BACKEND: show_backend_pending         = true; break;
      case WEB_CTX_ADDRESS: show_spoolman_pending        = true; break;
      case WEB_CTX_DRYING:  show_drying_reminder_pending  = true; break;
      default:              show_ota_pending              = true; break;
    }
  };
  // From the address screen during the setup: still the server step.
  if (s_web_ctx == WEB_CTX_ADDRESS) setupOrSettingsHeader(scr, title, SETUP_STEP_SERVER, back);
  else                              buildSubHeader(scr, title, back);
}

// Only right after connecting. No lv_timer_handler() in here: this screen is
// also opened from button callbacks, and running the LVGL handler from inside
// one would dispatch touch events again while the screen is half built.
static void webWaitForIp() {
  unsigned long t = millis();
  while (wifiManagerLocalIP() == IPAddress(0,0,0,0) && millis() - t < 3000) {
    delay(50);
  }
}

void buildOtaBrowserScreen() {
  logSD("BUILD: OtaBrowserScreen");
  releaseScreen(&scr_ota_browser);
  s_lbl_key_val = nullptr;
  s_lbl_token_val = nullptr;
  s_qr_page = nullptr;
  scr_ota_browser = buildOverlayScreen();
  webBuildHeader(scr_ota_browser, isFirmwareContext() ? T(STR_OTA_BROWSER_TITLE) : T(STR_WEB_TITLE));

  if (!wifi_ok) {
    lv_obj_t *lbl_err = webLabel(scr_ota_browser, T(STR_OTA_NO_WIFI), UI_FONT_BODY, UI_COL_BAD_TEXT);
    lv_obj_set_style_text_align(lbl_err, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_err, LV_ALIGN_CENTER, 0, 0);
    return;
  }
  webWaitForIp();

  const int step_id = !showsCredentials() ? STR_OTA_OPEN_BROWSER
                    : oneKeyOnly()         ? STR_WEB_STEP_CREDS_BB
                                           : STR_WEB_STEP_CREDS;
  lv_obj_align(webLabel(scr_ota_browser, T(step_id), UI_FONT_SMALL, UI_COL_INK_SOFT), LV_ALIGN_TOP_MID, 0, WEB_STEP_Y);
  // "/" is the status page, so each flow goes to the page that carries its
  // form, see webTargetFor().
  webBuildCard(scr_ota_browser, webTargetFor(s_web_ctx).path);
  // Not in the setup: its row and bar take the room the pill would need, and
  // the step line above already says where to go.
  if (s_gate_opened && s_web_ctx != WEB_CTX_SETUP) webBuildGatePill(scr_ota_browser);

  if (showsCredentials())      webBuildCredentials(scr_ota_browser);
  else if (isFirmwareContext()) webBuildFirmwareRow(scr_ota_browser);
  else if (s_web_ctx == WEB_CTX_DRYING) webBuildDryingRow(scr_ota_browser);
}

// Called wherever this screen is hidden or deleted. Ends the visit and lets
// the socket follow at once, as showing the screen does. An upload cannot be
// cut off by it: the upload holds the loop, touch included, until it is over.
void otaBrowserEndVisit() {
  if (webVisitEnd()) webServerSyncState();
}
