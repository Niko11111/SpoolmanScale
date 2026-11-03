#include "spoolman_screen.h"
#include "app/backend_switch.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "connection_screen.h"
#include "ota_browser.h"
#include "hardware/sd_logger.h"
#include "services/app_settings.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/backend_http.h"
#include "services/server_refusal.h"
#include "services/bambuddy_api.h"
#include "header_status.h"
#include "services/device_name.h"
#include "services/wifi_manager.h"
#include "web/web_access.h"
#include "confirm_popup.h"
#include "lang.h"
#include "ui_common.h"
#include "setup_frame.h"
#include "theme.h"



// Input buffer for Spoolman IP
static char sp_ip_input[64] = "";
// What the field held when the screen opened. The back button used to write
// unconditionally, so merely opening the screen and leaving it rewrote NVS -
// and on a host name a single stray tap appended a digit to it.
static char sp_ip_original[64] = "";
// True when the stored address cannot be typed on this screen.
static bool sp_locked = false;

// Every character the twelve key pad can produce. An empty host counts as
// numeric: there is nothing to protect yet, and the pad is the right tool.
//
// The address field is a plain string shared with the browser, and the browser
// has a real keyboard - it even advertises host names, because a reverse proxy
// tells its backends apart by the Host header. A name that arrives that way
// cannot be edited here, only damaged.
static bool hostIsNumeric(const char* h) {
  if (!h) return true;
  for (; *h; h++)
    if (!((*h >= '0' && *h <= '9') || *h == '.' || *h == ':')) return false;
  return true;
}

// Where to go to change it. Same cascade as the web screen (web_screen.cpp),
// because pointing at an address that does not answer is worse than saying
// which switch is off.
static void browserAddress(char* out, size_t len) {
  if (!webMasterEnabled())  { copyT(out, len, STR_SP_WEB_OFF); }
  else if (!wifi_ok)        { copyT(out, len, STR_WIFI_STATUS_DISCONNECTED); }
  else                      { deviceBrowserUrl(out, len); return; }
  out[len - 1] = '\0';
}

void spoolmanClearHost() {
  logSDf("Backend: address cleared on the device (was %s)", backendHost());
  backendApplyHost("");
  sp_ip_input[0] = '\0';
  show_spoolman_pending = true;   // rebuilt one loop pass later, never here
}
static lv_obj_t *lbl_sp_ip_display = nullptr;
// The result of the address test: a card under the field, its two lines.
static lv_obj_t *sp_card        = nullptr;
static lv_obj_t *sp_card_title  = nullptr;
static lv_obj_t *sp_card_detail = nullptr;
static SetupBar  sp_bar         = { nullptr, nullptr, nullptr };
// In the setup the main button turns from Connect into Next once the server
// answered; typing again turns it back.
static bool sp_can_continue = false;
// In the setup, after a test that got no usable answer: the quiet button
// offers Later instead of the browser, so a server that is not running yet
// does not hold the whole setup up.
static bool sp_offer_later = false;
// The save button parks the address test here; appLoop() runs it.
static bool sp_test_pending = false;
static void runAddressTest();

void handleSpoolmanScreenDeferredActions() {
  if (!sp_test_pending) return;
  sp_test_pending = false;
  if (!scr_spoolman) return;      // the screen went away before its pass
  runAddressTest();
}

void closeSpoolmanScreen() {
  sp_test_pending   = false;
  sp_can_continue   = false;
  lbl_sp_ip_display = nullptr;
  sp_card = sp_card_title = sp_card_detail = nullptr;
  sp_bar  = { nullptr, nullptr, nullptr };
  if (scr_spoolman) { lv_obj_del(scr_spoolman); scr_spoolman = nullptr; }
}

enum SpTone : uint8_t { SP_TONE_BUSY, SP_TONE_OK, SP_TONE_WARN, SP_TONE_BAD };

// One result at a time, in the card's colours: green when the server
// answered, amber when it is there but wants a key, red when nothing came.
static void showTestResult(SpTone tone, int title_id, const char *detail) {
  if (!sp_card) return;
  uint32_t bg = UI_COL_SURFACE, border = UI_COL_LINE_SOFT;
  if (tone == SP_TONE_OK)   { bg = UI_COL_PICKED_BG; border = UI_COL_ACCENT; }
  if (tone == SP_TONE_WARN) { bg = UI_COL_AMBER_BG;  border = UI_COL_WARN; }
  if (tone == SP_TONE_BAD)  { bg = UI_COL_BAD_BG;    border = UI_COL_BAD_TEXT; }
  lv_obj_set_style_bg_color(sp_card, lv_color_hex(bg), 0);
  lv_obj_set_style_border_color(sp_card, lv_color_hex(border), 0);
  lv_label_set_text(sp_card_title, T(title_id));
  lv_label_set_text(sp_card_detail, detail ? detail : "");
  lv_obj_clear_flag(sp_card, LV_OBJ_FLAG_HIDDEN);
}

static void setQuietLater(bool later) {
  sp_offer_later = later && setup_active;
  if (!sp_bar.quiet) return;
  lv_obj_t *lbl = lv_obj_get_child(sp_bar.quiet, 0);
  if (lbl) lv_label_set_text(lbl, T(sp_offer_later ? STR_SETUP_LATER : STR_SP_IN_BROWSER));
}

static void setMainContinues(bool cont) {
  sp_can_continue = cont && setup_active;
  if (!sp_bar.main_label) return;
  if (sp_can_continue) {
    char nb[32];
    snprintf(nb, sizeof(nb), "%s  " LV_SYMBOL_RIGHT, T(STR_BTN_NEXT));
    lv_label_set_text(sp_bar.main_label, nb);
  } else {
    lv_label_set_text(sp_bar.main_label, T(STR_SP_CONNECT));
  }
}

// The server is there, but will not work with this scale as it is set up.
static void showRefusedTest(int code) {
  char buf[64];
  snprintf(buf, sizeof(buf), "%s (HTTP %d)", T(serverRefusalTitleId(serverRefusalOf(code))), code);
  showTestResult(SP_TONE_BAD, STR_SP_REACHED, buf);
  setQuietLater(true);
  logSDf("Spoolman IP test: server refuses, HTTP %d", code);
  updateHeaderStatus();
}

// The address test the save button asks for: health, version, spool count -
// up to thirteen seconds of requests. Run from appLoop() one pass after the
// button, never from the button itself, which held the touch panel for the
// whole of it.
static void runAddressTest() {
  // Health check
  int hcode = backendGetHealthCode(cfg_spoolman_base, 4000);
  sm_reachable = (hcode == 200);

  // BamBuddy with authentication answers the credential half of the check
  // with 401 or 403 while the key is missing or wrong. The server is there,
  // and during the setup the key is only entered in the next step, so this
  // leads on to that step instead of ending here.
  if (!sm_reachable && backendIsBamBuddy() && (hcode == 401 || hcode == 403)) {
    const bool has_key = bambuddyApiKey()[0] != '\0';
    char buf[64];
    if (has_key) {
      snprintf(buf, sizeof(buf), "%s (HTTP %d)", T(STR_BB_KEY_REJECTED), hcode);
    } else {
      // The version endpoint is public, so it still names the server.
      char ver[32] = "?";
      backendGetVersion(cfg_spoolman_base, ver, sizeof(ver), 3000);
      snprintf(buf, sizeof(buf), "v%s | %s", ver, T(STR_BB_KEY_MISSING));
    }
    showTestResult(has_key ? SP_TONE_BAD : SP_TONE_WARN, STR_SP_REACHED, buf);
    setMainContinues(true);
    setupNoteKeyRequired(true);
    setupNoteServerLater(false);
    logSDf("Spoolman IP test: BamBuddy reachable, API key %s (HTTP %d)",
           has_key ? "rejected" : "missing", hcode);
    Serial.printf("Spoolman IP test: BamBuddy reachable, API key %s (HTTP %d)\n",
                  has_key ? "rejected" : "missing", hcode);
    updateHeaderStatus();
    return;
  }

  // Spoolman behind a proxy with a password, or a server that speaks its API
  // with a key, answers the same way BamBuddy does above: there, but not open.
  // Said as such rather than as an API error, which reads like a broken server.
  if (!sm_reachable && backendMode() == BACKEND_SPOOLMAN && (hcode == 401 || hcode == 403)) {
    const bool has_access = spoolmanAuthActive();
    char buf[64];
    snprintf(buf, sizeof(buf), "%s (HTTP %d)",
             T(has_access ? STR_SM_AUTH_REJECTED : STR_SM_AUTH_MISSING), hcode);
    showTestResult(SP_TONE_BAD, STR_SP_REACHED, buf);
    setQuietLater(true);
    logSDf("Spoolman IP test: server wants access, %s (HTTP %d)",
           has_access ? "rejected" : "none set", hcode);
    updateHeaderStatus();
    return;
  }

  if (!sm_reachable) {
    char buf[96];
    snprintf(buf, sizeof(buf), "%s (HTTP %d)", T(STR_SP_NO_ANSWER_HINT), hcode);
    showTestResult(SP_TONE_BAD, STR_SP_NO_ANSWER, buf);
    setQuietLater(true);
    logSDf("Spoolman IP test FAIL: HTTP %d ip=%s", hcode, sp_ip_input);
    Serial.printf("Spoolman IP test FAIL: HTTP %d ip=%s\n", hcode, sp_ip_input);
    return;
  }

  // BamBuddy needs to be asked where its inventory lives before anything
  // else is read. Placed after the health check so a wrong address fails
  // on the check rather than here.
  setupNoteServerLater(false);
  setupNoteKeyRequired(false);
  backendAfterConnect();

  // Fetch version from /api/v1/info
  char sm_ver[32] = "?";
  serverRefusalClearSeen();
  backendGetVersion(cfg_spoolman_base, sm_ver, sizeof(sm_ver), 3000);

  int spool_count = backendCountActiveSpools(cfg_spoolman_base, 6000);

  // A server may leave /health open, so the answer above says nothing about
  // the key: these two are the first requests that need one. FilaMan and
  // BamBuddy have their own steps for it during setup.
  if (backendMode() == BACKEND_SPOOLMAN && serverRefusalSeen()) {
    showRefusedTest(serverRefusalSeen());
    return;
  }

  // A negative count means the question could not be answered, not that
  // there are no spools. In FilaMan that is the normal case during setup,
  // because counting needs the API key and it is entered a step later.
  // Printing "0 spools" there would look like an empty database.
  // Which database BamBuddy is on decides which half of the client runs,
  // so it belongs on screen and not only in the log. The two names are the
  // ones BamBuddy uses itself under Settings > Filament Tracking. Empty for
  // the other backends, where there is nothing to choose between.
  char result_buf[96];
  size_t n = (size_t)snprintf(result_buf, sizeof(result_buf), "v%s", sm_ver);
  if (backendIsBamBuddy() && n < sizeof(result_buf)) {
    char inv_name[24];
    copyT(inv_name, sizeof(inv_name), bbInventoryMode() == BB_INV_SPOOLMAN ? STR_BB_INV_SPOOLMAN : STR_BB_INV_OWN);
    n += (size_t)snprintf(result_buf + n, sizeof(result_buf) - n, " | %s", inv_name);
  }
  if (spool_count >= 0 && n < sizeof(result_buf)) {
    char cnt[32];
    snprintf(cnt, sizeof(cnt), T(STR_SPOOLS_COUNT), spool_count);
    snprintf(result_buf + n, sizeof(result_buf) - n, " | %s", cnt);
  }
  showTestResult(SP_TONE_OK, STR_SP_CONNECTED, result_buf);
  setMainContinues(true);

  logSDf("Spoolman IP test OK: %s | %d spools", sm_ver, spool_count);
  Serial.printf("Spoolman IP test OK: %s | %d spools\n", sm_ver, spool_count);
  updateHeaderStatus();
}

// ---- layout ---------------------------------------------------
// Left: the field, an example and the result card. Right: the pad.
#define SP_COL_X         12
#define SP_COL_W        200
#define SP_CAPTION_Y     54
#define SP_FIELD_Y       72
#define SP_FIELD_H       44
#define SP_EXAMPLE_Y    124
#define SP_CARD_Y       148
#define SP_CARD_H        96
#define SP_CARD_PAD      10
#define SP_PAD_X        224
#define SP_PAD_Y         54
#define SP_PAD_W        244
#define SP_KEY_H         44
#define SP_KEY_GAP        5
#define SP_PAD_COLS       4

static void refreshAddress() {
  if (lbl_sp_ip_display) lv_label_set_text(lbl_sp_ip_display, sp_ip_input[0] ? sp_ip_input : "_");
  // A changed address has not been tested: back to Connect.
  if (sp_can_continue) setMainContinues(false);
  if (sp_offer_later) setQuietLater(false);
  if (sp_card) lv_obj_add_flag(sp_card, LV_OBJ_FLAG_HIDDEN);
}

static void onPadKey(lv_event_t *e) {
  const char* ch = lv_label_get_text(lv_obj_get_child(lv_event_get_target(e), 0));
  const int len = strlen(sp_ip_input);
  if (len < (int)sizeof(sp_ip_input) - 1) {
    sp_ip_input[len] = ch[0];
    sp_ip_input[len + 1] = '\0';
  }
  refreshAddress();
}

static void onPadDelete(lv_event_t *e) {
  const int len = strlen(sp_ip_input);
  if (len > 0) sp_ip_input[len - 1] = '\0';
  refreshAddress();
}

// Connect, or in the setup after a good answer, on to the next step.
static void onAddressMain(lv_event_t *e) {
  if (sp_can_continue) {
    if (backendInfo(backendMode()).auth_in_browser) {
      // Next comes the credential step, and those are entered in a browser.
      showOtaBrowserScreen(WEB_CTX_SETUP);
    } else {
      // Spoolman needs no step of its own any more: the tag source is picked
      // on the first scan and a missing field is created on its first write
      // (Nikolai, 25.09.2026). Deferred, never from the callback.
      cal_reminder_pending = true;
    }
    return;
  }
  if (!sp_ip_input[0]) return;
  backendApplyHost(sp_ip_input);
  // Says "testing" now, tests on the next loop pass.
  showTestResult(SP_TONE_BUSY, STR_SPOOLMAN_TESTING, "");
  sp_test_pending = true;
  updateHeaderStatus();
}

// Twelve keys and delete: 1 2 3 del / 4 5 6 . / 7 8 9 : / 0 across.
static void buildAddressPad(lv_obj_t *scr) {
  static const char *const KEYS[] = { "1","2","3","", "4","5","6",".", "7","8","9",":", "0" };
  const int key_w = (SP_PAD_W - (SP_PAD_COLS - 1) * SP_KEY_GAP) / SP_PAD_COLS;
  for (int i = 0; i < (int)(sizeof(KEYS) / sizeof(KEYS[0])); i++) {
    const int col = i % SP_PAD_COLS, row = i / SP_PAD_COLS;
    const bool del  = (i == 3);
    const bool zero = (i == 12);
    const bool sep  = KEYS[i][0] == '.' || KEYS[i][0] == ':';
    lv_obj_t *b = padButton(scr, SP_PAD_X + col * (key_w + SP_KEY_GAP),
                            SP_PAD_Y + row * (SP_KEY_H + SP_KEY_GAP),
                            zero ? SP_PAD_W : key_w, SP_KEY_H,
                            (del || sep) ? UI_COL_ROW : UI_COL_SURFACE, UI_COL_PRESS_FILL);
    padLabel(b, del ? LV_SYMBOL_BACKSPACE : KEYS[i], del ? UI_COL_INK_2 : UI_COL_INK,
             del ? UI_FONT_BODY : UI_FONT_TITLE);
    lv_obj_add_event_cb(b, del ? onPadDelete : onPadKey, LV_EVENT_CLICKED, NULL);
  }
}

// An address the pad cannot type - a name or https - is not edited here at
// all rather than on a dead pad: what it is, where to change it, and a way
// to clear it, because a typo made in the browser cannot be undone here.
static void buildLockedColumn(lv_obj_t *scr) {
  lv_obj_t *why = lv_label_create(scr);
  lv_obj_set_width(why, SP_PAD_W);
  lv_label_set_long_mode(why, LV_LABEL_LONG_WRAP);
  char buf_why[128];
  copyT(buf_why, sizeof(buf_why), STR_SP_LOCKED_INFO);
  lv_label_set_text(why, buf_why);
  lv_obj_set_style_text_color(why, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(why, UI_FONT_SMALL, 0);
  lv_obj_set_pos(why, SP_PAD_X, SP_PAD_Y);

  char buf_addr[64];
  browserAddress(buf_addr, sizeof(buf_addr));
  lv_obj_t *addr = lv_label_create(scr);
  lv_obj_set_width(addr, SP_PAD_W);
  lv_label_set_long_mode(addr, LV_LABEL_LONG_WRAP);
  lv_label_set_text(addr, buf_addr);
  lv_obj_set_style_text_color(addr, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(addr, UI_FONT_SMALL, 0);
  lv_obj_align_to(addr, why, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 8);

  lv_obj_t *clr = padButton(scr, SP_PAD_X, SP_CARD_Y + SP_CARD_H - SP_KEY_H, SP_PAD_W, SP_KEY_H,
                            UI_COL_BAD_BG, UI_COL_BAD_BG_PRESSED);
  lv_obj_add_event_cb(clr, [](lv_event_t *e) {
    // Asks, then acts one loop pass later. Nothing is deleted from inside
    // this callback.
    showConfirmPopup(T(STR_SP_CLEAR_ASK), 4);
  }, LV_EVENT_CLICKED, NULL);
  char buf_clear[32];
  copyT(buf_clear, sizeof(buf_clear), STR_SP_CLEAR);
  padLabel(clr, buf_clear, UI_COL_BAD_TEXT, UI_FONT_BODY);
}

static lv_obj_t *columnLabel(lv_obj_t *scr, const char *text, const lv_font_t *font,
                             uint32_t col, int y) {
  lv_obj_t *l = lv_label_create(scr);
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
  lv_obj_set_size(l, SP_COL_W, lv_font_get_line_height(font));
  lv_label_set_text(l, text);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(col), 0);
  lv_obj_set_pos(l, SP_COL_X + 2, y);
  return l;
}

static void buildAddressColumn(lv_obj_t *scr) {
  columnLabel(scr, T(STR_BACKEND_ADDRESS), UI_FONT_CAPTION, UI_COL_INK_SOFT, SP_CAPTION_Y);

  lv_obj_t *field = lv_obj_create(scr);
  lv_obj_set_size(field, SP_COL_W, SP_FIELD_H);
  lv_obj_set_pos(field, SP_COL_X, SP_FIELD_Y);
  lv_obj_set_style_bg_color(field, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(field, lv_color_hex(sp_locked ? UI_COL_WARN : UI_COL_ACCENT), 0);
  lv_obj_set_style_border_width(field, 2, 0);
  lv_obj_set_style_radius(field, UI_RADIUS_ROW, 0);
  lv_obj_set_style_pad_all(field, 0, 0);
  lv_obj_clear_flag(field, LV_OBJ_FLAG_SCROLLABLE);
  lbl_sp_ip_display = lv_label_create(field);
  lv_label_set_long_mode(lbl_sp_ip_display, LV_LABEL_LONG_DOT);
  lv_obj_set_size(lbl_sp_ip_display, SP_COL_W - 2 * SP_CARD_PAD, lv_font_get_line_height(UI_FONT_BODY));
  lv_label_set_text(lbl_sp_ip_display, sp_ip_input[0] ? sp_ip_input : "_");
  lv_obj_set_style_text_color(lbl_sp_ip_display, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(lbl_sp_ip_display, UI_FONT_BODY, 0);
  lv_obj_align(lbl_sp_ip_display, LV_ALIGN_LEFT_MID, SP_CARD_PAD, 0);

  // An https address is locked for the same reason as a name - the pad has
  // no letters - but says what it is, so nobody takes it for a typo.
  char buf_ex[64];
  if (sp_locked) {
    copyT(buf_ex, sizeof(buf_ex),
          backendUrlIsHttps(backendHost()) ? STR_SP_HTTPS_TITLE : STR_SP_LOCKED_TITLE);
  } else {
    // Only an example: an address typed without a port goes to 80.
    snprintf(buf_ex, sizeof(buf_ex), T(STR_SP_EXAMPLE), backendInfo(backendMode()).default_port);
  }
  columnLabel(scr, buf_ex, UI_FONT_CAPTION, sp_locked ? UI_COL_WARN : UI_COL_INK_SOFT, SP_EXAMPLE_Y);

  sp_card = lv_obj_create(scr);
  lv_obj_set_size(sp_card, SP_COL_W, SP_CARD_H);
  lv_obj_set_pos(sp_card, SP_COL_X, SP_CARD_Y);
  lv_obj_set_style_radius(sp_card, UI_RADIUS_ROW, 0);
  lv_obj_set_style_border_width(sp_card, 1, 0);
  lv_obj_set_style_pad_all(sp_card, SP_CARD_PAD, 0);
  lv_obj_clear_flag(sp_card, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_flag(sp_card, LV_OBJ_FLAG_HIDDEN);
  sp_card_title = lv_label_create(sp_card);
  lv_label_set_long_mode(sp_card_title, LV_LABEL_LONG_DOT);
  lv_obj_set_size(sp_card_title, SP_COL_W - 2 * SP_CARD_PAD, lv_font_get_line_height(UI_FONT_BODY));
  lv_obj_set_style_text_font(sp_card_title, UI_FONT_BODY, 0);
  lv_obj_set_style_text_color(sp_card_title, lv_color_hex(UI_COL_INK), 0);
  sp_card_detail = lv_label_create(sp_card);
  lv_label_set_long_mode(sp_card_detail, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(sp_card_detail, SP_COL_W - 2 * SP_CARD_PAD);
  lv_obj_set_style_text_font(sp_card_detail, UI_FONT_CAPTION, 0);
  lv_obj_set_style_text_color(sp_card_detail, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_pos(sp_card_detail, 0, lv_font_get_line_height(UI_FONT_BODY) + 6);
}

static void onAddressBack(lv_event_t *e) {
  logSD("BTN: Spoolman -> Back");
  // Only on a real change. Writing whatever the field happens to hold
  // turned a look into an edit, which is how one tap could append a
  // digit to a host name and make it unresolvable.
  if (sp_ip_input[0] && strcmp(sp_ip_input, sp_ip_original) != 0)
    backendApplyHost(sp_ip_input);
  // Return to wherever we came from. The Backend screen exists only
  // when the user navigated through it, the setup flow does not.
  if (scr_backend) show_backend_pending = true;
  else             show_connection_from_spoolman_pending = true;
}

void buildSpoolmanScreen() {
  logSD("BUILD: SpoolmanScreen");
  // This is the most object-heavy screen in the project (numpad + header,
  // ~40 LVGL objects). Log LVGL's memory before allocating, so a screen that
  // ends up in PSRAM is visible in the log.
  logLvMem("spoolman", 0);
  releaseScreen(&scr_spoolman);
  scr_spoolman = buildOverlayScreen();
  sp_can_continue = false;
  sp_offer_later = false;
  sp_locked = !hostIsNumeric(backendHost());

  // The product name is not translated, so the table holds only the words
  // around it, and the name is filled in here.
  char buf_title[32];
  snprintf(buf_title, sizeof(buf_title), T(STR_SERVER_TITLE), backendName());
  setupOrSettingsHeader(scr_spoolman, buf_title, SETUP_STEP_SERVER, onAddressBack);

  // Pre-fill with "192.168." if empty - user only needs to add last two octets + port
  const char* cur_host = backendHost();
  snprintf(sp_ip_input, sizeof(sp_ip_input), "%s",
           (cur_host && cur_host[0]) ? cur_host : "192.168.");
  snprintf(sp_ip_original, sizeof(sp_ip_original), "%s", sp_ip_input);

  buildAddressColumn(scr_spoolman);
  if (sp_locked) buildLockedColumn(scr_spoolman);
  else           buildAddressPad(scr_spoolman);

  // The browser takes what the pad cannot: a name, https, a password.
  sp_bar = setupActionBar(scr_spoolman,
    T(STR_SP_IN_BROWSER), [](lv_event_t *e) {
      if (sp_offer_later) {
        // On without a server: the summary says so, Settings sets it later.
        logSD("BTN: Spoolman -> Later (no answer)");
        setupNoteServerLater(true);
        cal_reminder_pending = true;
        return;
      }
      logSD("BTN: Spoolman -> Browser");
      showOtaBrowserScreen(WEB_CTX_ADDRESS);
    },
    T(STR_SP_CONNECT), onAddressMain);
}

