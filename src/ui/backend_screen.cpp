#include "backend_screen.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

// Ahead of lang.h: bambuddy_api.h pulls in ArduinoJson, whose template
// parameter T collides with the T() macro.
#include "services/bambuddy_api.h"

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/backend_profiles.h"
#include "header_status.h"
#include "lang.h"
#include "navigation.h"
#include "ota_browser.h"
#include "tag_display.h"
#include "app/backend_switch.h"
#include "ui_common.h"
#include "setup_frame.h"
#include "info_screen.h"
#include "wifi_setup_screen.h"
#include "theme.h"

// Switching the mode has to happen outside this screen's own event callback,
// otherwise the callback would delete the button it is currently running on.
// The flag is consumed in appLoop(), which rebuilds the screen.
static BackendMode s_pending_mode = BACKEND_SPOOLMAN;
static bool s_mode_change_pending = false;
// A tile picked in the setup: once the mode is set, the address is next.
static bool s_then_address = false;

static void applyPendingModeChange() {
  if (!s_mode_change_pending) return;
  s_mode_change_pending = false;
  // With the colours following the backend, this switch may move the panel
  // into another family. A palette is read at boot, so the restart is offered
  // the way the language screen offers it; appLoop() opens the question on
  // its next pass, over the rebuilt screen. Asked before the switch, which
  // changes what "the current backend" is.
  const bool palette_moves = !setup_active && uiThemeFollowMoves(s_pending_mode);
  // One switch for both entry points. What it lets go of used to be spelled
  // out here and stopped after three steps - see app/backend_switch.cpp.
  backendApplyMode(s_pending_mode);
  if (palette_moves) {
    logSD("Theme: the backend switch moves the palette, restart offered");
    show_reboot_pending = true;
  }
}

// Full width row that opens another screen: title on top, a value line under
// it and an arrow on the right. Shared by the address row and the extra fields
// row, which are the same shape.
static lv_obj_t* addNavRow(lv_obj_t *parent, int y, const char *title,
                           const char *value, uint32_t value_color,
                           lv_event_cb_t cb) {
  lv_obj_t *row = lv_btn_create(parent);
  lv_obj_set_size(row, 448, 56);
  lv_obj_set_pos(row, 16, y);
  lv_obj_set_style_bg_color(row, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(row, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_radius(row, 10, 0);
  lv_obj_set_style_shadow_width(row, 0, 0);
  lv_obj_set_style_border_width(row, 1, 0);
  lv_obj_set_style_border_color(row, lv_color_hex(UI_COL_ROW_PRESSED), 0);
  lv_obj_add_event_cb(row, cb, LV_EVENT_CLICKED, NULL);

  lv_obj_t *l = lv_label_create(row);
  lv_label_set_text(l, title);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(l, LV_ALIGN_LEFT_MID, 8, -11);

  lv_obj_t *s = lv_label_create(row);
  lv_label_set_text(s, value);
  lv_obj_set_style_text_color(s, lv_color_hex(value_color), 0);
  lv_obj_set_style_text_font(s, &lv_font_montserrat_ext_14, 0);
  lv_obj_align(s, LV_ALIGN_LEFT_MID, 8, 12);

  lv_obj_t *a = lv_label_create(row);
  lv_label_set_text(a, LV_SYMBOL_RIGHT);
  lv_obj_set_style_text_color(a, lv_color_hex(UI_COL_CAPTION), 0);
  lv_obj_set_style_text_font(a, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(a, LV_ALIGN_RIGHT_MID, -10, 0);
  return row;
}

// Credentials, one column each: label on top, state under it. The two used to
// sit side by side with their values pushed to column edges, which put the
// first "set" ten pixels from the *other* label and read as belonging to it.
// Stacking is the strongest grouping there is, and it matches the address row
// right above - same label size and colour, same offset to the value.
// label_b may be null, which BamBuddy used before it had something to put
// there. value_b replaces the set/missing wording in the second column: not
// every thing worth showing next to a credential is a credential, and the
// active database is the example - it is not set or missing, it has a name.
static void addCredentialsRow(lv_obj_t *parent, int y,
                              const char *label_a, bool present_a,
                              const char *label_b, bool present_b,
                              const char *value_b = nullptr) {
  const char *labels[2]  = { label_a, label_b };
  const bool  present[2] = { present_a, present_b };
  const int   columns    = label_b ? 2 : 1;

  for (int i = 0; i < columns; i++) {
    const int x = (i == 0) ? 24 : 250;

    char lbl_buf[32];
    strncpy(lbl_buf, labels[i], sizeof(lbl_buf) - 1);
    lbl_buf[sizeof(lbl_buf) - 1] = '\0';

    lv_obj_t *l = lv_label_create(parent);
    lv_label_set_text(l, lbl_buf);
    lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_pos(l, x, y);

    const bool free_value = (i == 1 && value_b);
    char val_buf[28];
    strncpy(val_buf, free_value ? value_b
                                : (present[i] ? T(STR_BACKEND_SET) : T(STR_BACKEND_MISSING)),
            sizeof(val_buf) - 1);
    val_buf[sizeof(val_buf) - 1] = '\0';

    lv_obj_t *v = lv_label_create(parent);
    lv_label_set_text(v, val_buf);
    // A free value is a statement of fact, not a warning - it gets the calm
    // colour rather than the green/amber of a credential.
    lv_obj_set_style_text_color(v, free_value ? lv_color_hex(UI_COL_INK_2)
                                : lv_color_hex(present[i] ? UI_COL_OK_TEXT_2 : UI_COL_WARN), 0);
    lv_obj_set_style_text_font(v, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_pos(v, x, y + 22);
  }
}

// Opens the device web server and shows its address. Both credential
// carrying backends need it, so it lives here rather than inline.
static void addWebSetupButton(lv_obj_t *parent, int x) {
  lv_obj_t *btn_web = lv_btn_create(parent);
  lv_obj_set_size(btn_web, 216, 44);
  lv_obj_set_pos(btn_web, x, 244);
  lv_obj_set_style_bg_color(btn_web, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(btn_web, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_web, 8, 0);
  lv_obj_set_style_shadow_width(btn_web, 0, 0);
  lv_obj_set_style_border_width(btn_web, 1, 0);
  lv_obj_set_style_border_color(btn_web, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_add_event_cb(btn_web, [](lv_event_t *e) {
    logSD("BTN: Backend -> Web interface");
    // Safe to call directly: this only hides the backend screen, the one it
    // deletes and rebuilds is the web screen.
    showOtaBrowserScreen(WEB_CTX_BACKEND);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_web = lv_label_create(btn_web);
  char buf_web[40];
  snprintf(buf_web, sizeof(buf_web), "%s  " LV_SYMBOL_RIGHT, T(STR_BTN_WEB_SETUP));
  lv_label_set_text(lbl_web, buf_web);
  lv_obj_set_style_text_color(lbl_web, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(lbl_web, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_web);
}

// ---- the setup step: one tile per backend --------------------
#define BK_LIST_X       12
#define BK_LIST_Y       52
#define BK_LIST_W      456
#define BK_LIST_H      202   // four tiles without scrolling, up to the bar
#define BK_TILE_H       46
#define BK_TILE_GAP      6
#define BK_MONO         32
#define BK_MONO_X       12
#define BK_TEXT_X       58
#define BK_TEXT_INSET    6
#define BK_DESC_W      350
#define BK_PILL_PAD_X    7
#define BK_ONLINE_VALUE_W 400

static void onBackendTile(lv_event_t *e) {
  const BackendMode m = (BackendMode)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
  logSDf("BTN: Backend setup -> %s", backendModeName(m));
  s_pending_mode = m;
  // On an online service the mode is already Spoolman, and the local server is
  // still a change.
  s_mode_change_pending = (m != backendMode()) || backendProfileIsOnline();
  s_then_address = true;
  show_backend_pending = true;   // the switch runs on the loop, then the address
}

// What the tile asks of the user, as a small outline beside the name.
static void addHostingPill(lv_obj_t *tile, lv_obj_t *name, BackendHosting hosting) {
  lv_obj_t *pill = lv_label_create(tile);
  lv_label_set_text(pill, T(hosting == BACKEND_ONLINE ? STR_HOSTING_ONLINE : STR_HOSTING_SELF));
  lv_obj_set_style_text_font(pill, UI_FONT_CAPTION, 0);
  lv_obj_set_style_text_color(pill, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_style_border_width(pill, 1, 0);
  lv_obj_set_style_border_color(pill, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_radius(pill, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_pad_hor(pill, BK_PILL_PAD_X, 0);
  lv_obj_align_to(pill, name, LV_ALIGN_OUT_RIGHT_MID, 8, 0);
}

struct BackendTile {
  const char    *name;
  const char    *mono;       // the first letter, or a symbol
  int            desc_str;
  BackendHosting hosting;
  bool           active;
};

static lv_obj_t *addBackendTile(lv_obj_t *list, const BackendTile &b) {
  lv_obj_t *t = lv_btn_create(list);
  lv_obj_set_size(t, LV_PCT(100), BK_TILE_H);
  lv_obj_set_style_pad_all(t, 0, 0);
  lv_obj_set_style_radius(t, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(t, 0, 0);
  lv_obj_set_style_bg_color(t, lv_color_hex(b.active ? UI_COL_PICKED_BG : UI_COL_SURFACE), 0);
  lv_obj_set_style_bg_color(t, lv_color_hex(UI_COL_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(t, b.active ? 2 : 1, 0);
  lv_obj_set_style_border_color(t, lv_color_hex(b.active ? UI_COL_ACCENT : UI_COL_LINE_SOFT), 0);

  // The first letter in a square, until the backends have icons of their own.
  lv_obj_t *mono = lv_obj_create(t);
  lv_obj_remove_style_all(mono);
  lv_obj_set_size(mono, BK_MONO, BK_MONO);
  lv_obj_set_style_radius(mono, UI_RADIUS_BTN, 0);
  lv_obj_set_style_bg_opa(mono, LV_OPA_COVER, 0);
  lv_obj_set_style_bg_color(mono, lv_color_hex(b.active ? UI_COL_GROUND : UI_COL_ROW), 0);
  lv_obj_align(mono, LV_ALIGN_LEFT_MID, BK_MONO_X, 0);
  lv_obj_t *ml = lv_label_create(mono);
  lv_label_set_text(ml, b.mono);
  lv_obj_set_style_text_font(ml, UI_FONT_BODY, 0);
  lv_obj_set_style_text_color(ml, lv_color_hex(b.active ? UI_COL_ACCENT : UI_COL_INK_SOFT), 0);
  lv_obj_center(ml);

  lv_obj_t *name = lv_label_create(t);
  lv_label_set_text(name, b.name);
  lv_obj_set_style_text_font(name, UI_FONT_BODY, 0);
  lv_obj_set_style_text_color(name, lv_color_hex(UI_COL_INK), 0);
  // The active tile's thicker border eats into the room inside it.
  const int inset = b.active ? BK_TEXT_INSET - 1 : BK_TEXT_INSET;
  lv_obj_align(name, LV_ALIGN_TOP_LEFT, BK_TEXT_X, inset);
  addHostingPill(t, name, b.hosting);

  lv_obj_t *desc = lv_label_create(t);
  lv_label_set_long_mode(desc, LV_LABEL_LONG_DOT);
  lv_obj_set_size(desc, BK_DESC_W, lv_font_get_line_height(UI_FONT_CAPTION));
  lv_label_set_text(desc, T(b.desc_str));
  lv_obj_set_style_text_font(desc, UI_FONT_CAPTION, 0);
  lv_obj_set_style_text_color(desc, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_align(desc, LV_ALIGN_BOTTOM_LEFT, BK_TEXT_X, -inset);

  if (b.active) {
    lv_obj_t *tick = lv_label_create(t);
    lv_label_set_text(tick, LV_SYMBOL_OK);
    lv_obj_set_style_text_font(tick, UI_FONT_BODY, 0);
    lv_obj_set_style_text_color(tick, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_align(tick, LV_ALIGN_RIGHT_MID, -14, 0);
  }
  return t;
}

// A row of the backend table: a tap sets the mode, and the address comes next.
static void addLocalTile(lv_obj_t *list, const BackendInfo &b) {
  const char *name = backendModeName(b.mode);
  char letter[2] = { name[0], '\0' };
  const BackendTile tile = { name, letter, b.desc_str, b.hosting,
                             b.mode == backendMode() && !backendProfileIsOnline() };
  lv_obj_t *t = addBackendTile(list, tile);
  lv_obj_set_user_data(t, (void *)(intptr_t)b.mode);
  lv_obj_add_event_cb(t, onBackendTile, LV_EVENT_CLICKED, NULL);
}

// The tile for the online services: nothing changes until one is picked there.
static void addInternetTile(lv_obj_t *list) {
  const BackendTile tile = { T(STR_BACKEND_INTERNET), LV_SYMBOL_WIFI, STR_BACKEND_DESC_INTERNET,
                             BACKEND_ONLINE, backendProfileIsOnline() };
  lv_obj_t *t = addBackendTile(list, tile);
  lv_obj_add_event_cb(t, [](lv_event_t *e) {
    logSD("BTN: Backend setup -> Internet");
    show_online_pending = true;
  }, LV_EVENT_CLICKED, NULL);
}

// In the setup this is a step, not a settings page: one question, answered
// by a tap on a tile, which leads straight on to the address - the same way
// a tap on a network leads to its password.
static void buildBackendSetupStep(lv_obj_t *scr, const char *title) {
  setupHeader(scr, title, SETUP_STEP_BACKEND, [](lv_event_t *e) {
    logSD("BTN: Backend setup -> Back (WiFi)");
    // "Connected" only while it is; a link that dropped meanwhile goes back
    // to the list to be chosen again.
    if (wifi_ok) showWifiConnectedScreen();
    else         showWifiSetupScreen();
  });

  // What each one needs stands on its own tile: "you need a server" above them
  // all stopped being true with the fourth.
  lv_obj_t *list = lv_obj_create(scr);
  lv_obj_set_size(list, BK_LIST_W, BK_LIST_H);
  lv_obj_set_pos(list, BK_LIST_X, BK_LIST_Y);
  lv_obj_set_style_bg_opa(list, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 0, 0);
  lv_obj_set_style_pad_row(list, BK_TILE_GAP, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  size_t n = 0;
  const BackendInfo *rows = backendInfoList(&n);
  for (size_t i = 0; i < n; i++) addLocalTile(list, rows[i]);
  addInternetTile(list);

  SetupBar bar = setupActionBar(scr, nullptr, nullptr, T(STR_SETUP_NO_SERVER), [](lv_event_t *e) {
    logSD("BTN: Backend setup -> Docs");
    showQRPopup(QR_DOCS);
  });
  setupBarMainOutline(bar);
}

// --- mode selector: four segments side by side ---------------------------
// 480 px wide screen: 12 px margin, four 108 px segments, 8 px between. Font 16:
// "BamBuddy" measures 93 of 108 px there, in the title font 104.
#define BK_SEG_W      108
#define BK_SEG_H       54
#define BK_SEG_X       12
#define BK_SEG_Y       54
#define BK_SEG_STEP   116
#define BK_SEG_COUNT    3

static void onLocalSegment(lv_event_t *e) {
  BackendMode m = (BackendMode)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
  if (m == backendMode() && !backendProfileIsOnline()) return;   // already active
  logSDf("BTN: Backend -> %s", backendModeName(m));   // m, not the active mode
  s_pending_mode = m;
  s_mode_change_pending = true;
  show_backend_pending = true;                  // rebuild from appLoop()
}

static lv_obj_t *addSegment(lv_obj_t *scr, int i, const char *text, bool active) {
  lv_obj_t *b = lv_btn_create(scr);
  lv_obj_set_size(b, BK_SEG_W, BK_SEG_H);
  lv_obj_set_pos(b, BK_SEG_X + i * BK_SEG_STEP, BK_SEG_Y);
  lv_obj_set_style_bg_color(b, lv_color_hex(active ? UI_COL_PICKED_BG : UI_COL_SURFACE), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_radius(b, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_border_width(b, active ? 2 : 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(active ? UI_COL_ACCENT : UI_COL_LINE_SOFT), 0);
  lv_obj_t *l = lv_label_create(b);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_color(l, lv_color_hex(active ? UI_COL_ACCENT : UI_COL_OFF_TEXT), 0);
  lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
  lv_obj_center(l);
  return b;
}

static void addBackendSegments(lv_obj_t *scr) {
  const bool online = backendProfileIsOnline();
  static const BackendMode MODES[BK_SEG_COUNT] = { BACKEND_SPOOLMAN, BACKEND_FILAMAN, BACKEND_BAMBUDDY };
  for (int i = 0; i < BK_SEG_COUNT; i++) {
    lv_obj_t *b = addSegment(scr, i, backendModeName(MODES[i]), !online && MODES[i] == backendMode());
    // The mode is stored in user_data so one callback serves every button.
    lv_obj_set_user_data(b, (void *)(intptr_t)MODES[i]);
    lv_obj_add_event_cb(b, onLocalSegment, LV_EVENT_CLICKED, NULL);
  }
  // Opens a page rather than switching, and the arrow says so. Tappable while
  // active too: that is the way to the other service.
  char label[24];
  snprintf(label, sizeof(label), "%s " LV_SYMBOL_RIGHT, T(STR_BACKEND_INTERNET));
  lv_obj_add_event_cb(addSegment(scr, BK_SEG_COUNT, label, online), [](lv_event_t *e) {
    logSD("BTN: Backend -> Internet");
    show_online_pending = true;
  }, LV_EVENT_CLICKED, NULL);
}

// What an online service shows instead of the address: which one and where,
// its key and what the account has to be, then the same pair as FilaMan and
// BamBuddy.
static void addOnlineRows(lv_obj_t *scr) {
  char host[48];
  backendProfileShortHost(backendHost(), host, sizeof(host));
  char value[96];
  snprintf(value, sizeof(value), "%s - %s", backendName(), host[0] ? host : T(STR_BTN_WIFI_NONE));
  lv_obj_t *row = addNavRow(scr, 122, T(STR_ONLINE_SERVICE), value,
                            host[0] ? UI_COL_GOOD : UI_COL_WARN, [](lv_event_t *e) {
    logSD("BTN: Backend -> Online service");
    show_online_pending = true;
  });
  lv_obj_t *value_lbl = lv_obj_get_child(row, 1);
  lv_label_set_long_mode(value_lbl, LV_LABEL_LONG_DOT);
  lv_obj_set_width(value_lbl, BK_ONLINE_VALUE_W);

  const bool needs_account = backendProfile(backendProfileId()).account_url[0] != '\0';
  addCredentialsRow(scr, 190, T(STR_BACKEND_APIKEY), spoolmanAuthActive(),
                    needs_account ? T(STR_ONLINE_ACCOUNT) : nullptr, false,
                    needs_account ? T(STR_ONLINE_PRO) : nullptr);

  lv_obj_t *btn_opts = lv_btn_create(scr);
  lv_obj_set_size(btn_opts, 216, 44);
  lv_obj_set_pos(btn_opts, 16, 244);
  lv_obj_set_style_bg_color(btn_opts, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(btn_opts, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_opts, 8, 0);
  lv_obj_set_style_shadow_width(btn_opts, 0, 0);
  lv_obj_set_style_border_width(btn_opts, 1, 0);
  lv_obj_set_style_border_color(btn_opts, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_add_event_cb(btn_opts, [](lv_event_t *e) {
    logSD("BTN: Backend -> Online options");
    show_spoolman_options_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_opts = lv_label_create(btn_opts);
  char ob[40];
  snprintf(ob, sizeof(ob), "%s  " LV_SYMBOL_RIGHT, T(STR_BTN_MORE_OPTIONS));
  lv_label_set_text(lbl_opts, ob);
  lv_obj_set_style_text_color(lbl_opts, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(lbl_opts, UI_FONT_BODY, 0);
  lv_obj_center(lbl_opts);

  addWebSetupButton(scr, 248);
}

void buildBackendScreen() {
  logSD("BUILD: BackendScreen");
  applyPendingModeChange();
  // Nothing to rebuild for a tile picked in the setup: the address takes over
  // in this same loop pass.
  if (s_then_address) {
    s_then_address = false;
    show_spoolman_pending = true;
    return;
  }
  releaseScreen(&scr_backend);

  char buf_title[32];
  copyT(buf_title, sizeof(buf_title), STR_BACKEND_TITLE);

  scr_backend = buildOverlayScreen();

  if (setup_active) {
    buildBackendSetupStep(scr_backend, buf_title);
    return;
  }
  buildSubHeader(scr_backend, buf_title, [](lv_event_t *e) {
    logSD("BTN: Backend -> Back");
    show_connection_from_spoolman_pending = true;
  });

  const bool is_filaman = backendIsFilaMan();
  const bool online = backendProfileIsOnline();
  addBackendSegments(scr_backend);

  if (online) {
    addOnlineRows(scr_backend);
    return;
  }

  // --- address row, opens the existing numpad screen -------------
  {
    char buf_addr[24];
    copyT(buf_addr, sizeof(buf_addr), STR_BACKEND_ADDRESS);

    char host_buf[64];
    const char *h = backendHost();
    strncpy(host_buf, (h && h[0]) ? h : T(STR_BTN_WIFI_NONE), sizeof(host_buf) - 1);
    host_buf[sizeof(host_buf) - 1] = '\0';

    // An address without a port silently goes to port 80. FilaMan listens on
    // 8083 and BamBuddy on 8000 by default, so flag a missing port in amber
    // rather than green.
    const bool port_missing = h && h[0] && !strchr(h, ':');

    addNavRow(scr_backend, 122, buf_addr, host_buf,
              port_missing ? UI_COL_WARN : UI_COL_GOOD,
              [](lv_event_t *e) {
                logSD("BTN: Backend -> Address");
                show_spoolman_pending = true;
              });
  }

  // --- Spoolman only settings ------------------------------------
  // The extra fields used to sit here as a row of their own. They moved into
  // the options screen so all three backends now hang their own settings off
  // the same "More options" button instead of one of them being special.
  //
  // Spoolman only by nature: FilaMan calls them system extra fields, which sit
  // behind a different endpoint and need admin rights, and BamBuddy has a fixed
  // schema with no extra fields at all.
  //
  // Centred rather than at x=16 like the other two: those sit beside a browser
  // button, and Spoolman has no credentials to enter, so there is no pair here
  // to line up with.
  if (backendMode() == BACKEND_SPOOLMAN) {
    lv_obj_t *btn_opts = lv_btn_create(scr_backend);
    lv_obj_set_size(btn_opts, 216, 44);
    // Right under the address row. It sat at 244 like the two backends that
    // have credential rows in between, and here nothing is in between.
    lv_obj_set_pos(btn_opts, 132, 194);
    lv_obj_set_style_bg_color(btn_opts, lv_color_hex(UI_COL_ROW), 0);
    lv_obj_set_style_bg_color(btn_opts, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_opts, 8, 0);
    lv_obj_set_style_shadow_width(btn_opts, 0, 0);
    lv_obj_set_style_border_width(btn_opts, 1, 0);
    lv_obj_set_style_border_color(btn_opts, lv_color_hex(UI_COL_LINE), 0);
    lv_obj_add_event_cb(btn_opts, [](lv_event_t *e) {
      logSD("BTN: Backend -> Spoolman options");
      show_spoolman_options_pending = true;
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_opts = lv_label_create(btn_opts);
    { char ob[40];
      snprintf(ob, sizeof(ob), "%s  " LV_SYMBOL_RIGHT, T(STR_BTN_MORE_OPTIONS));
      lv_label_set_text(lbl_opts, ob); }
    lv_obj_set_style_text_color(lbl_opts, lv_color_hex(UI_COL_INK_2), 0);
    lv_obj_set_style_text_font(lbl_opts, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_opts);
  }

  // --- FilaMan credentials, shown only in FilaMan mode -----------
  // FilaMan needs two tokens because it has no per device permissions.
  // Both are entered in the browser, a 49 character key cannot be typed
  // on a numpad that only has digits, dot and colon.
  if (is_filaman) {
    addCredentialsRow(scr_backend, 190,
                      T(STR_BACKEND_APIKEY),       filamanApiKey()[0] != '\0',
                      T(STR_BACKEND_DEVICE_TOKEN), filamanDeviceToken()[0] != '\0');

    // The hint used to only say "enter them in the browser" without offering
    // a way there. This starts the device web server and shows its address.
    // Left of the browser button: the FilaMan only settings, which are
    // expected to grow and therefore live behind their own screen.
    lv_obj_t *btn_opts = lv_btn_create(scr_backend);
    lv_obj_set_size(btn_opts, 216, 44);
    lv_obj_set_pos(btn_opts, 16, 244);
    lv_obj_set_style_bg_color(btn_opts, lv_color_hex(UI_COL_ROW), 0);
    lv_obj_set_style_bg_color(btn_opts, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_opts, 8, 0);
    lv_obj_set_style_shadow_width(btn_opts, 0, 0);
    lv_obj_set_style_border_width(btn_opts, 1, 0);
    lv_obj_set_style_border_color(btn_opts, lv_color_hex(UI_COL_LINE), 0);
    lv_obj_add_event_cb(btn_opts, [](lv_event_t *e) {
      logSD("BTN: Backend -> FilaMan options");
      show_filaman_options_pending = true;
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_opts = lv_label_create(btn_opts);
    { char ob[40];
      snprintf(ob, sizeof(ob), "%s  " LV_SYMBOL_RIGHT, T(STR_BTN_MORE_OPTIONS));
      lv_label_set_text(lbl_opts, ob); }
    lv_obj_set_style_text_color(lbl_opts, lv_color_hex(UI_COL_INK_2), 0);
    lv_obj_set_style_text_font(lbl_opts, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_opts);

    addWebSetupButton(scr_backend, 248);
  }

  // --- BamBuddy credentials, shown only in BamBuddy mode ---------
  // One key instead of two, and an empty one is a valid state: an instance
  // with authentication switched off answers without it. Entered in the
  // browser for the same reason as FilaMan's, a 46 character key cannot be
  // typed on a numpad.
  if (backendIsBamBuddy()) {
    // Second column: which database the answers actually come from. It sits
    // next to the key because both are "what this connection is", and it is
    // the one thing about BamBuddy that can change without the scale being
    // touched. Product names, so not translated.
    char inv_buf[24];
    strncpy(inv_buf, (bbInventoryMode() == BB_INV_SPOOLMAN) ? "Spoolman" : "BamBuddy",
            sizeof(inv_buf) - 1);
    inv_buf[sizeof(inv_buf) - 1] = '\0';
    addCredentialsRow(scr_backend, 190,
                      T(STR_BACKEND_APIKEY), bambuddyApiKey()[0] != '\0',
                      T(STR_BACKEND_INVENTORY), false, inv_buf);

    // Same pair as in FilaMan mode: the backend's own settings on the left,
    // the browser on the right.
    lv_obj_t *btn_opts = lv_btn_create(scr_backend);
    lv_obj_set_size(btn_opts, 216, 44);
    lv_obj_set_pos(btn_opts, 16, 244);
    lv_obj_set_style_bg_color(btn_opts, lv_color_hex(UI_COL_ROW), 0);
    lv_obj_set_style_bg_color(btn_opts, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_opts, 8, 0);
    lv_obj_set_style_shadow_width(btn_opts, 0, 0);
    lv_obj_set_style_border_width(btn_opts, 1, 0);
    lv_obj_set_style_border_color(btn_opts, lv_color_hex(UI_COL_LINE), 0);
    lv_obj_add_event_cb(btn_opts, [](lv_event_t *e) {
      logSD("BTN: Backend -> BamBuddy options");
      show_bambuddy_options_pending = true;
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_opts = lv_label_create(btn_opts);
    { char ob[40];
      snprintf(ob, sizeof(ob), "%s  " LV_SYMBOL_RIGHT, T(STR_BTN_MORE_OPTIONS));
      lv_label_set_text(lbl_opts, ob); }
    lv_obj_set_style_text_color(lbl_opts, lv_color_hex(UI_COL_INK_2), 0);
    lv_obj_set_style_text_font(lbl_opts, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_opts);

    addWebSetupButton(scr_backend, 248);
  }
}
