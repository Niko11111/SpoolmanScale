#include "wifi_saved_screen.h"

#include <Arduino.h>
#include <lvgl.h>
#include <stdio.h>
#include <string.h>

#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "navigation.h"
#include "services/wifi_known.h"
#include "services/wifi_manager.h"
#include "theme.h"
#include "ui_common.h"
#include "wifi_setup_screen.h"

// The popup's coordinates, inside its box (no padding, 2 px border).
#define WS_BOX_W       440
#define WS_X            12
#define WS_INNER_W     412
#define WS_TITLE_Y     10
#define WS_STATUS_Y    38
#define WS_NOTE_Y      60
#define WS_ACTIONS_Y   66
#define WS_ACTIONS_Y_NOTE 86
#define WS_BTN_H       46
#define WS_BTN_GAP      8
#define WS_ROW_STEP    54
#define WS_BOX_EXTRA   12
#define WS_EMPTY_Y    120

static lv_obj_t *s_scr   = nullptr;
static lv_obj_t *s_popup = nullptr;
// The full SSID per row: a title may be cut with dots on screen.
static char s_rows[WIFI_KNOWN_MAX][WIFI_KNOWN_SSID_BYTES];
// The network the popup is about, and a "Forget" parked for the loop.
static char s_pick[WIFI_KNOWN_SSID_BYTES] = "";
static bool s_forget_pending = false;

void hideWifiSavedScreen() {
  releaseScreen(&s_popup);
  releaseScreen(&s_scr);
}

struct NetState { bool connected; bool preferred; };

static NetState stateOf(const char *ssid) {
  char on[WIFI_KNOWN_SSID_BYTES];
  wifiManagerCurrentSsid(on, sizeof(on));
  return { strcmp(on, ssid) == 0, strcmp(wifiPreferredSsid(), ssid) == 0 };
}

static int statusText(NetState st) {
  if (st.connected && st.preferred) return STR_WIFI_ST_CONN_PREF;
  if (st.connected) return STR_WIFI_STATUS_CONNECTED;
  if (st.preferred) return STR_WIFI_ST_PREFERRED;
  return STR_WIFI_ST_SAVED;
}

static void onConnect(lv_event_t *e) {
  const WifiKnownList &l = wifiKnownList();
  const int at = wifiKnownFind(l, s_pick);
  releaseScreen(&s_popup);
  if (at < 0) return;
  logSDf("BTN: SavedNetworks -> connect to %s", s_pick);
  wifiSetupConnectWith(l.e[at].ssid, l.e[at].pass);   // runs from the loop
}

static void onForget(lv_event_t *e) {
  s_forget_pending = true;
  releaseScreen(&s_popup);
}

// One line of the popup across its width, cut with dots where it is longer.
static void popupLine(lv_obj_t *box, int y, const char *text, const lv_font_t *font, uint32_t col) {
  lv_obj_t *l = lv_label_create(box);
  lv_label_set_text(l, text);
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
  lv_obj_set_width(l, WS_INNER_W);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(col), 0);
  lv_obj_set_pos(l, WS_X + 2, y);
}

struct BtnAt { int x, y, w; };

static lv_obj_t* popupButton(lv_obj_t *box, BtnAt at, const char *text, uint32_t ink) {
  lv_obj_t *b = padButton(box, at.x, at.y, at.w, WS_BTN_H, UI_COL_ROW, UI_COL_ROW_PRESS_FILL);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  padLabel(b, text, ink, UI_FONT_SMALL);
  return b;
}

// Connect where the scale is not on it; forget where it is not the
// preferred one, whose stored choice the next boot would still use.
static void showNetPopup(const char *ssid) {
  snprintf(s_pick, sizeof(s_pick), "%s", ssid);
  const NetState st = stateOf(ssid);
  const bool connect = !st.connected, forget = !st.preferred;
  const int n = (connect ? 1 : 0) + (forget ? 1 : 0);
  const int actions_y = st.preferred ? WS_ACTIONS_Y_NOTE : WS_ACTIONS_Y;
  const int close_y = actions_y + (n ? WS_ROW_STEP : 0);
  lv_obj_t *box = uiPopupBox(&s_popup, WS_BOX_W, close_y + WS_BTN_H + WS_BOX_EXTRA);

  popupLine(box, WS_TITLE_Y, ssid, UI_FONT_TITLE, UI_COL_INK);
  popupLine(box, WS_STATUS_Y, T(statusText(st)), UI_FONT_CAPTION, UI_COL_CAPTION);
  if (st.preferred) popupLine(box, WS_NOTE_Y, T(STR_WIFI_PREF_KEEP), UI_FONT_CAPTION, UI_COL_INK_SOFT);

  const int w = n == 2 ? (WS_INNER_W - WS_BTN_GAP) / 2 : WS_INNER_W;
  int x = WS_X;
  char buf[48];
  if (connect) {
    snprintf(buf, sizeof(buf), LV_SYMBOL_WIFI "  %s", T(STR_WIFI_CONNECT_NOW));
    lv_obj_add_event_cb(popupButton(box, {x, actions_y, w}, buf, UI_COL_ACCENT), onConnect, LV_EVENT_CLICKED, NULL);
    x += w + WS_BTN_GAP;
  }
  if (forget) {
    snprintf(buf, sizeof(buf), LV_SYMBOL_TRASH "  %s", T(STR_WIFI_FORGET));
    lv_obj_add_event_cb(popupButton(box, {x, actions_y, w}, buf, UI_COL_ARCHIVE_TEXT), onForget, LV_EVENT_CLICKED, NULL);
  }
  lv_obj_t *close = popupButton(box, {WS_X, close_y, WS_INNER_W}, T(n ? STR_CANCEL : STR_BT_CLOSE), UI_COL_INK_2);
  styleLeaveButton(close);
  lv_obj_add_event_cb(close, [](lv_event_t *e) { releaseScreen(&s_popup); }, LV_EVENT_CLICKED, NULL);
}

static void onRowClicked(lv_event_t *e) {
  const char *ssid = (const char *)lv_obj_get_user_data(lv_event_get_target(e));
  if (ssid) showNetPopup(ssid);
}

void showWifiSavedScreen() {
  logSD("SHOW: WifiSavedScreen");
  hideAllOverlays();
  releaseScreen(&s_scr);
  s_scr = buildOverlayScreen();
  buildSubHeader(s_scr, T(STR_WIFI_SAVED_TITLE), [](lv_event_t *e) {
    // Into the WiFi menu, built on the loop.
    show_wifi_menu_pending = true;
  });

  const WifiKnownList &l = wifiKnownList();
  if (l.n == 0) {
    lv_obj_t *none = lv_label_create(s_scr);
    lv_label_set_text(none, T(STR_WIFI_SAVED_NONE));
    lv_obj_set_style_text_font(none, UI_FONT_SMALL, 0);
    lv_obj_set_style_text_color(none, lv_color_hex(UI_COL_INK_SOFT), 0);
    lv_obj_align(none, LV_ALIGN_TOP_MID, 0, WS_EMPTY_Y);
  }
  lv_obj_t *list = buildOptionList(s_scr);
  for (int i = 0; i < l.n; i++) {
    snprintf(s_rows[i], sizeof(s_rows[i]), "%s", l.e[i].ssid);
    lv_obj_t *b = makeListBtn(list, LV_SYMBOL_WIFI, s_rows[i], T(statusText(stateOf(s_rows[i]))));
    lv_obj_set_user_data(b, s_rows[i]);
    lv_obj_add_event_cb(b, onRowClicked, LV_EVENT_CLICKED, NULL);
  }
  lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_HIDDEN);
}

void wifiSavedScreenTick() {
  if (!s_forget_pending) return;
  s_forget_pending = false;
  wifiKnownForgetSsid(s_pick);
  // Shown again with the row gone, unless the user has moved on meanwhile.
  if (s_scr && !lv_obj_has_flag(s_scr, LV_OBJ_FLAG_HIDDEN)) showWifiSavedScreen();
}
