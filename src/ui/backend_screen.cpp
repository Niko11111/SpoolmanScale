#include "backend_screen.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "header_status.h"
#include "lang.h"
#include "navigation.h"
#include "extra_fields_screen.h"
#include "ota_browser.h"
#include "ui_common.h"

// Switching the mode has to happen outside this screen's own event callback,
// otherwise the callback would delete the button it is currently running on.
// The flag is consumed in appLoop(), which rebuilds the screen.
static BackendMode s_pending_mode = BACKEND_SPOOLMAN;
static bool s_mode_change_pending = false;

static void applyPendingModeChange() {
  if (!s_mode_change_pending) return;
  s_mode_change_pending = false;
  backendSetMode(s_pending_mode);

  // The header abbreviation and the caption above the database weight name
  // the backend. Without this they would only catch up on the next
  // reachability change, which can be half a minute away, or on reboot.
  sm_reachable = false;          // unknown until the new backend answers
  updateHeaderStatus();
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
  lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(row, 10, 0);
  lv_obj_set_style_shadow_width(row, 0, 0);
  lv_obj_set_style_border_width(row, 1, 0);
  lv_obj_set_style_border_color(row, lv_color_hex(0x1a3050), 0);
  lv_obj_add_event_cb(row, cb, LV_EVENT_CLICKED, NULL);

  lv_obj_t *l = lv_label_create(row);
  lv_label_set_text(l, title);
  lv_obj_set_style_text_color(l, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(l, LV_ALIGN_LEFT_MID, 8, -11);

  lv_obj_t *s = lv_label_create(row);
  lv_label_set_text(s, value);
  lv_obj_set_style_text_color(s, lv_color_hex(value_color), 0);
  lv_obj_set_style_text_font(s, &lv_font_montserrat_ext_14, 0);
  lv_obj_align(s, LV_ALIGN_LEFT_MID, 8, 12);

  lv_obj_t *a = lv_label_create(row);
  lv_label_set_text(a, LV_SYMBOL_RIGHT);
  lv_obj_set_style_text_color(a, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(a, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(a, LV_ALIGN_RIGHT_MID, -10, 0);
  return row;
}

// Credentials, one column each: label on top, state under it. The two used to
// sit side by side with their values pushed to column edges, which put the
// first "set" ten pixels from the *other* label and read as belonging to it.
// Stacking is the strongest grouping there is, and it matches the address row
// right above - same label size and colour, same offset to the value.
// label_b may be null, which BamBuddy uses - it has a single key where
// FilaMan needs a pair.
static void addCredentialsRow(lv_obj_t *parent, int y,
                              const char *label_a, bool present_a,
                              const char *label_b, bool present_b) {
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
    lv_obj_set_style_text_color(l, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_pos(l, x, y);

    char val_buf[24];
    strncpy(val_buf, present[i] ? T(STR_BACKEND_SET) : T(STR_BACKEND_MISSING),
            sizeof(val_buf) - 1);
    val_buf[sizeof(val_buf) - 1] = '\0';

    lv_obj_t *v = lv_label_create(parent);
    lv_label_set_text(v, val_buf);
    lv_obj_set_style_text_color(v, lv_color_hex(present[i] ? 0x40c080 : 0xf0b838), 0);
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
  lv_obj_set_style_bg_color(btn_web, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_web, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_web, 8, 0);
  lv_obj_set_style_shadow_width(btn_web, 0, 0);
  lv_obj_set_style_border_width(btn_web, 1, 0);
  lv_obj_set_style_border_color(btn_web, lv_color_hex(0x1a3060), 0);
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
  lv_obj_set_style_text_color(lbl_web, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_web, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_web);
}

void buildBackendScreen() {
  logSD("BUILD: BackendScreen");
  applyPendingModeChange();
  releaseScreen(&scr_backend);

  char buf_title[32];
  strncpy(buf_title, T(STR_BACKEND_TITLE), sizeof(buf_title) - 1);
  buf_title[sizeof(buf_title) - 1] = '\0';

  scr_backend = buildOverlayScreen();

  // During the first time setup this is a step, not a settings page: there is
  // no settings menu to go back to, and the way onward is the address screen.
  if (setup_active) {
    lv_obj_t *lbl_title = lv_label_create(scr_backend);
    lv_label_set_text(lbl_title, buf_title);
    lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);

    lv_obj_t *btn_x = lv_btn_create(scr_backend);
    lv_obj_set_size(btn_x, 44, 44);
    lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
    lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_x, 8, 0);
    lv_obj_set_style_shadow_width(btn_x, 0, 0);
    lv_obj_set_style_border_width(btn_x, 0, 0);
    lv_obj_add_event_cb(btn_x, [](lv_event_t *e){
      logSD("BTN: Backend setup -> Close");
      finish_setup_pending = true;
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_x = lv_label_create(btn_x);
    lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(lbl_x);
  } else {
    buildSubHeader(scr_backend, buf_title, [](lv_event_t *e) {
      logSD("BTN: Backend -> Back");
      show_connection_from_spoolman_pending = true;
    });
  }

  // --- mode selector: three segments side by side ---------------
  // 480 px wide screen: 12 px margin, three 145 px segments, 10 px between.
  const int SEG_W = 145, SEG_H = 54, SEG_Y = 54;
  const bool is_filaman = backendIsFilaMan();

  struct Seg { BackendMode mode; int x; };
  const Seg segs[3] = {
    { BACKEND_SPOOLMAN,  12 },
    { BACKEND_FILAMAN,  167 },
    { BACKEND_BAMBUDDY, 322 }
  };

  for (int i = 0; i < 3; i++) {
    const bool active = (segs[i].mode == backendMode());

    lv_obj_t *b = lv_btn_create(scr_backend);
    lv_obj_set_size(b, SEG_W, SEG_H);
    lv_obj_set_pos(b, segs[i].x, SEG_Y);
    lv_obj_set_style_bg_color(b, lv_color_hex(active ? 0x14402e : 0x0a1828), 0);
    lv_obj_set_style_bg_color(b, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(b, 10, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_border_width(b, active ? 2 : 1, 0);
    lv_obj_set_style_border_color(b, lv_color_hex(active ? 0x28d49a : 0x1a2840), 0);

    lv_obj_t *l = lv_label_create(b);
    lv_label_set_text(l, backendModeName(segs[i].mode));
    lv_obj_set_style_text_color(l, lv_color_hex(active ? 0x28d49a : 0x8098b8), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(l);

    // The mode is stored in user_data so one callback serves every button.
    lv_obj_set_user_data(b, (void *)(intptr_t)segs[i].mode);
    lv_obj_add_event_cb(b, [](lv_event_t *e) {
      BackendMode m = (BackendMode)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
      if (m == backendMode()) return;               // already active, nothing to do
      logSDf("BTN: Backend -> %s", backendModeName(m));   // m, not the active mode
      s_pending_mode = m;
      s_mode_change_pending = true;
      show_backend_pending = true;                  // rebuild from appLoop()
    }, LV_EVENT_CLICKED, NULL);
  }

  // In setup the address is the next step of its own, so this screen asks the
  // one question it is here for and gets out of the way.
  if (setup_active) {
    char buf_hint[160];
    strncpy(buf_hint, T(STR_SETUP_BACKEND_HINT), sizeof(buf_hint) - 1);
    buf_hint[sizeof(buf_hint) - 1] = '\0';

    lv_obj_t *hint = lv_label_create(scr_backend);
    lv_label_set_text(hint, buf_hint);
    lv_obj_set_style_text_color(hint, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(hint, 440);
    lv_obj_align(hint, LV_ALIGN_TOP_MID, 0, 138);

    lv_obj_t *btn_next = lv_btn_create(scr_backend);
    lv_obj_set_size(btn_next, 200, 48);
    lv_obj_align(btn_next, LV_ALIGN_BOTTOM_MID, 0, -20);
    lv_obj_set_style_bg_color(btn_next, lv_color_hex(0x1a3020), 0);
    lv_obj_set_style_bg_color(btn_next, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_next, 8, 0);
    lv_obj_set_style_shadow_width(btn_next, 0, 0);
    lv_obj_set_style_border_width(btn_next, 0, 0);
    lv_obj_add_event_cb(btn_next, [](lv_event_t *e) {
      logSD("BTN: Backend setup -> Address");
      show_spoolman_pending = true;
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_next = lv_label_create(btn_next);
    char next_buf[32];
    snprintf(next_buf, sizeof(next_buf), "%s  " LV_SYMBOL_RIGHT, T(STR_BTN_NEXT));
    lv_label_set_text(lbl_next, next_buf);
    lv_obj_set_style_text_color(lbl_next, lv_color_hex(0x40c080), 0);
    lv_obj_set_style_text_font(lbl_next, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_next);
    return;
  }

  // --- address row, opens the existing numpad screen -------------
  {
    char buf_addr[24];
    strncpy(buf_addr, T(STR_BACKEND_ADDRESS), sizeof(buf_addr) - 1);
    buf_addr[sizeof(buf_addr) - 1] = '\0';

    char host_buf[64];
    const char *h = backendHost();
    strncpy(host_buf, (h && h[0]) ? h : T(STR_BTN_WIFI_NONE), sizeof(host_buf) - 1);
    host_buf[sizeof(host_buf) - 1] = '\0';

    // An address without a port silently goes to port 80. FilaMan listens on
    // 8002 and BamBuddy on 8000 by default, so flag a missing port in amber
    // rather than green.
    const bool port_missing = h && h[0] && !strchr(h, ':');

    addNavRow(scr_backend, 122, buf_addr, host_buf,
              port_missing ? 0xf0b838 : 0x28d49a,
              [](lv_event_t *e) {
                logSD("BTN: Backend -> Address");
                show_spoolman_pending = true;
              });
  }

  // --- extra fields, Spoolman only -------------------------------
  // Moved here from the connection screen: extra fields are a property of the
  // filament manager, not of the network connection, and this screen has the
  // room in Spoolman mode because the two credential rows below are FilaMan
  // only. FilaMan calls them system extra fields, they sit behind a different
  // endpoint and need admin rights, so they are not offered there. BamBuddy
  // has a fixed schema and no extra fields at all.
  if (backendMode() == BACKEND_SPOOLMAN) {
    char buf_ef[40];
    backendText(T(STR_EXTRA_FIELDS_TITLE), buf_ef, sizeof(buf_ef));
    addNavRow(scr_backend, 186, buf_ef, "tag, last_dried", 0x4a6fa0,
              [](lv_event_t *e) {
                logSD("BTN: Backend -> Extra Fields");
                showExtraFieldsScreen(false);
              });
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
    lv_obj_set_style_bg_color(btn_opts, lv_color_hex(0x0a1e30), 0);
    lv_obj_set_style_bg_color(btn_opts, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_opts, 8, 0);
    lv_obj_set_style_shadow_width(btn_opts, 0, 0);
    lv_obj_set_style_border_width(btn_opts, 1, 0);
    lv_obj_set_style_border_color(btn_opts, lv_color_hex(0x1a3060), 0);
    lv_obj_add_event_cb(btn_opts, [](lv_event_t *e) {
      logSD("BTN: Backend -> FilaMan options");
      show_filaman_options_pending = true;
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_opts = lv_label_create(btn_opts);
    { char ob[40];
      snprintf(ob, sizeof(ob), "%s  " LV_SYMBOL_RIGHT, T(STR_BTN_MORE_OPTIONS));
      lv_label_set_text(lbl_opts, ob); }
    lv_obj_set_style_text_color(lbl_opts, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(lbl_opts, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_opts);

    addWebSetupButton(scr_backend, 248);
  }

  // --- BamBuddy credentials, shown only in BamBuddy mode ---------
  // One key instead of two, and an empty one is a valid state: an instance
  // with authentication switched off answers without it. Entered in the
  // browser for the same reason as FilaMan's, a 46 character key cannot be
  // typed on a numpad. There is no options screen yet, so the browser button
  // sits centred rather than beside one.
  if (backendIsBamBuddy()) {
    addCredentialsRow(scr_backend, 190,
                      T(STR_BACKEND_APIKEY), bambuddyApiKey()[0] != '\0',
                      nullptr, false);
    addWebSetupButton(scr_backend, 132);
  }
}
