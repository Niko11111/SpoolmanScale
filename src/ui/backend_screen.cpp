#include "backend_screen.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "lang.h"
#include "navigation.h"
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
}

// Small status row: label on the left, value on the right in green or amber.
static void addStatusRow(lv_obj_t *parent, int y, const char *label,
                         bool present) {
  char lbl_buf[32];
  strncpy(lbl_buf, label, sizeof(lbl_buf) - 1);
  lbl_buf[sizeof(lbl_buf) - 1] = '\0';

  lv_obj_t *l = lv_label_create(parent);
  lv_label_set_text(l, lbl_buf);
  lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(l, 24, y);

  char val_buf[24];
  strncpy(val_buf, present ? T(STR_BACKEND_SET) : T(STR_BACKEND_MISSING),
          sizeof(val_buf) - 1);
  val_buf[sizeof(val_buf) - 1] = '\0';

  lv_obj_t *v = lv_label_create(parent);
  lv_label_set_text(v, val_buf);
  lv_obj_set_style_text_color(v, lv_color_hex(present ? 0x40c080 : 0xf0b838), 0);
  lv_obj_set_style_text_font(v, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(v, LV_ALIGN_TOP_RIGHT, -24, y);
}

void buildBackendScreen() {
  logSD("BUILD: BackendScreen");
  applyPendingModeChange();
  releaseScreen(&scr_backend);

  char buf_title[32];
  strncpy(buf_title, T(STR_BACKEND_TITLE), sizeof(buf_title) - 1);
  buf_title[sizeof(buf_title) - 1] = '\0';

  scr_backend = buildOverlayScreen();
  buildSubHeader(scr_backend, buf_title, [](lv_event_t *e) {
    logSD("BTN: Backend -> Back");
    show_connection_from_spoolman_pending = true;
  });

  // --- mode selector: two segments side by side -----------------
  const int SEG_W = 216, SEG_H = 54, SEG_Y = 54;
  const bool is_filaman = backendIsFilaMan();

  struct Seg { const char *name; BackendMode mode; int x; };
  const Seg segs[2] = {
    { "Spoolman", BACKEND_SPOOLMAN, 16 },
    { "FilaMan",  BACKEND_FILAMAN,  248 }
  };

  for (int i = 0; i < 2; i++) {
    const bool active = (segs[i].mode == BACKEND_FILAMAN) == is_filaman;

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
    lv_label_set_text(l, segs[i].name);
    lv_obj_set_style_text_color(l, lv_color_hex(active ? 0x28d49a : 0x8098b8), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(l);

    // The mode is stored in user_data so one callback serves both buttons.
    lv_obj_set_user_data(b, (void *)(intptr_t)segs[i].mode);
    lv_obj_add_event_cb(b, [](lv_event_t *e) {
      BackendMode m = (BackendMode)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
      if (m == backendMode()) return;               // already active, nothing to do
      logSDf("BTN: Backend -> %s", m == BACKEND_FILAMAN ? "FilaMan" : "Spoolman");
      s_pending_mode = m;
      s_mode_change_pending = true;
      show_backend_pending = true;                  // rebuild from appLoop()
    }, LV_EVENT_CLICKED, NULL);
  }

  // --- address row, opens the existing numpad screen -------------
  lv_obj_t *row = lv_btn_create(scr_backend);
  lv_obj_set_size(row, 448, 56);
  lv_obj_set_pos(row, 16, 122);
  lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(row, 10, 0);
  lv_obj_set_style_shadow_width(row, 0, 0);
  lv_obj_set_style_border_width(row, 1, 0);
  lv_obj_set_style_border_color(row, lv_color_hex(0x1a3050), 0);
  lv_obj_add_event_cb(row, [](lv_event_t *e) {
    logSD("BTN: Backend -> Address");
    show_spoolman_pending = true;
  }, LV_EVENT_CLICKED, NULL);

  {
    char buf_addr[24];
    strncpy(buf_addr, T(STR_BACKEND_ADDRESS), sizeof(buf_addr) - 1);
    buf_addr[sizeof(buf_addr) - 1] = '\0';

    lv_obj_t *l = lv_label_create(row);
    lv_label_set_text(l, buf_addr);
    lv_obj_set_style_text_color(l, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(l, LV_ALIGN_LEFT_MID, 8, -11);

    char host_buf[64];
    const char *h = backendHost();
    strncpy(host_buf, (h && h[0]) ? h : T(STR_BTN_WIFI_NONE), sizeof(host_buf) - 1);
    host_buf[sizeof(host_buf) - 1] = '\0';

    // An address without a port silently goes to port 80. FilaMan listens on
    // 8002 by default, so flag a missing port in amber rather than green.
    const bool port_missing = h && h[0] && !strchr(h, ':');

    lv_obj_t *s = lv_label_create(row);
    lv_label_set_text(s, host_buf);
    lv_obj_set_style_text_color(s, lv_color_hex(port_missing ? 0xf0b838 : 0x28d49a), 0);
    lv_obj_set_style_text_font(s, &lv_font_montserrat_ext_14, 0);
    lv_obj_align(s, LV_ALIGN_LEFT_MID, 8, 12);

    lv_obj_t *a = lv_label_create(row);
    lv_label_set_text(a, LV_SYMBOL_RIGHT);
    lv_obj_set_style_text_color(a, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(a, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(a, LV_ALIGN_RIGHT_MID, -10, 0);
  }

  // --- FilaMan credentials, shown only in FilaMan mode -----------
  // FilaMan needs two tokens because it has no per device permissions.
  // Both are entered in the browser, a 49 character key cannot be typed
  // on a numpad that only has digits, dot and colon.
  if (is_filaman) {
    addStatusRow(scr_backend, 196, T(STR_BACKEND_APIKEY),
                 filamanApiKey()[0] != '\0');
    addStatusRow(scr_backend, 228, T(STR_BACKEND_DEVICE_TOKEN),
                 filamanDeviceToken()[0] != '\0');

    char buf_hint[64];
    strncpy(buf_hint, T(STR_BACKEND_BROWSER_HINT), sizeof(buf_hint) - 1);
    buf_hint[sizeof(buf_hint) - 1] = '\0';

    lv_obj_t *hint = lv_label_create(scr_backend);
    lv_label_set_text(hint, buf_hint);
    lv_obj_set_style_text_color(hint, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(hint, 440);
    lv_obj_align(hint, LV_ALIGN_TOP_MID, 0, 268);
  }
}
