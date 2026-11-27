#include "ams_assign_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/ams_assign.h"
#include "services/backend.h"
#include "services/prefs_store.h"
#include "num_pad.h"
#include "ui_common.h"
#include "theme.h"

// Work parked by a button callback and carried out at the top of the next
// build. Every one of these costs an HTTP request, which is exactly what a
// callback may not do.
static int  s_write_mode_pending   = -1;     // mode to push to the server
static bool s_write_window_pending = false;  // push s_ams_numpad_value

// Result of the last server read, kept so the screen can say why a value is
// missing instead of showing a stale number as if it were fresh.
static int  s_server_code    = 0;
static bool s_server_enabled = false;

const char* amsModeName() {
  switch (g_ams_mode) {
    case AMS_ASK:    return T(STR_AMS_MODE_ASK);
    case AMS_ALWAYS: return T(STR_AMS_MODE_ALWAYS);
    default:         return T(STR_AMS_MODE_OFF);
  }
}

// Row with a label, a hint underneath and a value on the right. Same shape
// as the drying thresholds, which is the only other place a settings value
// is edited rather than toggled.
static lv_obj_t* makeValueRow(lv_obj_t* parent, const char* label, const char* hint,
                              const char* value, uint32_t color, int y,
                              lv_event_cb_t cb) {
  lv_obj_t *row = lv_btn_create(parent);
  lv_obj_set_size(row, 456, 56);
  lv_obj_set_pos(row, 12, y);
  lv_obj_set_style_bg_color(row, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(row, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_radius(row, 10, 0);
  lv_obj_set_style_shadow_width(row, 0, 0);
  lv_obj_set_style_border_width(row, 1, 0);
  lv_obj_set_style_border_color(row, lv_color_hex(color), 0);
  lv_obj_set_style_pad_all(row, 0, 0);

  lv_obj_t *lbl = lv_label_create(row);
  lv_label_set_text(lbl, label);
  lv_obj_set_style_text_color(lbl, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 16, -8);

  lv_obj_t *slbl = lv_label_create(row);
  lv_label_set_text(slbl, hint);
  lv_obj_set_style_text_color(slbl, lv_color_hex(UI_COL_INK_FAINT), 0);
  lv_obj_set_style_text_font(slbl, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(slbl, LV_ALIGN_LEFT_MID, 16, 12);

  lv_obj_t *vlbl = lv_label_create(row);
  lv_label_set_text(vlbl, value);
  lv_obj_set_style_text_color(vlbl, lv_color_hex(color), 0);
  lv_obj_set_style_text_font(vlbl, &lv_font_montserrat_ext_20, 0);
  lv_obj_align(vlbl, LV_ALIGN_RIGHT_MID, -16, 0);

  if (cb) lv_obj_add_event_cb(row, cb, LV_EVENT_CLICKED, NULL);
  return row;
}

// The window length, typed on the house keypad. Done only parks the value;
// the PUT happens back in buildAmsAssignScreen().
#define AMS_WINDOW_INPUT_MAX_CHARS 3   // up to AMS_WINDOW_MAX_S

static bool onAmsWindowDone(const char *text) {
  int s = atoi(text);
  if (s < AMS_WINDOW_MIN_S) s = AMS_WINDOW_MIN_S;
  if (s > AMS_WINDOW_MAX_S) s = AMS_WINDOW_MAX_S;
  s_ams_numpad_value = s;
  s_write_window_pending = true;
  show_ams_assign_pending = true;
  return true;
}

void showAmsWindowPad() {
  char initial[8];
  snprintf(initial, sizeof(initial), "%d", g_ams_window_s);
  NumPadSpec spec = {};
  spec.title      = T(STR_AMS_WINDOW_LBL);
  spec.hint       = T(STR_AMS_PAD_HINT);
  spec.unit       = T(STR_AMS_SEC_UNIT);
  spec.primary    = T(STR_BTN_SAVE);
  spec.initial    = initial;
  spec.max_chars  = AMS_WINDOW_INPUT_MAX_CHARS;
  spec.help_title = -1;
  spec.on_done    = onAmsWindowDone;
  spec.on_leave   = [] { show_ams_assign_pending = true; };
  spec.replaced_from_loop = true;
  hideAllOverlays();
  // Deleted on the loop in the same pass as the pad is built, like the drying
  // screen under its pad: back and Save rebuild it.
  if (scr_ams_assign) { lv_obj_del(scr_ams_assign); scr_ams_assign = nullptr; }
  showNumPad(spec);
}

void buildAmsAssignScreen() {
  logSD("BUILD: AmsAssignScreen");

  // Without a connection every request below would only burn its timeout
  // and freeze the screen for seconds on end.
  const bool online = wifi_ok && backendIsFilaMan();

  // ---- parked writes, before anything is drawn --------------------
  if (s_write_mode_pending >= 0 && !online) {
    // The mode itself is local, so it still switches; only the server side
    // of it has to wait for the next time the screen is opened online.
    g_ams_mode = (uint8_t)s_write_mode_pending;
    s_write_mode_pending = -1;
    prefsPutUChar("ams_mode", g_ams_mode);
  }
  if (s_write_mode_pending >= 0) {
    g_ams_mode = (uint8_t)s_write_mode_pending;
    s_write_mode_pending = -1;
    prefsPutUChar("ams_mode", g_ams_mode);
    // Only "always" wants the flag standing. The ask mode raises it for the
    // length of one report and lowers it again, so its resting state is off
    // just like "off" itself.
    const bool want = (g_ams_mode == AMS_ALWAYS);
    s_server_code = amsWriteEnabled(want);
    logSDf("AMS: mode set to %d, auto_assign_enabled=%d HTTP %d",
           g_ams_mode, (int)want, s_server_code);
  }
  if (s_write_window_pending && !online) {
    s_write_window_pending = false;
    g_ams_window_s = s_ams_numpad_value;
    prefsPutInt("ams_window", g_ams_window_s);
  }
  if (s_write_window_pending) {
    s_write_window_pending = false;
    s_server_code = amsWriteWindow(s_ams_numpad_value);
    if (s_server_code == 200) prefsPutInt("ams_window", g_ams_window_s);
    logSDf("AMS: window set to %d s, HTTP %d", s_ams_numpad_value, s_server_code);
  }

  // ---- read the server back ---------------------------------------
  if (online) {
    s_server_code = amsReadServer(&s_server_enabled);
    if (s_server_code == 200) prefsPutInt("ams_window", g_ams_window_s);
  } else {
    s_server_code = 0;   // nothing was attempted, so nothing is wrong
  }

  releaseScreen(&scr_ams_assign);
  scr_ams_assign = buildOverlayScreen();
  { char tbuf[32]; copyT(tbuf, sizeof(tbuf), STR_AMS_TITLE);
    buildSubHeader(scr_ams_assign, tbuf, [](lv_event_t *e){
      logSD("BTN: Back -> FilaMan options");
      show_filaman_options_pending = true;
    }); }

  // ---- mode buttons ------------------------------------------------
  char ml0[16], ml1[16], ml2[16];
  copyT(ml0, sizeof(ml0), STR_AMS_MODE_OFF);
  copyT(ml1, sizeof(ml1), STR_AMS_MODE_ASK);
  copyT(ml2, sizeof(ml2), STR_AMS_MODE_ALWAYS);
  const char* mode_labels[] = { ml0, ml1, ml2 };
  const int btn_w = 144, btn_h = 36, btn_y = 64, btn_gap = 6;
  const int btn_x0 = (480 - (3*btn_w + 2*btn_gap)) / 2;
  for (int m = 0; m < AMS_MODE_COUNT; m++) {
    bool active = (g_ams_mode == m);
    lv_obj_t *mb = lv_btn_create(scr_ams_assign);
    lv_obj_set_size(mb, btn_w, btn_h);
    lv_obj_set_pos(mb, btn_x0 + m*(btn_w+btn_gap), btn_y);
    lv_obj_set_style_radius(mb, 8, 0);
    lv_obj_t *ml = lv_label_create(mb);
    lv_label_set_text(ml, mode_labels[m]);
    lv_obj_set_style_text_font(ml, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(ml, LV_ALIGN_CENTER, 0, 0);
    uiSegmentLook(mb, active ? SEG_PICKED : SEG_OFF);
    lv_obj_set_user_data(mb, (void*)(intptr_t)m);
    lv_obj_add_event_cb(mb, [](lv_event_t *e){
      int new_mode = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
      if (g_ams_mode == new_mode) return;
      s_write_mode_pending = new_mode;
      show_ams_assign_pending = true;
    }, LV_EVENT_CLICKED, NULL);
  }

  // Cross-check: mode says one thing, the server another means a PUT was
  // refused. Without this nobody would notice.
  if (s_server_code == 200) {
    lv_obj_t *srv = lv_label_create(scr_ams_assign);
    { char sbuf[48];
      snprintf(sbuf, sizeof(sbuf), LV_SYMBOL_BULLET " %s",
               T(s_server_enabled ? STR_AMS_SRV_ON : STR_AMS_SRV_OFF));
      lv_label_set_text(srv, sbuf); }
    lv_obj_set_style_text_color(srv,
      s_server_enabled ? lv_color_hex(UI_COL_ACCENT) : lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_set_style_text_font(srv, &lv_font_montserrat_ext_12, 0);
    lv_obj_align(srv, LV_ALIGN_TOP_MID, 0, 104);
  }

  // ---- content per mode --------------------------------------------
  char win_val[16];
  snprintf(win_val, sizeof(win_val), "%d %s", g_ams_window_s, T(STR_AMS_SEC_UNIT));
  char win_lbl[24];  copyT(win_lbl, sizeof(win_lbl), STR_AMS_WINDOW_LBL);
  char win_hint[48]; copyT(win_hint, sizeof(win_hint), STR_AMS_WINDOW_HINT);

  // The loop replaces this screen with the pad (ams_window_pad_pending).
  auto windowRowCb = [](lv_event_t *e){ ams_window_pad_pending = true; };

  int desc_y = 132;

  if (g_ams_mode == AMS_ASK) {
    char tl[24];  copyT(tl, sizeof(tl), STR_AMS_TIMER_LBL);
    char th[40];  copyT(th, sizeof(th), STR_AMS_TIMER_HINT);
    char tv[16];  copyT(tv, sizeof(tv), g_ams_timer_yes ? STR_AMS_TIMER_YES : STR_AMS_TIMER_NO);
    makeValueRow(scr_ams_assign, tl, th, tv,
                 g_ams_timer_yes ? UI_COL_ACCENT : UI_COL_WARN, 124,
                 [](lv_event_t *e){
                   g_ams_timer_yes = !g_ams_timer_yes;
                   prefsPutBool("ams_tmr_yes", g_ams_timer_yes);
                   logSDf("AMS: timeout means %s", g_ams_timer_yes ? "yes" : "no");
                   show_ams_assign_pending = true;
                 });
    makeValueRow(scr_ams_assign, win_lbl, win_hint, win_val, UI_COL_ACCENT, 186, windowRowCb);
    desc_y = 250;
  } else if (g_ams_mode == AMS_ALWAYS) {
    makeValueRow(scr_ams_assign, win_lbl, win_hint, win_val, UI_COL_ACCENT, 124, windowRowCb);
    desc_y = 188;
  }

  // Description of the active mode, plus the auto weighing caveat: without
  // it the ask mode never gets a measurement to ask about.
  {
    char dbuf[320];
    const int desc_id = (g_ams_mode == AMS_ASK)    ? STR_AMS_ASK_DESC
                      : (g_ams_mode == AMS_ALWAYS) ? STR_AMS_ALWAYS_DESC
                                                   : STR_AMS_OFF_DESC;
    copyT(dbuf, sizeof(dbuf), desc_id);
    lv_obj_t *lbl = lv_label_create(scr_ams_assign);
    lv_label_set_text(lbl, dbuf);
    lv_obj_set_style_text_color(lbl, lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(lbl, 452);
    lv_label_set_long_mode(lbl, LV_LABEL_LONG_WRAP);
    lv_obj_align(lbl, LV_ALIGN_TOP_MID, 0, desc_y);
  }

  // Why a value is missing matters: a refused key reads very differently
  // from a server that is simply not answering.
  if (s_server_code != 200 && s_server_code != 0) {
    char ebuf[80];
    if (s_server_code == 403) {
      copyT(ebuf, sizeof(ebuf), STR_AMS_ERR_FORBIDDEN);
    } else {
      snprintf(ebuf, sizeof(ebuf), T(STR_AMS_ERR_HTTP), s_server_code);
    }
    lv_obj_t *err = lv_label_create(scr_ams_assign);
    lv_label_set_text(err, ebuf);
    lv_obj_set_style_text_color(err, lv_color_hex(UI_COL_BAD), 0);
    lv_obj_set_style_text_font(err, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(err, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(err, 452);
    lv_label_set_long_mode(err, LV_LABEL_LONG_WRAP);
    lv_obj_align(err, LV_ALIGN_BOTTOM_MID, 0, -4);
  }
}
