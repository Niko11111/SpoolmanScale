#include "factor_screen.h"
#include "navigation.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cmath>
#include <cstdlib>
#include <cstring>

#include "app_config.h"
#include "hardware/scale.h"
#include "hardware/scale_state.h"
#include "confirm_popup.h"
#include "info_popup.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "scale_menu.h"
#include "services/prefs_store.h"
#include "services/user_options.h"
#include "ui_common.h"


void resetActivityTimer();

static char factor_input[16] = "";
static lv_obj_t *lbl_factor_display = nullptr;


void showFactorScreen() {
  logSD("SHOW: FactorScreen");
  logSD("UI: Screen -> Calibration");
  // Null all loop-update pointers BEFORE deleting scr_factor
  // Loop checks these pointers — must be null before del to avoid dangling access
  lbl_factor_display    = nullptr;
  lbl_factor_result     = nullptr;
  lbl_factor_cal_weight = nullptr;
  // Now safe to delete
  if (scr_factor) { lv_obj_del(scr_factor); scr_factor = nullptr; }
  buildFactorScreen();
  // hideAllOverlays() is the authoritative list. A hand maintained copy used to
  // live here and had drifted: scr_backend, scr_drying_reminder, scr_lastused,
  // scr_more_info, scr_ota_github and scr_spoolman_fail were missing, so coming
  // here from any of them left the old screen standing. Order matters - it also
  // hides scr_factor, which buildFactorScreen() created hidden anyway, so the
  // screen is shown right afterwards.
  hideAllOverlays();
  lv_obj_clear_flag(scr_factor, LV_OBJ_FLAG_HIDDEN);
  resetActivityTimer();
}

void buildFactorScreen() {
  logSD("BUILD: FactorScreen");
  releaseScreen(&scr_factor);
  scr_factor = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_factor, 480, 320);
  lv_obj_set_pos(scr_factor, 0, 0);
  lv_obj_add_flag(scr_factor, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_factor, 0, 0);
  lv_obj_set_style_border_width(scr_factor, 0, 0);
  lv_obj_set_style_pad_all(scr_factor, 0, 0);
  lv_obj_clear_flag(scr_factor, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_factor, lv_color_hex(0x0a1020), 0);

  // Crash protection: null label pointers (screen is rebuilt)
  lbl_factor_display = nullptr;
  lbl_factor_result  = nullptr;
  lbl_factor_cal_weight = nullptr;
  factor_input[0]    = '\0';

  buildSubHeader(scr_factor, T(STR_CAL_TITLE),
    [](lv_event_t *e){
      hideAllOverlays();
      if (!scr_scale_sub) buildScaleSubScreen();
      lv_obj_clear_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN);
    });

  // Description / hint — single line, compact
  lv_obj_t *lbl_desc = lv_label_create(scr_factor);
  lv_label_set_text(lbl_desc, T(STR_CAL_TARE_HINT));
  lv_obj_set_style_text_color(lbl_desc, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_desc, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_desc, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_desc, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_desc, 440);
  lv_obj_align(lbl_desc, LV_ALIGN_TOP_MID, 0, 54);

  // The whole instruction, one tap away. This screen has room for the one line
  // above and a numpad, not for the four steps someone needs the first time -
  // and the first time is exactly when they are here. Styled like the help
  // circles on the settings rows so it reads as the same affordance.
  //
  // In the header row rather than beside the hint: everything from y=50 down
  // is spoken for - the factor readout sits at the right edge at y=78 - and
  // the 16 px between the centred title and the close button is the one gap on
  // this screen that nothing else wants.
  lv_obj_t *help = lv_btn_create(scr_factor);
  lv_obj_set_size(help, 34, 34);
  lv_obj_set_pos(help, 386, 5);
  lv_obj_set_style_bg_opa(help, LV_OPA_TRANSP, 0);
  lv_obj_set_style_bg_color(help, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_bg_opa(help, LV_OPA_COVER, LV_STATE_PRESSED);
  lv_obj_set_style_border_color(help, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(help, 1, 0);
  lv_obj_set_style_radius(help, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_shadow_width(help, 0, 0);
  lv_obj_set_style_pad_all(help, 0, 0);
  lv_obj_set_ext_click_area(help, 6);
  lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                      INFO_POPUP_ARG(STR_CAL_HELP_TITLE, STR_CAL_HELP_TEXT));
  lv_obj_t *help_q = lv_label_create(help);
  lv_label_set_text(help_q, "?");
  lv_obj_set_style_text_color(help_q, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(help_q, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(help_q, LV_ALIGN_CENTER, 0, 0);

  // Single status row: "Scale: <value>" left | "Factor: --" right
  lv_obj_t *lbl_cal_w_title = lv_label_create(scr_factor);
  lv_label_set_text(lbl_cal_w_title, T(STR_LBL_SCALE));
  lv_obj_set_style_text_color(lbl_cal_w_title, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_cal_w_title, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_cal_w_title, 12, 78);

  lbl_factor_cal_weight = lv_label_create(scr_factor);
  lv_label_set_text(lbl_factor_cal_weight, "-- g");
  lv_obj_set_style_text_color(lbl_factor_cal_weight, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_factor_cal_weight, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_factor_cal_weight, 56, 78);

  lbl_factor_result = lv_label_create(scr_factor);
  lv_label_set_text(lbl_factor_result, T(STR_CAL_FACTOR));
  lv_obj_set_style_text_color(lbl_factor_result, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_factor_result, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_factor_result, LV_TEXT_ALIGN_RIGHT, 0);
  lv_obj_set_width(lbl_factor_result, 220);
  lv_obj_set_pos(lbl_factor_result, 248, 78);

  // Input field — y=94 (below status row)
  lv_obj_t *input_box_f = lv_obj_create(scr_factor);
  lv_obj_set_size(input_box_f, 260, 34);
  lv_obj_align(input_box_f, LV_ALIGN_TOP_MID, 0, 94);
  lv_obj_set_style_bg_color(input_box_f, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_border_color(input_box_f, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(input_box_f, 1, 0);
  lv_obj_set_style_radius(input_box_f, 6, 0);
  lv_obj_set_style_pad_all(input_box_f, 0, 0);
  lv_obj_clear_flag(input_box_f, LV_OBJ_FLAG_SCROLLABLE);

  lbl_factor_display = lv_label_create(input_box_f);
  lv_label_set_text(lbl_factor_display, "_");
  lv_obj_set_style_text_color(lbl_factor_display, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_factor_display, &lv_font_montserrat_ext_20, 0);
  lv_obj_set_style_text_align(lbl_factor_display, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_center(lbl_factor_display);

  // ── Numpad (104x30, start y=132) ──
  const int NP_W = 104, NP_H = 30, NP_GAP = 4;
  const int NP_PAD_X = (480 - 3*NP_W - 2*NP_GAP) / 2;
  const int NP_START_Y = 132;

  const char* np_labels_f[] = { "1","2","3","4","5","6","7","8","9",".","0","T" };

  // ── Whole-gram toggle (left of numpad, 68x68px) ──
  // NP_PAD_X = 80px — 68px toggle fits with 6px margin
  {
    lv_obj_t *btn_wg = lv_btn_create(scr_factor);
    lv_obj_set_size(btn_wg, 68, 68);
    int wg_y = NP_START_Y + (4*(NP_H+NP_GAP) - 68) / 2;  // vertically centred in numpad area
    lv_obj_set_pos(btn_wg, 6, wg_y);
    lv_obj_set_style_radius(btn_wg, 8, 0);
    lv_obj_set_style_shadow_width(btn_wg, 0, 0);
    lv_obj_set_style_border_width(btn_wg, 1, 0);
    lv_obj_set_style_bg_color(btn_wg, g_whole_gram ? lv_color_hex(0x1a3020) : lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_border_color(btn_wg, g_whole_gram ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_bg_color(btn_wg, lv_color_hex(0x2a5030), LV_STATE_PRESSED);

    lv_obj_t *lbl_wg = lv_label_create(btn_wg);
    lv_label_set_text(lbl_wg, T(STR_WHOLE_GRAM));
    lv_obj_set_style_text_color(lbl_wg, g_whole_gram ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_wg, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(lbl_wg, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(lbl_wg, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(lbl_wg, 60);
    lv_obj_center(lbl_wg);

    lv_obj_add_event_cb(btn_wg, [](lv_event_t *e) {
      g_whole_gram = !g_whole_gram;
      prefsPutBool("whole_gram", g_whole_gram);
      lv_obj_t *b = lv_event_get_target(e);
      lv_obj_t *l = lv_obj_get_child(b, 0);
      lv_obj_set_style_bg_color(b, g_whole_gram ? lv_color_hex(0x1a3020) : lv_color_hex(0x0a1828), 0);
      lv_obj_set_style_border_color(b, g_whole_gram ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a2840), 0);
      lv_obj_set_style_text_color(l, g_whole_gram ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
    }, LV_EVENT_CLICKED, NULL);
  }

  // ── Reset calibration (right of numpad, mirror of the toggle) ──
  // The way back from a calibration taken while the ADC was off the bus: every
  // reading was -1 then, the stored factor is arithmetic on nonsense, and no
  // amount of re-tareing fixes it. This is the only place it can be asked for,
  // and the screen someone is on when they find out they need it.
  //
  // The column right of the numpad (x 400..480) is otherwise empty, so the
  // button sits where the whole-gram toggle sits on the other side.
  {
    lv_obj_t *btn_rst = lv_btn_create(scr_factor);
    lv_obj_set_size(btn_rst, 68, 68);
    int rst_y = NP_START_Y + (4*(NP_H+NP_GAP) - 68) / 2;
    lv_obj_set_pos(btn_rst, 480 - 68 - 6, rst_y);
    lv_obj_set_style_radius(btn_rst, 8, 0);
    lv_obj_set_style_shadow_width(btn_rst, 0, 0);
    lv_obj_set_style_border_width(btn_rst, 1, 0);
    // The house red for something that cannot be taken back, as in
    // ui_common.cpp addCloseButton() and the No button of every confirmation.
    lv_obj_set_style_bg_color(btn_rst, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_rst, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_border_color(btn_rst, lv_color_hex(0x601010), 0);

    lv_obj_t *lbl_rst = lv_label_create(btn_rst);
    { char rb[24]; strncpy(rb, T(STR_BTN_CAL_RESET_SHORT), sizeof(rb) - 1);
      rb[sizeof(rb) - 1] = '\0'; lv_label_set_text(lbl_rst, rb); }
    lv_obj_set_style_text_color(lbl_rst, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_rst, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(lbl_rst, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(lbl_rst, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(lbl_rst, 60);
    lv_obj_center(lbl_rst);

    lv_obj_add_event_cb(btn_rst, [](lv_event_t *e) {
      // The write itself is deferred like every other NVS write reached from a
      // callback, and it rebuilds nothing - see cal_reset_pending in app_loop.
      logSD("BTN: Calibration -> Reset calibration");
      char ask[64]; strncpy(ask, T(STR_CAL_RESET_CONFIRM), sizeof(ask) - 1);
      ask[sizeof(ask) - 1] = '\0';
      showConfirmPopup(ask, 6);
    }, LV_EVENT_CLICKED, NULL);
  }

  for (int i = 0; i < 12; i++) {
    int col = i % 3, row = i / 3;
    lv_obj_t *btn = lv_btn_create(scr_factor);
    lv_obj_set_size(btn, NP_W, NP_H);
    lv_obj_set_pos(btn, NP_PAD_X + col*(NP_W+NP_GAP), NP_START_Y + row*(NP_H+NP_GAP));

    if (i == 11) {
      // TARE button in the free slot (bottom right of numpad)
      lv_obj_set_style_bg_color(btn, lv_color_hex(0x2a2010), 0);
      lv_obj_set_style_bg_color(btn, lv_color_hex(0x4a4020), LV_STATE_PRESSED);
      lv_obj_set_style_radius(btn, 6, 0);
      lv_obj_set_style_shadow_width(btn, 0, 0);
      lv_obj_set_style_border_width(btn, 1, 0);
      lv_obj_set_style_border_color(btn, lv_color_hex(0x3a3010), 0);
      lv_obj_add_event_cb(btn, [](lv_event_t *e) {
        if (!lbl_factor_result) return;
        // Presence asked as well as scale_ready: an ADC that left the bus
        // reads back as all ones, and tare would store -1 as the zero point.
        if (scale_ready && scaleHardwarePresent()) {
          int32_t raw = scaleHardwareReadRaw();
          saveTareOffset(raw);
          scale_weight_g = 0.0f;
          resetScaleFilter();
          lv_label_set_text(lbl_factor_result, T(STR_TARE_OK));
          lv_label_set_text(lbl_scale_weight, "0 g");
          Serial.println("Tare (calibration screen) executed");
        } else {
          lv_label_set_text(lbl_factor_result, T(STR_TARE_NOT_READY));
        }
      }, LV_EVENT_CLICKED, NULL);
      lv_obj_t *lbl = lv_label_create(btn);
      lv_label_set_text(lbl, LV_SYMBOL_REFRESH "TARE");
      lv_obj_set_style_text_color(lbl, lv_color_hex(0xf0b838), 0);
      lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_14, 0);
      lv_obj_center(lbl);
    } else {
      lv_obj_set_style_bg_color(btn, lv_color_hex(0x0a1828), 0);
      lv_obj_set_style_bg_color(btn, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
      lv_obj_set_style_radius(btn, 6, 0);
      lv_obj_set_style_shadow_width(btn, 0, 0);
      lv_obj_set_style_border_width(btn, 1, 0);
      lv_obj_set_style_border_color(btn, lv_color_hex(0x1a2840), 0);
      lv_obj_t *lbl = lv_label_create(btn);
      lv_label_set_text(lbl, np_labels_f[i]);
      lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
      lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
      lv_obj_center(lbl);
      lv_obj_add_event_cb(btn, [](lv_event_t *e) {
        if (!lbl_factor_display) return;
        const char* ch = lv_label_get_text(lv_obj_get_child(lv_event_get_target(e), 0));
        if (ch[0] == '.' && strchr(factor_input, '.')) return;
        int len = strlen(factor_input);
        if (len < (int)sizeof(factor_input)-1) { factor_input[len]=ch[0]; factor_input[len+1]='\0'; }
        lv_label_set_text(lbl_factor_display, factor_input[0] ? factor_input : "_");
      }, LV_EVENT_CLICKED, NULL);
    }
  }

  int by5_f = NP_START_Y + 4*(NP_H+NP_GAP);
  int bw5_f = (3*NP_W + 2*NP_GAP - NP_GAP) / 2;

  lv_obj_t *btn_del_f = lv_btn_create(scr_factor);
  lv_obj_set_size(btn_del_f, bw5_f, NP_H);
  lv_obj_set_pos(btn_del_f, NP_PAD_X, by5_f);
  lv_obj_set_style_bg_color(btn_del_f, lv_color_hex(0x1a2030), 0);
  lv_obj_set_style_bg_color(btn_del_f, lv_color_hex(0x2a3040), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_del_f, 6, 0);
  lv_obj_set_style_shadow_width(btn_del_f, 0, 0);
  lv_obj_set_style_border_width(btn_del_f, 1, 0);
  lv_obj_set_style_border_color(btn_del_f, lv_color_hex(0x1a2840), 0);
  lv_obj_add_event_cb(btn_del_f, [](lv_event_t *e) {
    if (!lbl_factor_display) return;
    int len = strlen(factor_input);
    if (len > 0) factor_input[len-1] = '\0';
    lv_label_set_text(lbl_factor_display, factor_input[0] ? factor_input : "_");
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_del_f = lv_label_create(btn_del_f);
  lv_label_set_text(lbl_del_f, LV_SYMBOL_BACKSPACE);
  lv_obj_set_style_text_color(lbl_del_f, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_del_f, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_del_f);

  lv_obj_t *btn_ok_f = lv_btn_create(scr_factor);
  lv_obj_set_size(btn_ok_f, bw5_f, NP_H);
  lv_obj_set_pos(btn_ok_f, NP_PAD_X + bw5_f + NP_GAP, by5_f);
  lv_obj_set_style_bg_color(btn_ok_f, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_ok_f, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok_f, 6, 0);
  lv_obj_set_style_shadow_width(btn_ok_f, 0, 0);
  lv_obj_set_style_border_width(btn_ok_f, 1, 0);
  lv_obj_set_style_border_color(btn_ok_f, lv_color_hex(0x2a5030), 0);
  lv_obj_add_event_cb(btn_ok_f, [](lv_event_t *e) {
    if (!lbl_factor_result) return;
    float known_g = atof(factor_input);
    if (!scale_ready || !scaleHardwarePresent()) {
      lv_label_set_text(lbl_factor_result, T(STR_TARE_NOT_READY));
    } else if (known_g <= 0) {
      lv_label_set_text(lbl_factor_result, T(STR_CAL_ZERO_ERR));
    } else if (known_g < CAL_KNOWN_MIN_G || known_g > CAL_KNOWN_MAX_G) {
      lv_label_set_text(lbl_factor_result, T(STR_CAL_RANGE_ERR));
    } else {
      int32_t raw = scaleHardwareReadRaw();
      float factor = (float)(raw - zero_offset) / known_g;
      // The last line of defence. A reading the bus never delivered is -1, and
      // if tare stored -1 too the difference is zero: the factor collapses and
      // every later weight explodes. Refusing here costs a retry; storing it
      // costs a device that has to be re-flashed to be usable again.
      if (!isfinite(factor) ||
          fabsf(factor) < CAL_FACTOR_MIN || fabsf(factor) > CAL_FACTOR_MAX) {
        Serial.printf("Calibration refused: raw=%d zero=%d known=%.1f factor=%.6f\n",
                      raw, zero_offset, known_g, factor);
        lv_label_set_text(lbl_factor_result, T(STR_CAL_IMPLAUSIBLE));
      } else {
        saveCalFactor(factor);
        char buf[64];
        snprintf(buf, sizeof(buf), T(STR_CAL_OK), factor);
        lv_label_set_text(lbl_factor_result, buf);
      }
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ok2_f = lv_label_create(btn_ok_f);
  lv_label_set_text(lbl_ok2_f, T(STR_BTN_CALCULATE));
  lv_obj_set_style_text_color(lbl_ok2_f, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_ok2_f, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(lbl_ok2_f);
}
