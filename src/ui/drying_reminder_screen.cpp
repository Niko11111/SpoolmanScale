#include "drying_reminder_screen.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "ota_browser.h"
#include "scale_menu.h"
#include "services/drying_config.h"
#include "services/prefs_store.h"
#include "ui_common.h"
#include "theme.h"


// ============================================================
//  DRYING REMINDER SCREEN
//  Modi: 0=Aus  1=Material  2=Manuell
//  Manuell-Werte per Numpad editierbar; Material-Werte per Webserver
// ============================================================

// Numpad-Subscreen fuer Schwellwert-Eingabe
// target: 0=Manuell-Gelb, 1=Manuell-Rot
static void buildDryNumpadScreen(int target) {
  logSDf("BUILD: DryNumpadScreen target=%d", target);
  s_dry_numpad_target = target;
  s_dry_numpad_value  = (target == 0) ? g_dry_man_yellow : g_dry_man_red;
  if (s_dry_numpad_scr) { lv_obj_del(s_dry_numpad_scr); s_dry_numpad_scr = nullptr; }
  s_dry_numpad_scr = buildOverlayScreen(&s_dry_numpad_scr);
  // Header
  char title_buf[32];
  strncpy(title_buf, (target == 0) ? T(STR_DRY_NUMPAD_YELLOW_TITLE) : T(STR_DRY_NUMPAD_RED_TITLE), sizeof(title_buf)-1);
  title_buf[sizeof(title_buf)-1] = '\0';
  const char* title_str = title_buf;
  buildSubHeader(s_dry_numpad_scr, title_str, [](lv_event_t *e){
    if (s_dry_numpad_scr) { lv_obj_del(s_dry_numpad_scr); s_dry_numpad_scr = nullptr; }
    show_drying_reminder_pending = true;
  });
  // Wert-Anzeige
  lv_obj_t *val_box = lv_obj_create(s_dry_numpad_scr);
  lv_obj_set_size(val_box, 380, 44);
  lv_obj_set_pos(val_box, 50, 68);
  lv_obj_set_style_bg_color(val_box, tc(TH_BG), 0);
  lv_obj_set_style_border_color(val_box, tc(TH_ACCENT), 0);
  lv_obj_set_style_border_width(val_box, 1, 0);
  lv_obj_set_style_radius(val_box, 8, 0);
  s_dry_numpad_lbl = lv_label_create(val_box);
  char vbuf[16]; snprintf(vbuf, sizeof(vbuf), "%d %s", s_dry_numpad_value, T(STR_DRY_DAYS_UNIT));
  lv_label_set_text(s_dry_numpad_lbl, vbuf);
  lv_obj_set_style_text_color(s_dry_numpad_lbl, tc(TH_ACCENT), 0);
  lv_obj_set_style_text_font(s_dry_numpad_lbl, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(s_dry_numpad_lbl, LV_ALIGN_CENTER, 0, 0);

  // Numpad 3x4 Grid: 1-9, DEL, 0, SAVE (standard pattern)
  // Row4: [DEL][0][SAVE] — SAVE replaces separate button below
  const int NP_W = 136, NP_H = 36, NP_GAP = 4;
  const int NP_X0 = (480 - 3*NP_W - 2*NP_GAP) / 2;
  const int NP_Y0 = 122;
  static const char* keys[] = { "1","2","3","4","5","6","7","8","9","DEL","0","OK" };
  int kx = 0, ky = 0, kw = NP_W, kh = NP_H, gap = NP_GAP;  // unused vars kept for compat
  for (int i = 0; i < 12; i++) {
    int col = i % 3, row = i / 3;
    int bx = NP_X0 + col * (NP_W + NP_GAP);
    int by = NP_Y0 + row * (NP_H + NP_GAP);
    bool is_del = (strcmp(keys[i], "DEL") == 0);
    bool is_ok  = (strcmp(keys[i], "OK")  == 0);
    lv_obj_t *kb = lv_btn_create(s_dry_numpad_scr);
    lv_obj_set_size(kb, NP_W, NP_H);
    lv_obj_set_pos(kb, bx, by);
    lv_obj_set_style_bg_color(kb, is_del ? tc(TH_BG) :
                                  is_ok  ? lv_color_hex(g_theme[TH_OK_BG]) :
                                           tc(TH_SURFACE), 0);
    lv_obj_set_style_bg_color(kb, tc(TH_BORDER), LV_STATE_PRESSED);
    lv_obj_set_style_radius(kb, 6, 0);
    lv_obj_set_style_shadow_width(kb, 0, 0);
    lv_obj_set_style_border_width(kb, 1, 0);
    lv_obj_set_style_border_color(kb, is_ok ? tc(TH_ACCENT) : tc(TH_BORDER), 0);
    lv_obj_t *kl = lv_label_create(kb);
    lv_label_set_text(kl, is_ok ? LV_SYMBOL_OK : keys[i]);
    lv_obj_set_style_text_color(kl, is_del ? lv_color_hex(0xe04040) :
                                     is_ok  ? tc(TH_ACCENT) :
                                              tc(TH_TEXT_BRIGHT), 0);
    lv_obj_set_style_text_font(kl, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(kl, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_user_data(kb, (void*)keys[i]);
    lv_obj_add_event_cb(kb, [](lv_event_t *e){
      const char* k = (const char*)lv_obj_get_user_data(lv_event_get_target(e));
      if (!k || !s_dry_numpad_lbl) return;
      if (strcmp(k, "DEL") == 0) {
        s_dry_numpad_value /= 10;
      } else if (strcmp(k, "OK") == 0) {
        // Speichern (gleiche Logik wie Save-Button)
        if (s_dry_numpad_value < 1) s_dry_numpad_value = 1;
        if (s_dry_numpad_target == 0) g_dry_man_yellow = s_dry_numpad_value;
        else                           g_dry_man_red    = s_dry_numpad_value;
        logSDf("Drying Reminder: manual yellow=%d red=%d", g_dry_man_yellow, g_dry_man_red);
        prefsPutInt("dry_man_y", g_dry_man_yellow);
        prefsPutInt("dry_man_r", g_dry_man_red);
        if (s_dry_numpad_scr) { lv_obj_del(s_dry_numpad_scr); s_dry_numpad_scr = nullptr; }
        show_drying_reminder_pending = true;
        return;
      } else {
        int digit = k[0] - '0';
        if (s_dry_numpad_value < 999)
          s_dry_numpad_value = s_dry_numpad_value * 10 + digit;
      }
      char vb[16]; snprintf(vb, sizeof(vb), "%d %s", s_dry_numpad_value, T(STR_DRY_DAYS_UNIT));
      lv_label_set_text(s_dry_numpad_lbl, vb);
    }, LV_EVENT_CLICKED, NULL);
  }

  // Save is now handled by OK key in numpad grid
}

void showDryingReminderScreen() {
  logSD("SHOW: DryingReminderScreen");
  if (scr_drying_reminder) { lv_obj_del(scr_drying_reminder); scr_drying_reminder = nullptr; }
  scr_drying_reminder = buildOverlayScreen(&scr_drying_reminder);
  buildSubHeader(scr_drying_reminder, T(STR_DRYING_REMINDER_TITLE),
    [](lv_event_t *e){ logSD("BTN: Back -> Scale");
      if (scr_drying_reminder) { lv_obj_del(scr_drying_reminder); scr_drying_reminder = nullptr; }
      if (scr_scale_sub) { lv_obj_del(scr_scale_sub); scr_scale_sub = nullptr; }
      buildScaleSubScreen();
      lv_obj_clear_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN);
    });

  // ── Modi-Toggle-Buttons ──────────────────────────────────
  // Drei Buttons nebeneinander: Aus / Material / Manuell
  char ml0[16],ml1[16],ml2[16];
  strncpy(ml0,T(STR_DRY_MODE_OFF),sizeof(ml0)-1);
  strncpy(ml1,T(STR_DRY_MODE_MATERIAL),sizeof(ml1)-1);
  strncpy(ml2,T(STR_DRY_MODE_MANUAL),sizeof(ml2)-1);
  const char* mode_labels[] = { ml0, ml1, ml2 };
  int btn_w = 144, btn_h = 36, btn_y = 64, btn_gap = 6;
  int total_w = 3*btn_w + 2*btn_gap;
  int btn_x0 = (480 - total_w) / 2;
  for (int m = 0; m < 3; m++) {
    bool active = (g_dry_mode == m);
    lv_obj_t *mb = lv_btn_create(scr_drying_reminder);
    lv_obj_set_size(mb, btn_w, btn_h);
    lv_obj_set_pos(mb, btn_x0 + m*(btn_w+btn_gap), btn_y);
    lv_obj_set_style_bg_color(mb, active ? tc(TH_OK_BG) : tc(TH_SURFACE), 0);
    lv_obj_set_style_bg_color(mb, tc(TH_BORDER), LV_STATE_PRESSED);
    lv_obj_set_style_border_color(mb, active ? tc(TH_ACCENT) : tc(TH_BORDER), 0);
    lv_obj_set_style_border_width(mb, 1, 0);
    lv_obj_set_style_radius(mb, 8, 0);
    lv_obj_set_style_shadow_width(mb, 0, 0);
    lv_obj_t *ml = lv_label_create(mb);
    lv_label_set_text(ml, mode_labels[m]);
    lv_obj_set_style_text_color(ml, active ? tc(TH_ACCENT) : tc(TH_TEXT_MUTED), 0);
    lv_obj_set_style_text_font(ml, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(ml, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_user_data(mb, (void*)(intptr_t)m);
    lv_obj_add_event_cb(mb, [](lv_event_t *e){
      uint8_t new_mode = (uint8_t)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
      if (g_dry_mode == new_mode) return;
      g_dry_mode = new_mode;
      logSDf("Drying Reminder: mode set to %d", g_dry_mode);
      prefsPutUChar("dry_mode", g_dry_mode);
      show_drying_reminder_pending = true;
    }, LV_EVENT_CLICKED, NULL);
  }

  // ── Inhaltsbereich je nach Modus ────────────────────────
  int content_y = 112;

  if (g_dry_mode == 0) {
    // Aus: Erklaerungstext
    lv_obj_t *lbl = lv_label_create(scr_drying_reminder);
    { char dbuf[200]; strncpy(dbuf, T(STR_DRY_OFF_DESC), sizeof(dbuf)-1);
      lv_label_set_text(lbl, dbuf); }
    lv_obj_set_style_text_color(lbl, tc(TH_TEXT_MUTED), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(lbl, 440);
    lv_label_set_long_mode(lbl, LV_LABEL_LONG_WRAP);
    lv_obj_align(lbl, LV_ALIGN_TOP_MID, 0, content_y);

  } else if (g_dry_mode == 1) {
    // Material: Tabelle der Schwellwerte (read-only)
    lv_obj_t *hint = lv_label_create(scr_drying_reminder);
    { char hbuf[64]; strncpy(hbuf, T(STR_DRY_MAT_HINT), sizeof(hbuf)-1); hbuf[sizeof(hbuf)-1]=0;
      lv_label_set_text(hint, hbuf); }
    lv_obj_set_style_text_color(hint, tc(TH_TEXT_MUTED), 0);
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_LEFT, 0);
    lv_obj_set_width(hint, 300);
    lv_obj_set_pos(hint, 12, content_y);

    // The hint said the thresholds are editable in the browser but left the
    // user to find the way there through the update menu. LVGL labels have no
    // clickable words, so the link is a small button next to the text.
    lv_obj_t *btn_web = lv_btn_create(scr_drying_reminder);
    lv_obj_set_size(btn_web, 150, 26);
    lv_obj_set_pos(btn_web, 318, content_y - 6);
    lv_obj_set_style_bg_color(btn_web, tc(TH_TILE_BG), 0);
    lv_obj_set_style_bg_color(btn_web, tc(TH_BORDER), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_web, 6, 0);
    lv_obj_set_style_shadow_width(btn_web, 0, 0);
    lv_obj_set_style_border_width(btn_web, 1, 0);
    lv_obj_set_style_border_color(btn_web, tc(TH_SURFACE_2), 0);
    lv_obj_add_event_cb(btn_web, [](lv_event_t *e) {
      logSD("BTN: Drying -> Web interface");
      showOtaBrowserScreen(WEB_CTX_DRYING);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_web = lv_label_create(btn_web);
    { char wbuf[32]; snprintf(wbuf, sizeof(wbuf), "%s  " LV_SYMBOL_RIGHT, T(STR_BTN_OPEN_BROWSER));
      lv_label_set_text(lbl_web, wbuf); }
    lv_obj_set_style_text_color(lbl_web, tc(TH_ACCENT), 0);
    lv_obj_set_style_text_font(lbl_web, &lv_font_montserrat_ext_12, 0);
    lv_obj_center(lbl_web);

    content_y += 24;

    // Scrollbare Tabelle
    lv_obj_t *tbl_cont = lv_obj_create(scr_drying_reminder);
    lv_obj_set_size(tbl_cont, 456, 162);
    lv_obj_set_pos(tbl_cont, 12, content_y + 4);
    lv_obj_set_style_bg_color(tbl_cont, tc(TH_BG), 0);
    lv_obj_set_style_border_color(tbl_cont, tc(TH_BORDER), 0);
    lv_obj_set_style_border_width(tbl_cont, 1, 0);
    lv_obj_set_style_radius(tbl_cont, 8, 0);
    lv_obj_set_style_pad_all(tbl_cont, 6, 0);
    lv_obj_set_style_pad_row(tbl_cont, 3, 0);
    lv_obj_set_flex_flow(tbl_cont, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scroll_dir(tbl_cont, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(tbl_cont, LV_SCROLLBAR_MODE_AUTO);
    // Header-Zeile
    { lv_obj_t *row = lv_obj_create(tbl_cont);
      lv_obj_set_size(row, 430, 24);
      lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0);
      lv_obj_set_style_border_width(row, 0, 0);
      lv_obj_set_style_pad_all(row, 0, 0);
      auto hdr = [&](const char* t, int x, int w){
        lv_obj_t *l = lv_label_create(row);
        lv_label_set_text(l, t);
        lv_obj_set_style_text_color(l, tc(TH_TEXT_MUTED), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_12, 0);
        lv_obj_set_width(l, w);
        lv_obj_set_pos(l, x, 4);
      };
      { char h0[24],h1[24],h2[24];
      strncpy(h0,T(STR_DRY_MAT_HDR_MAT),sizeof(h0)-1);
      strncpy(h1,T(STR_DRY_MAT_HDR_YELLOW),sizeof(h1)-1);
      strncpy(h2,T(STR_DRY_MAT_HDR_RED),sizeof(h2)-1);
      hdr(h0,0,72); hdr(h1,80,120); hdr(h2,210,120);
      lv_obj_t *h4l = lv_label_create(row);
      lv_label_set_text(h4l, T(STR_DRY_SEALED_HDR));
      lv_obj_set_style_text_color(h4l, tc(TH_TEXT_MUTED), 0);
      lv_obj_set_style_text_font(h4l, &lv_font_montserrat_ext_12, 0);
      lv_obj_set_width(h4l, 50); lv_obj_set_pos(h4l, 366, 4); }
    }
    // Daten-Zeilen
    for (int i = 0; i < DRY_MAT_COUNT; i++) {
      lv_obj_t *row = lv_obj_create(tbl_cont);
      lv_obj_set_size(row, 430, 24);
      lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0);
      lv_obj_set_style_border_width(row, 0, 0);
      lv_obj_set_style_pad_all(row, 0, 0);
      auto cell = [&](const char* t, int x, int w, uint32_t col){
        lv_obj_t *l = lv_label_create(row);
        lv_label_set_text(l, t);
        lv_obj_set_style_text_color(l, lv_color_hex(col), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_14, 0);
        lv_obj_set_width(l, w);
        lv_obj_set_pos(l, x, 2);
      };
      // Effektive Schwellwerte (mit Multiplikator wenn sealed)
      float eff_mult = g_dry_mat_sealed[i] ? g_dry_mult_sealed : 1.0f;
      int eff_y = (int)(g_dry_mat_yellow[i] * eff_mult);
      int eff_r = (int)(g_dry_mat_red[i]    * eff_mult);
      char y_buf[10], r_buf[10];
      snprintf(y_buf, sizeof(y_buf), "%d T.", eff_y);
      snprintf(r_buf, sizeof(r_buf), "%d T.", eff_r);
      cell(DRY_MAT_NAMES[i], 0,  72, g_theme[TH_TEXT_BRIGHT]);
      cell(y_buf,            80, 120, g_theme[TH_WARNING]);
      cell(r_buf,           210, 120, 0xe04040);
      // Sealed-Symbol
      lv_obj_t *seal_lbl = lv_label_create(row);
      lv_label_set_text(seal_lbl, g_dry_mat_sealed[i] ? LV_SYMBOL_OK : "-");
      lv_obj_set_style_text_color(seal_lbl, g_dry_mat_sealed[i] ? tc(TH_ACCENT) : tc(TH_TEXT_DIM), 0);
      lv_obj_set_style_text_font(seal_lbl, &lv_font_montserrat_ext_14, 0);
      lv_obj_set_pos(seal_lbl, 370, 2);
    }
    // Fussnote
    lv_obj_t *fn = lv_label_create(scr_drying_reminder);
    { char fnbuf[80]; snprintf(fnbuf, sizeof(fnbuf), T(STR_DRY_MAT_EFF_NOTE), g_dry_mult_sealed); lv_label_set_text(fn, fnbuf); }
    lv_obj_set_style_text_color(fn, tc(TH_TEXT_DIM), 0);
    lv_obj_set_style_text_font(fn, &lv_font_montserrat_ext_12, 0);
    lv_obj_align(fn, LV_ALIGN_BOTTOM_MID, 0, -4);

  } else {
    // Manuell: zwei Zeilen, Gelb + Rot, per Numpad editierbar
    auto makeThreshRow = [&](const char* label, int value, uint32_t color, int y, int target){
      lv_obj_t *row_btn = lv_btn_create(scr_drying_reminder);
      lv_obj_set_size(row_btn, 456, 56);
      lv_obj_set_pos(row_btn, 12, y);
      lv_obj_set_style_bg_color(row_btn, tc(TH_TILE_BG), 0);
      lv_obj_set_style_bg_color(row_btn, tc(TH_BORDER), LV_STATE_PRESSED);
      lv_obj_set_style_radius(row_btn, 10, 0);
      lv_obj_set_style_shadow_width(row_btn, 0, 0);
      lv_obj_set_style_border_width(row_btn, 1, 0);
      lv_obj_set_style_border_color(row_btn, lv_color_hex(color), 0);
      lv_obj_set_style_pad_all(row_btn, 0, 0);
      // Farbindikator-Balken links
      lv_obj_t *bar = lv_obj_create(row_btn);
      lv_obj_set_size(bar, 6, 40);
      lv_obj_set_pos(bar, 8, 8);
      lv_obj_set_style_bg_color(bar, lv_color_hex(color), 0);
      lv_obj_set_style_border_width(bar, 0, 0);
      lv_obj_set_style_radius(bar, 3, 0);
      // Label
      lv_obj_t *lbl = lv_label_create(row_btn);
      lv_label_set_text(lbl, label);
      lv_obj_set_style_text_color(lbl, tc(TH_TEXT_BRIGHT), 0);
      lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
      lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 24, -8);
      // Untertitel
      lv_obj_t *slbl = lv_label_create(row_btn);
      { char ehbuf[32]; strncpy(ehbuf, T(STR_DRY_MAN_EDIT_HINT), sizeof(ehbuf)-1); lv_label_set_text(slbl, ehbuf); }
      lv_obj_set_style_text_color(slbl, tc(TH_TEXT_DIM), 0);
      lv_obj_set_style_text_font(slbl, &lv_font_montserrat_ext_12, 0);
      lv_obj_align(slbl, LV_ALIGN_LEFT_MID, 24, 10);
      // Wert rechts
      char vbuf[16]; snprintf(vbuf, sizeof(vbuf), "%d %s", value, T(STR_DRY_DAYS_UNIT));
      lv_obj_t *vlbl = lv_label_create(row_btn);
      lv_label_set_text(vlbl, vbuf);
      lv_obj_set_style_text_color(vlbl, lv_color_hex(color), 0);
      lv_obj_set_style_text_font(vlbl, &lv_font_montserrat_ext_20, 0);
      lv_obj_align(vlbl, LV_ALIGN_RIGHT_MID, -16, 0);
      lv_obj_set_user_data(row_btn, (void*)(intptr_t)target);
      lv_obj_add_event_cb(row_btn, [](lv_event_t *e){
        int tgt = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
        if (scr_drying_reminder) { lv_obj_del(scr_drying_reminder); scr_drying_reminder = nullptr; }
        buildDryNumpadScreen(tgt);
        lv_obj_clear_flag(s_dry_numpad_scr, LV_OBJ_FLAG_HIDDEN);
      }, LV_EVENT_CLICKED, NULL);
    };
    { char ybuf[16]; strncpy(ybuf, T(STR_DRY_MAN_YELLOW_LBL), sizeof(ybuf)-1); makeThreshRow(ybuf, g_dry_man_yellow, g_theme[TH_WARNING], content_y,      0); }
    { char rbuf[16]; strncpy(rbuf, T(STR_DRY_MAN_RED_LBL),    sizeof(rbuf)-1); makeThreshRow(rbuf, g_dry_man_red,    0xe04040, content_y + 68, 1); }

    // Info-Text
    lv_obj_t *info = lv_label_create(scr_drying_reminder);
    { char ibuf[64]; strncpy(ibuf, T(STR_DRY_MAN_INFO), sizeof(ibuf)-1); lv_label_set_text(info, ibuf); }
    lv_obj_set_style_text_color(info, tc(TH_TEXT_DIM), 0);
    lv_obj_set_style_text_font(info, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(info, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(info, 440);
    lv_obj_align(info, LV_ALIGN_BOTTOM_MID, 0, -4);
  }
}
