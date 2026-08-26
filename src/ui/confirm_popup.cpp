#include "confirm_popup.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "services/auto_weight_state.h"
#include "services/prefs_store.h"
#include "services/spoolman_actions.h"
#include "dried_action.h"
#include "lang.h"
#include "theme.h"


static lv_obj_t *confirm_popup = nullptr;
static int confirm_action = 0;
static lv_obj_t *lbl_auto_weight_btn = nullptr;

bool isConfirmPopupOpen() {
  return confirm_popup != nullptr;
}

void closeConfirmPopup() {
  if (confirm_popup) { lv_obj_del(confirm_popup); confirm_popup = nullptr; }
  confirm_action = 0;
  lbl_auto_weight_btn = nullptr;  // Pointer ungültig nach lv_obj_del
}

void showConfirmPopup(const char* msg, int action) {
  closeConfirmPopup();
  confirm_action = action;

  confirm_popup = lv_obj_create(lv_scr_act());
  lv_obj_set_size(confirm_popup, 480, 320);
  lv_obj_set_pos(confirm_popup, 0, 0);
  lv_obj_set_style_bg_color(confirm_popup, tc(TH_BLACK), 0);
  lv_obj_set_style_bg_opa(confirm_popup, LV_OPA_70, 0);
  lv_obj_set_style_border_width(confirm_popup, 0, 0);
  lv_obj_set_style_radius(confirm_popup, 0, 0);
  lv_obj_set_style_pad_all(confirm_popup, 0, 0);  // KRITISCH: kein Default-Padding!
  lv_obj_clear_flag(confirm_popup, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(confirm_popup);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x2a4080), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_q = lv_label_create(box);
  lv_label_set_text(lbl_q, msg);
  lv_obj_set_style_text_color(lbl_q, tc(TH_TEXT), 0);
  lv_obj_set_style_text_font(lbl_q, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_q, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_q, LV_LABEL_LONG_WRAP);

  if (action == 2) {
    // Layout: 4 Zeilen — Row1=66, Row2=52, Row3=52, Row4=42
    // BOX_H = 8+28+6+66+6+52+6+52+6+42+8 = 280px (original)
    const int BOX_W  = 460;
    const int H_ROW1 = 66;
    const int H_ROW2 = 52;
    const int H_ROW3 = 52;
    const int H_ROW4 = 42;
    const int PAD    = 6;
    const int EDGE   = 8;
    const int HDR_H  = 28;
    const int BOX_H  = EDGE + HDR_H + PAD + H_ROW1 + PAD + H_ROW2 + PAD + H_ROW3 + PAD + H_ROW4 + EDGE;

    lv_obj_set_size(box, BOX_W, BOX_H);
    lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_pad_all(box, 0, 0);

    lv_obj_set_width(lbl_q, BOX_W - 2*EDGE);
    lv_obj_set_pos(lbl_q, EDGE, 6);
    lv_obj_set_style_text_font(lbl_q, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(lbl_q, LV_TEXT_ALIGN_CENTER, 0);

    const int Y1 = EDGE + HDR_H + PAD;
    const int Y2 = Y1 + H_ROW1 + PAD;
    const int Y3 = Y2 + H_ROW2 + PAD;
    const int Y4 = Y3 + H_ROW3 + PAD;

    const int BW2 = (BOX_W - 2*EDGE - PAD) / 2;
    const int XL  = EDGE;
    const int XR  = EDGE + BW2 + PAD;

    float netto_plain = scale_weight_g - (float)sm_spool_weight;
    float netto_bag   = netto_plain - bag_weight_g;
    if (netto_plain < 0) netto_plain = 0;
    if (netto_bag   < 0) netto_bag   = 0;

    // ── Zeile 1 Links: Ohne Beutel ──
    lv_obj_t *btn1 = lv_btn_create(box);
    lv_obj_set_size(btn1, BW2, H_ROW1);
    lv_obj_set_pos(btn1, XL, Y1);
    lv_obj_set_style_bg_color(btn1, lv_color_hex(0x1a4020), 0);
    lv_obj_set_style_bg_color(btn1, lv_color_hex(0x2a7030), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn1, 8, 0);
    lv_obj_set_style_shadow_width(btn1, 0, 0);
    lv_obj_add_event_cb(btn1, [](lv_event_t *e) {
      closeConfirmPopup();
      float r = scale_weight_g - (float)sm_spool_weight;
      if (r < 0) r = 0;
      patchSpoolmanWeight(r);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l1 = lv_label_create(btn1);
    char buf1[48];
    snprintf(buf1, sizeof(buf1), T(STR_BTN_NO_BAG_VAL), netto_plain);
    lv_label_set_text(l1, buf1);
    lv_obj_set_style_text_color(l1, lv_color_hex(0x80ffb0), 0);
    lv_obj_set_style_text_font(l1, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l1, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l1);

    // ── Zeile 1 Rechts: Mit Beutel ──
    lv_obj_t *btn2 = lv_btn_create(box);
    lv_obj_set_size(btn2, BW2, H_ROW1);
    lv_obj_set_pos(btn2, XR, Y1);
    lv_obj_set_style_bg_color(btn2, lv_color_hex(0x1a3a20), 0);
    lv_obj_set_style_bg_color(btn2, lv_color_hex(0x2a6030), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn2, 8, 0);
    lv_obj_set_style_shadow_width(btn2, 0, 0);
    lv_obj_add_event_cb(btn2, [](lv_event_t *e) {
      closeConfirmPopup();
      float r = scale_weight_g - (float)sm_spool_weight - bag_weight_g;
      if (r < 0) r = 0;
      patchSpoolmanWeight(r);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l2 = lv_label_create(btn2);
    char buf2[56];
    snprintf(buf2, sizeof(buf2), T(STR_BTN_WITH_BAG_VAL), netto_plain, bag_weight_g);
    lv_label_set_text(l2, buf2);
    lv_obj_set_style_text_color(l2, lv_color_hex(0x80ffb0), 0);
    lv_obj_set_style_text_font(l2, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l2, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l2);

    // ── Zeile 2 Links: Neue Spule ──
    lv_obj_t *btn3 = lv_btn_create(box);
    lv_obj_set_size(btn3, BW2, H_ROW2);
    lv_obj_set_pos(btn3, XL, Y2);
    lv_obj_set_style_bg_color(btn3, lv_color_hex(0x102040), 0);
    lv_obj_set_style_bg_color(btn3, lv_color_hex(0x1a3870), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn3, 8, 0);
    lv_obj_set_style_shadow_width(btn3, 0, 0);
    lv_obj_add_event_cb(btn3, [](lv_event_t *e) {
      closeConfirmPopup();
      float initial = scale_weight_g - (float)sm_spool_weight;
      if (initial < 0) initial = 0;
      patchInitialWeight(initial);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l3 = lv_label_create(btn3);
    char buf3[56];
    snprintf(buf3, sizeof(buf3), T(STR_BTN_NEW_SPOOL_VAL), netto_plain);
    lv_label_set_text(l3, buf3);
    lv_obj_set_style_text_color(l3, lv_color_hex(0x80c8ff), 0);
    lv_obj_set_style_text_font(l3, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(l3, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l3);

    // ── Row 2 right: empty spool + core ──
    lv_obj_t *btn4 = lv_btn_create(box);
    lv_obj_set_size(btn4, BW2, H_ROW2);
    lv_obj_set_pos(btn4, XR, Y2);
    lv_obj_set_style_bg_color(btn4, lv_color_hex(0x1a2a40), 0);
    lv_obj_set_style_bg_color(btn4, tc(TH_TEXT_DIM), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn4, 8, 0);
    lv_obj_set_style_shadow_width(btn4, 0, 0);
    lv_obj_add_event_cb(btn4, [](lv_event_t *e) {
      closeConfirmPopup();
      // Sub-popup: where should the spool weight be written?
      float w = scale_weight_g;

      lv_obj_t *popup = lv_obj_create(lv_scr_act());
      lv_obj_set_size(popup, 480, 320);
      lv_obj_set_pos(popup, 0, 0);
      lv_obj_set_style_bg_color(popup, tc(TH_BG), 0);
      lv_obj_set_style_bg_opa(popup, LV_OPA_COVER, 0);
      lv_obj_set_style_border_width(popup, 0, 0);
      lv_obj_set_style_pad_all(popup, 0, 0);
      lv_obj_clear_flag(popup, LV_OBJ_FLAG_SCROLLABLE);

      // Title
      lv_obj_t *title = lv_label_create(popup);
      char title_buf[48];
      snprintf(title_buf, sizeof(title_buf), T(STR_SPOOL_WEIGHT_TITLE), w);
      lv_label_set_text(title, title_buf);
      lv_obj_set_style_text_color(title, tc(TH_ACCENT), 0);
      lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_14, 0);
      lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

      // Button 1: this spool
      lv_obj_t *b1 = lv_btn_create(popup);
      lv_obj_set_size(b1, 460, 60); lv_obj_set_pos(b1, 10, 36);
      lv_obj_set_style_bg_color(b1, lv_color_hex(0x0a2040), 0);
      lv_obj_set_style_radius(b1, 8, 0); lv_obj_set_style_shadow_width(b1, 0, 0);
      { lv_obj_t *l = lv_label_create(b1);
        lv_label_set_text(l, T(STR_BTN_THIS_SPOOL));
        lv_obj_set_style_text_color(l, tc(TH_TEXT), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
        lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_center(l); }
      lv_obj_add_event_cb(b1, [](lv_event_t *e) {
        patchSpoolWeight(scale_weight_g);
        lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
      }, LV_EVENT_CLICKED, NULL);

      // Button 2: this filament
      lv_obj_t *b2 = lv_btn_create(popup);
      lv_obj_set_size(b2, 460, 60); lv_obj_set_pos(b2, 10, 106);
      lv_obj_set_style_bg_color(b2, lv_color_hex(0x0a2820), 0);
      lv_obj_set_style_radius(b2, 8, 0); lv_obj_set_style_shadow_width(b2, 0, 0);
      { lv_obj_t *l = lv_label_create(b2);
        lv_label_set_text(l, T(STR_BTN_THIS_FILAMENT));
        lv_obj_set_style_text_color(l, tc(TH_TEXT), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
        lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_center(l); }
      lv_obj_add_event_cb(b2, [](lv_event_t *e) {
        patchFilamentSpoolWeight(scale_weight_g);
        lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
      }, LV_EVENT_CLICKED, NULL);

      // Button 3: vendor
      lv_obj_t *b3 = lv_btn_create(popup);
      lv_obj_set_size(b3, 460, 60); lv_obj_set_pos(b3, 10, 176);
      lv_obj_set_style_bg_color(b3, lv_color_hex(0x281a00), 0);
      lv_obj_set_style_radius(b3, 8, 0); lv_obj_set_style_shadow_width(b3, 0, 0);
      { lv_obj_t *l = lv_label_create(b3);
        lv_label_set_text(l, T(STR_BTN_THIS_VENDOR));
        lv_obj_set_style_text_color(l, tc(TH_TEXT), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
        lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_center(l); }
      lv_obj_add_event_cb(b3, [](lv_event_t *e) {
        patchVendorSpoolWeight(scale_weight_g);
        lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
      }, LV_EVENT_CLICKED, NULL);

      // Button 4: cancel
      lv_obj_t *b4 = lv_btn_create(popup);
      lv_obj_set_size(b4, 460, 40); lv_obj_set_pos(b4, 10, 256);
      lv_obj_set_style_bg_color(b4, tc(TH_DANGER_BG), 0);
      lv_obj_set_style_radius(b4, 8, 0); lv_obj_set_style_shadow_width(b4, 0, 0);
      { lv_obj_t *l = lv_label_create(b4);
        lv_label_set_text(l, T(STR_CANCEL));
        lv_obj_set_style_text_color(l, tc(TH_DANGER_TEXT), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_14, 0);
        lv_obj_center(l); }
      lv_obj_add_event_cb(b4, [](lv_event_t *e) {
        lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
      }, LV_EVENT_CLICKED, NULL);

    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l4 = lv_label_create(btn4);
    char buf4[56];
    snprintf(buf4, sizeof(buf4), T(STR_BTN_EMPTY_SPOOL), scale_weight_g);
    lv_label_set_text(l4, buf4);
    lv_obj_set_style_text_color(l4, lv_color_hex(0x80c0ff), 0);
    lv_obj_set_style_text_font(l4, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(l4, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l4);

    // ── Row 3 links: Auto-Speichern Toggle ──
    // AN->AUS: sofort deaktivieren + Popup schliessen
    // AUS->AN: aktivieren + Popup schliessen, Hintergrund laeuft ab jetzt
    lv_obj_t *btn5 = lv_btn_create(box);
    lv_obj_set_size(btn5, BW2, H_ROW3);
    lv_obj_set_pos(btn5, XL, Y3);
    lv_obj_set_style_bg_color(btn5, g_auto_weight ? tc(TH_OK_BG) : lv_color_hex(0x101820), 0);
    lv_obj_set_style_bg_color(btn5, g_auto_weight ? tc(TH_SUCCESS_BG) : lv_color_hex(0x1a2a38), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(btn5, 1, 0);
    lv_obj_set_style_border_color(btn5, g_auto_weight ? tc(TH_ACCENT) : tc(TH_SURFACE_3), 0);
    lv_obj_set_style_radius(btn5, 8, 0);
    lv_obj_set_style_shadow_width(btn5, 0, 0);
    lv_obj_add_event_cb(btn5, [](lv_event_t *e) {
      if (g_auto_weight) {
        // Deaktivieren: sofort, kein zweites Popup
        g_auto_weight = false;
        auto_weight_stable_ms = 0;
        auto_weight_last_val = -9999.0f;
        // Was written to the "spool" namespace while loadPrefs() reads from
        // "spoolscale", so the setting silently reverted on every reboot.
        prefsPutBool("auto_weight", false);
        logSD("Auto-Weight: deaktiviert");
        if (lbl_weight_main_lbl) {
          char wmbuf[40];
          strncpy(wmbuf, T(STR_BTN_WEIGHT), sizeof(wmbuf)-1); wmbuf[sizeof(wmbuf)-1] = '\0';
          lv_label_set_text(lbl_weight_main_lbl, wmbuf);
          lv_obj_set_style_text_color(lbl_weight_main_lbl, tc(TH_SUCCESS_TEXT), 0);
        }
        closeConfirmPopup();
      } else {
        // Aktivieren: zweites Bestaetigungs-Popup zeigen
        // Gewichts-Popup verstecken (nicht loeschen — cancel bringt es zurueck)
        if (confirm_popup) lv_obj_add_flag(confirm_popup, LV_OBJ_FLAG_HIDDEN);

        lv_obj_t *apop = lv_obj_create(lv_scr_act());
        lv_obj_set_size(apop, 480, 320);
        lv_obj_set_pos(apop, 0, 0);
        lv_obj_set_style_bg_color(apop, tc(TH_BLACK), 0);
        lv_obj_set_style_bg_opa(apop, LV_OPA_70, 0);
        lv_obj_set_style_border_width(apop, 0, 0);
        lv_obj_set_style_radius(apop, 0, 0);
        lv_obj_set_style_pad_all(apop, 0, 0);
        lv_obj_clear_flag(apop, LV_OBJ_FLAG_SCROLLABLE);

        lv_obj_t *abox = lv_obj_create(apop);
        lv_obj_set_size(abox, 460, 220);
        lv_obj_align(abox, LV_ALIGN_CENTER, 0, 0);
        lv_obj_set_style_bg_color(abox, lv_color_hex(0x0c1828), 0);
        lv_obj_set_style_border_color(abox, lv_color_hex(0x2a4080), 0);
        lv_obj_set_style_border_width(abox, 2, 0);
        lv_obj_set_style_radius(abox, 12, 0);
        lv_obj_set_style_pad_all(abox, 0, 0);
        lv_obj_clear_flag(abox, LV_OBJ_FLAG_SCROLLABLE);

        // Titel
        lv_obj_t *atitle = lv_label_create(abox);
        char atbuf[48]; strncpy(atbuf, T(STR_AUTO_WEIGHT_TITLE), sizeof(atbuf)-1); atbuf[sizeof(atbuf)-1] = '\0';
        lv_label_set_text(atitle, atbuf);
        lv_obj_set_style_text_color(atitle, tc(TH_ACCENT), 0);
        lv_obj_set_style_text_font(atitle, &lv_font_montserrat_ext_16, 0);
        lv_obj_set_style_text_align(atitle, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_width(atitle, 444);
        lv_obj_set_pos(atitle, 8, 10);

        // Info-Text
        lv_obj_t *ainfo = lv_label_create(abox);
        char aibuf[160]; strncpy(aibuf, T(STR_AUTO_WEIGHT_INFO), sizeof(aibuf)-1); aibuf[sizeof(aibuf)-1] = '\0';
        lv_label_set_text(ainfo, aibuf);
        lv_obj_set_style_text_color(ainfo, tc(TH_TEXT), 0);
        lv_obj_set_style_text_font(ainfo, &lv_font_montserrat_ext_14, 0);
        lv_obj_set_style_text_align(ainfo, LV_TEXT_ALIGN_CENTER, 0);
        lv_label_set_long_mode(ainfo, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(ainfo, 444);
        lv_obj_set_pos(ainfo, 8, 38);

        // Bestaetigen-Button
        lv_obj_t *abtn_ok = lv_btn_create(abox);
        lv_obj_set_size(abtn_ok, 222, 52);
        lv_obj_set_pos(abtn_ok, 8, 156);
        lv_obj_set_style_bg_color(abtn_ok, tc(TH_OK_BG), 0);
        lv_obj_set_style_bg_color(abtn_ok, tc(TH_SUCCESS_BG), LV_STATE_PRESSED);
        lv_obj_set_style_radius(abtn_ok, 8, 0);
        lv_obj_set_style_shadow_width(abtn_ok, 0, 0);
        lv_obj_add_event_cb(abtn_ok, [](lv_event_t *e) {
          lv_obj_t *apop = lv_obj_get_parent(lv_obj_get_parent(lv_event_get_target(e)));
          // Aktivieren
          g_auto_weight = true;
          auto_weight_stable_ms = 0;
          auto_weight_last_val = -9999.0f;
          prefsPutBool("auto_weight", true);
          logSD("Auto-Weight: aktiviert");
          if (lbl_weight_main_lbl) {
            char wmbuf[48];
            snprintf(wmbuf, sizeof(wmbuf), "%s (A)", T(STR_BTN_WEIGHT));
            lv_label_set_text(lbl_weight_main_lbl, wmbuf);
            lv_obj_set_style_text_color(lbl_weight_main_lbl, tc(TH_ACCENT), 0);
          }
          lv_obj_del(apop);         // zweites Popup weg
          closeConfirmPopup();      // erstes Popup weg
        }, LV_EVENT_CLICKED, NULL);
        lv_obj_t *abtn_ok_lbl = lv_label_create(abtn_ok);
        char acbuf[32]; strncpy(acbuf, T(STR_CONFIRM), sizeof(acbuf)-1); acbuf[sizeof(acbuf)-1] = '\0';
        lv_label_set_text(abtn_ok_lbl, acbuf);
        lv_obj_set_style_text_color(abtn_ok_lbl, tc(TH_SUCCESS_TEXT), 0);
        lv_obj_set_style_text_font(abtn_ok_lbl, &lv_font_montserrat_ext_14, 0);
        lv_obj_align(abtn_ok_lbl, LV_ALIGN_CENTER, 0, 0);

        // Abbrechen-Button
        lv_obj_t *abtn_cancel = lv_btn_create(abox);
        lv_obj_set_size(abtn_cancel, 222, 52);
        lv_obj_set_pos(abtn_cancel, 238, 156);
        lv_obj_set_style_bg_color(abtn_cancel, tc(TH_DANGER_BG), 0);
        lv_obj_set_style_bg_color(abtn_cancel, tc(TH_DANGER_PRESSED), LV_STATE_PRESSED);
        lv_obj_set_style_radius(abtn_cancel, 8, 0);
        lv_obj_set_style_shadow_width(abtn_cancel, 0, 0);
        lv_obj_add_event_cb(abtn_cancel, [](lv_event_t *e) {
          lv_obj_t *apop = lv_obj_get_parent(lv_obj_get_parent(lv_event_get_target(e)));
          lv_obj_del(apop);
          // Erstes Popup wieder einblenden
          if (confirm_popup) lv_obj_clear_flag(confirm_popup, LV_OBJ_FLAG_HIDDEN);
        }, LV_EVENT_CLICKED, NULL);
        lv_obj_t *abtn_cancel_lbl = lv_label_create(abtn_cancel);
        char acancelbuf[32]; strncpy(acancelbuf, T(STR_CANCEL), sizeof(acancelbuf)-1); acancelbuf[sizeof(acancelbuf)-1] = '\0';
        lv_label_set_text(abtn_cancel_lbl, acancelbuf);
        lv_obj_set_style_text_color(abtn_cancel_lbl, tc(TH_DANGER_TEXT), 0);
        lv_obj_set_style_text_font(abtn_cancel_lbl, &lv_font_montserrat_ext_14, 0);
        lv_obj_align(abtn_cancel_lbl, LV_ALIGN_CENTER, 0, 0);
      }
    }, LV_EVENT_CLICKED, NULL);
    lbl_auto_weight_btn = lv_label_create(btn5);
    {
      char abuf[48];
      strncpy(abuf, g_auto_weight ? T(STR_AUTO_WEIGHT_DISABLE) : T(STR_AUTO_WEIGHT_ENABLE), sizeof(abuf)-1);
      abuf[sizeof(abuf)-1] = '\0';
      lv_label_set_text(lbl_auto_weight_btn, abuf);
    }
    lv_obj_set_style_text_color(lbl_auto_weight_btn, g_auto_weight ? tc(TH_ACCENT) : tc(TH_TEXT_MUTED), 0);
    lv_obj_set_style_text_font(lbl_auto_weight_btn, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(lbl_auto_weight_btn, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(lbl_auto_weight_btn);

    // ── Row 3 right: empty / archive ──
    lv_obj_t *btn6 = lv_btn_create(box);
    lv_obj_set_size(btn6, BW2, H_ROW3);
    lv_obj_set_pos(btn6, XR, Y3);
    lv_obj_set_style_bg_color(btn6, lv_color_hex(0x3a1a00), 0);
    lv_obj_set_style_bg_color(btn6, lv_color_hex(0x6a3000), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn6, 8, 0);
    lv_obj_set_style_shadow_width(btn6, 0, 0);
    lv_obj_add_event_cb(btn6, [](lv_event_t *e) {
      closeConfirmPopup();
      // Separate confirmation popup for archiving
      showConfirmPopup(T(STR_ARCHIVE_CONFIRM), 3);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l6 = lv_label_create(btn6);
    lv_label_set_text(l6, T(STR_BTN_ARCHIVE_EMPTY));
    lv_obj_set_style_text_color(l6, lv_color_hex(0xffb060), 0);
    lv_obj_set_style_text_font(l6, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(l6, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l6);

    // ── Row 4: cancel (full width) ──
    const int BW_FULL = BOX_W - 2*EDGE;
    lv_obj_t *btn7 = lv_btn_create(box);
    lv_obj_set_size(btn7, BW_FULL, H_ROW4);
    lv_obj_set_pos(btn7, XL, Y4);
    lv_obj_set_style_bg_color(btn7, tc(TH_DANGER_BG), 0);
    lv_obj_set_style_bg_color(btn7, tc(TH_DANGER_PRESSED), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn7, 8, 0);
    lv_obj_set_style_shadow_width(btn7, 0, 0);
    lv_obj_add_event_cb(btn7, [](lv_event_t *e){ closeConfirmPopup(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l7 = lv_label_create(btn7);
    lv_label_set_text(l7, T(STR_CANCEL));
    lv_obj_set_style_text_color(l7, tc(TH_DANGER_TEXT), 0);
    lv_obj_set_style_text_font(l7, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l7, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l7);

  } else {
    // Standard popup (dried): yes / no
    lv_obj_set_size(box, 400, 200);
    lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_pad_all(box, 0, 0);
    lv_obj_set_width(lbl_q, 360);
    lv_obj_align(lbl_q, LV_ALIGN_TOP_MID, 0, 20);

    lv_obj_t *btn_ja = lv_btn_create(box);
    lv_obj_set_size(btn_ja, 170, 56);
    lv_obj_set_pos(btn_ja, 12, 122);
    lv_obj_set_style_bg_color(btn_ja, lv_color_hex(0x1a4020), 0);
    lv_obj_set_style_bg_color(btn_ja, lv_color_hex(0x2a7030), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_ja, 8, 0);
    lv_obj_set_style_shadow_width(btn_ja, 0, 0);
    lv_obj_add_event_cb(btn_ja, [](lv_event_t *e) {
      int act = confirm_action;
      closeConfirmPopup();
      if (act == 1) btn_dried_cb(nullptr);
      if (act == 3) patchArchiveSpool();
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_ja = lv_label_create(btn_ja);
    lv_label_set_text(lbl_ja, T(STR_BTN_CONFIRMED));
    lv_obj_set_style_text_font(lbl_ja, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_color(lbl_ja, lv_color_hex(0x80ffb0), 0);
    lv_obj_center(lbl_ja);

    lv_obj_t *btn_nein = lv_btn_create(box);
    lv_obj_set_size(btn_nein, 170, 56);
    lv_obj_set_pos(btn_nein, 218, 122);
    lv_obj_set_style_bg_color(btn_nein, tc(TH_DANGER_BG), 0);
    lv_obj_set_style_bg_color(btn_nein, tc(TH_DANGER_PRESSED), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_nein, 8, 0);
    lv_obj_set_style_shadow_width(btn_nein, 0, 0);
    lv_obj_add_event_cb(btn_nein, [](lv_event_t *e){ closeConfirmPopup(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_nein = lv_label_create(btn_nein);
    lv_label_set_text(lbl_nein, T(STR_CANCEL));
    lv_obj_set_style_text_font(lbl_nein, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_color(lbl_nein, tc(TH_DANGER_TEXT), 0);
    lv_obj_center(lbl_nein);
  }
}
