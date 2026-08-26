#include "confirm_popup.h"
#include <math.h>
#include "app/app_state.h"
#include "services/backend.h"
#include "services/backend_api.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "services/ams_assign.h"
#include "services/auto_weight_state.h"
#include "services/prefs_store.h"
#include "services/spoolman_actions.h"
#include "dried_action.h"
#include "app/deferred_actions.h"
#include "spoolman_screen.h"
#include "lang.h"


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


// The weight the scope buttons below will store. Normally whatever is on the
// pad, but a brand new spool can derive it instead -- see the New spool button.
static float s_tare_prompt_g = 0.0f;
static float s_cap_measured  = 0.0f;
// What the reactivate button says it will write. Settled while the popup is
// built and reused in the callback, so the number the user read is the number
// that lands - re-measuring on the click would quietly write something else.
static float s_reactivate_g   = 0.0f;
static bool  s_tare_then_new = false;

// After a tare is stored from the New spool flow the initial weight follows
// from it: what is left of the reading once the spool itself is taken off.
// Done here rather than in the caller so the two writes stay in the order that
// makes the second one correct.
static void tareFollowUp() {
  if (!s_tare_then_new) return;
  s_tare_then_new = false;
  // The tare was derived as reading minus nominal, so what is left of the
  // reading once the spool comes off is the nominal weight itself. Reading
  // scale_weight_g again here would use a value that has moved on since the
  // popup opened - the pad drifts, someone leans on the bench - and leave the
  // tare and the initial weight contradicting each other, which is the exact
  // thing deriving the tare is meant to prevent.
  patchInitialWeight(sm_total);
}

// Whether New spool has to derive the tare from this reading because nothing
// else is known, and what it would store.
//
// Only when no tare exists at any level. The two numbers in the reading are
// the spool and the filament, and exactly one of them can be measured
// independently: the spool. Its weight is a property of the spool MODEL and
// barely varies between spools of the same kind, while what a manufacturer
// actually winds onto an individual spool varies by a couple of percent. So a
// tare that exists - measured here, or inherited from the filament or the
// brand - is the more trustworthy of the two, and the filament weight is what
// gets measured against it.
//
// Deriving on top of a known tare would do the opposite: it folds this one
// spool's fill tolerance into a tare that other spools inherit, where a few
// grams of error stop being local and start applying to every spool of that
// filament or that brand.
//
// This is the only moment a tare can be had at all without emptying the spool
// first, which is why it stays for the case where there is nothing.
//
// Asked in two places - the button label and its handler - so that the label
// can never promise a different number than the press writes.
static bool newSpoolDerivesTare(float* out_tare) {
  if (sm_tare_source != TARE_NONE) return false;
  const float derived = scale_weight_g - sm_total;
  const bool plausible = (sm_total > 0.0f) &&
                         (derived >= NEW_SPOOL_TARE_MIN_G) &&
                         (derived <= NEW_SPOOL_TARE_MAX_G);
  if (!plausible) return false;
  if (out_tare) *out_tare = derived;
  return true;
}

static void showSpoolWeightPopup(float grams, bool then_new_spool) {
  s_tare_prompt_g = grams;
  s_tare_then_new = then_new_spool;

      // Sub-popup: where should the spool weight be written?
      const float w = s_tare_prompt_g;
      // Not every backend has all three places to put it. BamBuddy has no
      // filament and no vendor object at all, and behind its Spoolman proxy
      // even the spool's own core weight is discarded on write. Buttons for
      // those are not built rather than built and left to fail.
      const bool scope_spool  = backendCanTareSpool();
      const bool scope_shared = backendCanTareFilamentOrVendor();

      lv_obj_t *popup = lv_obj_create(lv_scr_act());
      lv_obj_set_size(popup, 480, 320);
      lv_obj_set_pos(popup, 0, 0);
      lv_obj_set_style_bg_color(popup, lv_color_hex(0x0a1020), 0);
      lv_obj_set_style_bg_opa(popup, LV_OPA_COVER, 0);
      lv_obj_set_style_border_width(popup, 0, 0);
      lv_obj_set_style_pad_all(popup, 0, 0);
      lv_obj_clear_flag(popup, LV_OBJ_FLAG_SCROLLABLE);

      // Title
      lv_obj_t *title = lv_label_create(popup);
      char title_buf[48];
      snprintf(title_buf, sizeof(title_buf), T(STR_SPOOL_WEIGHT_TITLE), w);
      lv_label_set_text(title, title_buf);
      lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
      lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_14, 0);
      lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

      // Rows are placed one after another so a missing scope leaves no hole.
      int row_y = 36;

      // Button 1: this spool
      lv_obj_t *b1 = lv_btn_create(popup);
      lv_obj_set_size(b1, 460, 60); lv_obj_set_pos(b1, 10, row_y);
      if (!scope_spool) lv_obj_add_flag(b1, LV_OBJ_FLAG_HIDDEN);
      else row_y += 70;
      lv_obj_set_style_bg_color(b1, lv_color_hex(0x0a2040), 0);
      lv_obj_set_style_radius(b1, 8, 0); lv_obj_set_style_shadow_width(b1, 0, 0);
      { lv_obj_t *l = lv_label_create(b1);
        lv_label_set_text(l, T(backendIsFilaMan() ? STR_BTN_THIS_SPOOL_FM
                                                  : STR_BTN_THIS_SPOOL));
        lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
        lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_center(l); }
      lv_obj_add_event_cb(b1, [](lv_event_t *e) {
        patchSpoolWeight(s_tare_prompt_g); tareFollowUp();
        lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
      }, LV_EVENT_CLICKED, NULL);

      // Button 2: this filament
      lv_obj_t *b2 = lv_btn_create(popup);
      lv_obj_set_size(b2, 460, 60); lv_obj_set_pos(b2, 10, row_y);
      if (!scope_shared) lv_obj_add_flag(b2, LV_OBJ_FLAG_HIDDEN);
      else row_y += 70;
      lv_obj_set_style_bg_color(b2, lv_color_hex(0x0a2820), 0);
      lv_obj_set_style_radius(b2, 8, 0); lv_obj_set_style_shadow_width(b2, 0, 0);
      { lv_obj_t *l = lv_label_create(b2);
        lv_label_set_text(l, T(backendIsFilaMan() ? STR_BTN_THIS_FILAMENT_FM
                                                  : STR_BTN_THIS_FILAMENT));
        lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
        lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_center(l); }
      lv_obj_add_event_cb(b2, [](lv_event_t *e) {
        patchFilamentSpoolWeight(s_tare_prompt_g); tareFollowUp();
        lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
      }, LV_EVENT_CLICKED, NULL);

      // Button 3: vendor
      lv_obj_t *b3 = lv_btn_create(popup);
      lv_obj_set_size(b3, 460, 60); lv_obj_set_pos(b3, 10, row_y);
      if (!scope_shared) lv_obj_add_flag(b3, LV_OBJ_FLAG_HIDDEN);
      else row_y += 70;
      lv_obj_set_style_bg_color(b3, lv_color_hex(0x281a00), 0);
      lv_obj_set_style_radius(b3, 8, 0); lv_obj_set_style_shadow_width(b3, 0, 0);
      { lv_obj_t *l = lv_label_create(b3);
        // Spoolman's vendor is FilaMan's manufacturer, and the bracketed field
        // names below the title only hold for Spoolman - see the lang.cpp entries.
        lv_label_set_text(l, T(backendIsFilaMan() ? STR_BTN_THIS_VENDOR_FM
                                                  : STR_BTN_THIS_VENDOR));
        lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
        lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_center(l); }
      lv_obj_add_event_cb(b3, [](lv_event_t *e) {
        patchVendorSpoolWeight(s_tare_prompt_g); tareFollowUp();
        lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
      }, LV_EVENT_CLICKED, NULL);

      // Button 4: cancel, right under whatever was built above
      lv_obj_t *b4 = lv_btn_create(popup);
      lv_obj_set_size(b4, 460, 40); lv_obj_set_pos(b4, 10, row_y + 10);
      lv_obj_set_style_bg_color(b4, lv_color_hex(0x3a1010), 0);
      lv_obj_set_style_radius(b4, 8, 0); lv_obj_set_style_shadow_width(b4, 0, 0);
      { lv_obj_t *l = lv_label_create(b4);
        lv_label_set_text(l, T(STR_CANCEL));
        lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_14, 0);
        lv_obj_center(l); }
      lv_obj_add_event_cb(b4, [](lv_event_t *e) {
        s_tare_then_new = false;
        lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
      }, LV_EVENT_CLICKED, NULL);

      // A bag on the pad is counted into the reading, and this number may be
      // written to an entire brand. The device cannot tell whether one is
      // there, so it says so rather than silently subtracting a weight that
      // might not be on the scale at all.
      if (bag_weight_g > 0.0f) {
        lv_obj_t *bag_hint = lv_label_create(popup);
        char bag_buf[64];
        snprintf(bag_buf, sizeof(bag_buf), T(STR_SPOOL_WEIGHT_BAG_HINT), bag_weight_g);
        lv_label_set_text(bag_hint, bag_buf);
        lv_obj_set_style_text_color(bag_hint, lv_color_hex(0xf0b838), 0);
        lv_obj_set_style_text_font(bag_hint, &lv_font_montserrat_ext_12, 0);
        lv_obj_align(bag_hint, LV_ALIGN_TOP_MID, 0, 300);
      }

    }

void showConfirmPopup(const char* msg, int action) {
  closeConfirmPopup();
  confirm_action = action;

  confirm_popup = lv_obj_create(lv_scr_act());
  lv_obj_set_size(confirm_popup, 480, 320);
  lv_obj_set_pos(confirm_popup, 0, 0);
  lv_obj_set_style_bg_color(confirm_popup, lv_color_hex(0x000000), 0);
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
  lv_obj_set_style_text_color(lbl_q, lv_color_hex(0xc8d8f0), 0);
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

    // True when at least one tare scope reaches the database. Decides both
    // whether the button below exists and how wide its neighbour is.
    const bool tare_writable = backendCanTareSpool() || backendCanTareFilamentOrVendor();

    const int BW2 = (BOX_W - 2*EDGE - PAD) / 2;
    const int XL  = EDGE;
    const int XR  = EDGE + BW2 + PAD;

    float netto_plain = scale_weight_g - (float)sm_spool_weight;
    // Settled here, with the same arithmetic the weight buttons use, so the
    // reactivate button below can name the number it will write.
    s_reactivate_g = (netto_plain < 0) ? 0.0f : netto_plain;
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
      // Remembered so the question can come up on removal. A yes there
      // reports the same weight once more, which is the only way to open the
      // window. The cap check above cannot interfere: it is BamBuddy only and
      // amsAskActive() requires FilaMan.
      if (amsAskActive()) amsNoteMeasurement(sm_id, r, scale_weight_g, true);
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
      // Gross without the bag: that is what the scale would have shown had
      // the spool been weighed bare, and it is what FilaMan has to be told.
      if (amsAskActive()) amsNoteMeasurement(sm_id, r, scale_weight_g - bag_weight_g, true);
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
      float derived = 0.0f;
      if (newSpoolDerivesTare(&derived)) {
        showSpoolWeightPopup(derived, true);   // stores the tare, then the initial
        return;
      }
      float initial = scale_weight_g - (float)sm_spool_weight;
      if (initial < 0) initial = 0;
      patchInitialWeight(initial);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l3 = lv_label_create(btn3);
    char buf3[56];
    // Name the weight the button will really write. Where the tare is derived
    // that is the nominal filament weight, not the reading minus a tare that
    // is about to be replaced - and those two differ by the whole spool.
    const bool derives_tare = newSpoolDerivesTare(nullptr);
    float new_spool_shown = derives_tare ? sm_total : netto_plain;
    snprintf(buf3, sizeof(buf3), T(STR_BTN_NEW_SPOOL_VAL), new_spool_shown);
    // An inherited tare carries into the filament weight measured against it,
    // so the button says where it came from - same wording as the spool
    // details, so the two read as one statement rather than two.
    const char *tare_note = "";
    if (!derives_tare && sm_tare_source == TARE_FILAMENT) tare_note = T(STR_TARE_FROM_FILAMENT);
    else if (!derives_tare && sm_tare_source == TARE_VENDOR) tare_note = T(STR_TARE_FROM_BRAND);
    if (tare_note[0]) {
      const size_t used = strlen(buf3);
      snprintf(buf3 + used, sizeof(buf3) - used, "%s", tare_note);
    }
    lv_label_set_text(l3, buf3);
    lv_obj_set_style_text_color(l3, lv_color_hex(0x80c8ff), 0);
    lv_obj_set_style_text_font(l3, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(l3, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l3);

    // ── Row 2 right: empty spool + core ──
    // Dropped entirely where no tare scope can be written - which is the case
    // for BamBuddy behind Spoolman. The place stays empty on purpose rather
    // than letting the neighbour grow into it: a button that changes width
    // depending on the backend reads as a different button.
    if (tare_writable) {
    lv_obj_t *btn4 = lv_btn_create(box);
    lv_obj_set_size(btn4, BW2, H_ROW2);
    lv_obj_set_pos(btn4, XR, Y2);
    lv_obj_set_style_bg_color(btn4, lv_color_hex(0x1a2a40), 0);
    lv_obj_set_style_bg_color(btn4, lv_color_hex(0x2a4060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn4, 8, 0);
    lv_obj_set_style_shadow_width(btn4, 0, 0);
    lv_obj_add_event_cb(btn4, [](lv_event_t *e) {
      closeConfirmPopup();
      showSpoolWeightPopup(scale_weight_g, false);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l4 = lv_label_create(btn4);
    char buf4[56];
    snprintf(buf4, sizeof(buf4), T(STR_BTN_EMPTY_SPOOL), scale_weight_g);
    lv_label_set_text(l4, buf4);
    lv_obj_set_style_text_color(l4, lv_color_hex(0x80c0ff), 0);
    lv_obj_set_style_text_font(l4, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(l4, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l4);
    }

    // ── Row 3 links: Auto-Speichern Toggle ──
    // AN->AUS: sofort deaktivieren + Popup schliessen
    // AUS->AN: aktivieren + Popup schliessen, Hintergrund laeuft ab jetzt
    lv_obj_t *btn5 = lv_btn_create(box);
    lv_obj_set_size(btn5, BW2, H_ROW3);
    lv_obj_set_pos(btn5, XL, Y3);
    lv_obj_set_style_bg_color(btn5, g_auto_weight ? lv_color_hex(0x1a3020) : lv_color_hex(0x101820), 0);
    lv_obj_set_style_bg_color(btn5, g_auto_weight ? lv_color_hex(0x2a5030) : lv_color_hex(0x1a2a38), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(btn5, 1, 0);
    lv_obj_set_style_border_color(btn5, g_auto_weight ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a2840), 0);
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
          lv_obj_set_style_text_color(lbl_weight_main_lbl, lv_color_hex(0x40c080), 0);
        }
        closeConfirmPopup();
      } else {
        // Aktivieren: zweites Bestaetigungs-Popup zeigen
        // Gewichts-Popup verstecken (nicht loeschen — cancel bringt es zurueck)
        if (confirm_popup) lv_obj_add_flag(confirm_popup, LV_OBJ_FLAG_HIDDEN);

        lv_obj_t *apop = lv_obj_create(lv_scr_act());
        lv_obj_set_size(apop, 480, 320);
        lv_obj_set_pos(apop, 0, 0);
        lv_obj_set_style_bg_color(apop, lv_color_hex(0x000000), 0);
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

        // The same circular arrow the button carries, on its own line so it
        // reads as the mark of this setting rather than as part of the
        // sentence. Both sizes below are already linked elsewhere, so the
        // larger type costs no flash.
        lv_obj_t *aicon = lv_label_create(abox);
        lv_label_set_text(aicon, LV_SYMBOL_REFRESH);
        lv_obj_set_style_text_color(aicon, lv_color_hex(0x28d49a), 0);
        lv_obj_set_style_text_font(aicon, &lv_font_montserrat_ext_24, 0);
        lv_obj_align(aicon, LV_ALIGN_TOP_MID, 0, 12);

        // Titel
        lv_obj_t *atitle = lv_label_create(abox);
        char atbuf[48]; strncpy(atbuf, T(STR_AUTO_WEIGHT_TITLE), sizeof(atbuf)-1); atbuf[sizeof(atbuf)-1] = '\0';
        lv_label_set_text(atitle, atbuf);
        lv_obj_set_style_text_color(atitle, lv_color_hex(0x28d49a), 0);
        lv_obj_set_style_text_font(atitle, &lv_font_montserrat_ext_20, 0);
        lv_obj_set_style_text_align(atitle, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_width(atitle, 444);
        lv_obj_set_pos(atitle, 8, 44);

        // Info-Text. Both languages carry three hard line breaks, so the block
        // below is 3 lines at 14 px and ends well clear of the buttons at 156.
        lv_obj_t *ainfo = lv_label_create(abox);
        char aibuf[160]; strncpy(aibuf, T(STR_AUTO_WEIGHT_INFO), sizeof(aibuf)-1); aibuf[sizeof(aibuf)-1] = '\0';
        lv_label_set_text(ainfo, aibuf);
        lv_obj_set_style_text_color(ainfo, lv_color_hex(0xc8d8f0), 0);
        lv_obj_set_style_text_font(ainfo, &lv_font_montserrat_ext_14, 0);
        lv_obj_set_style_text_align(ainfo, LV_TEXT_ALIGN_CENTER, 0);
        lv_label_set_long_mode(ainfo, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(ainfo, 444);
        lv_obj_set_pos(ainfo, 8, 78);

        // Bestaetigen-Button
        lv_obj_t *abtn_ok = lv_btn_create(abox);
        lv_obj_set_size(abtn_ok, 222, 52);
        lv_obj_set_pos(abtn_ok, 8, 156);
        lv_obj_set_style_bg_color(abtn_ok, lv_color_hex(0x1a3020), 0);
        lv_obj_set_style_bg_color(abtn_ok, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
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
            lv_obj_set_style_text_color(lbl_weight_main_lbl, lv_color_hex(0x28d49a), 0);
          }
          lv_obj_del(apop);         // zweites Popup weg
          closeConfirmPopup();      // erstes Popup weg
        }, LV_EVENT_CLICKED, NULL);
        lv_obj_t *abtn_ok_lbl = lv_label_create(abtn_ok);
        char acbuf[32]; strncpy(acbuf, T(STR_CONFIRM), sizeof(acbuf)-1); acbuf[sizeof(acbuf)-1] = '\0';
        lv_label_set_text(abtn_ok_lbl, acbuf);
        lv_obj_set_style_text_color(abtn_ok_lbl, lv_color_hex(0x40c080), 0);
        lv_obj_set_style_text_font(abtn_ok_lbl, &lv_font_montserrat_ext_14, 0);
        lv_obj_align(abtn_ok_lbl, LV_ALIGN_CENTER, 0, 0);

        // Abbrechen-Button
        lv_obj_t *abtn_cancel = lv_btn_create(abox);
        lv_obj_set_size(abtn_cancel, 222, 52);
        lv_obj_set_pos(abtn_cancel, 238, 156);
        lv_obj_set_style_bg_color(abtn_cancel, lv_color_hex(0x3a1010), 0);
        lv_obj_set_style_bg_color(abtn_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
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
        lv_obj_set_style_text_color(abtn_cancel_lbl, lv_color_hex(0xff8080), 0);
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
    lv_obj_set_style_text_color(lbl_auto_weight_btn, g_auto_weight ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
    // 16 rather than 14: this row carries the one setting in the popup that is
    // not about the spool in hand, and at 14 it read as a footnote. The row is
    // 219 px wide, which the longer German wording still fits at this size.
    //
    // The circular arrow names the feature rather than the action, the way the
    // drop names the drying date. Enabled or disabled is already said twice
    // over, by the wording and by the colour, and a play/stop pair said it a
    // third time while leaving nothing to recognise the row by.
    lv_obj_set_style_text_font(lbl_auto_weight_btn, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl_auto_weight_btn, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(lbl_auto_weight_btn);

    // ── Row 3 right: empty / archive, or its opposite ──
    //
    // On an archived spool this is the way back. Same place, because it is the
    // same decision seen from the other side, and there is no room for a fifth
    // button anyway. Green rather than orange: archiving takes a spool out of
    // circulation, this puts it back.
    lv_obj_t *btn6 = lv_btn_create(box);
    lv_obj_set_size(btn6, BW2, H_ROW3);
    lv_obj_set_pos(btn6, XR, Y3);
    lv_obj_set_style_bg_color(btn6, lv_color_hex(sm_archived ? 0x0a3020 : 0x3a1a00), 0);
    lv_obj_set_style_bg_color(btn6, lv_color_hex(sm_archived ? 0x156040 : 0x6a3000),
                              LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn6, 8, 0);
    lv_obj_set_style_shadow_width(btn6, 0, 0);
    lv_obj_add_event_cb(btn6, [](lv_event_t *e) {
      closeConfirmPopup();
      if (sm_archived) {
        // No confirmation step: the button already named the number it writes,
        // and the action is undoable by archiving again. Deferred like every
        // other network call reached from a callback.
        reactivate_weight_g = s_reactivate_g;
        reactivate_pending  = true;
        return;
      }
      // Separate confirmation popup for archiving
      showConfirmPopup(T(STR_ARCHIVE_CONFIRM), 3);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l6 = lv_label_create(btn6);
    if (sm_archived) {
      // The subtitle carries the weight this will write, so the button says
      // what it does. Formatted here rather than in the table because the
      // number only exists once the spool is on the pad.
      char rb[64];
      snprintf(rb, sizeof(rb), T(STR_BTN_REACTIVATE), s_reactivate_g);
      lv_label_set_text(l6, rb);
    } else {
      // "remaining=0" is Spoolman's field name. FilaMan archives through a
      // status endpoint and calls the field something else, so it says the same
      // thing in words there.
      lv_label_set_text(l6, T(backendIsFilaMan() ? STR_BTN_ARCHIVE_EMPTY_FM
                                                 : STR_BTN_ARCHIVE_EMPTY));
    }
    lv_obj_set_style_text_color(l6, lv_color_hex(sm_archived ? 0x28d49a : 0xffb060), 0);
    lv_obj_set_style_text_font(l6, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(l6, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l6);

    // ── Row 4: cancel (full width) ──
    const int BW_FULL = BOX_W - 2*EDGE;
    lv_obj_t *btn7 = lv_btn_create(box);
    lv_obj_set_size(btn7, BW_FULL, H_ROW4);
    lv_obj_set_pos(btn7, XL, Y4);
    lv_obj_set_style_bg_color(btn7, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn7, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn7, 8, 0);
    lv_obj_set_style_shadow_width(btn7, 0, 0);
    lv_obj_add_event_cb(btn7, [](lv_event_t *e){ closeConfirmPopup(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l7 = lv_label_create(btn7);
    lv_label_set_text(l7, T(STR_CANCEL));
    lv_obj_set_style_text_color(l7, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l7, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l7, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l7);

  } else {
    // Standard popup: an icon, the question, yes / no.
    //
    // The icon names the consequence before the sentence is read, and the
    // three that land here are different enough to deserve their own: a drop
    // for drying, a bin for archiving, a warning for throwing an address
    // away. The drop is the same one the BamBuddy options screen already uses
    // for the drying date.
    //
    // Height follows the text. Two short lines at 20 px need far less room
    // than the address warning, which is a full paragraph and stays at 16 px
    // so it does not run into the buttons.
    const char*      icon     = LV_SYMBOL_WARNING;
    uint32_t         icon_col = 0xf0b838;
    const lv_font_t* q_font   = &lv_font_montserrat_ext_20;
    int              box_h    = 210;
    if (action == 1) {                       // dried today
      icon = LV_SYMBOL_TINT;  icon_col = 0x5ad1ff;
    } else if (action == 3) {                // archive spool
      icon = LV_SYMBOL_TRASH; icon_col = 0xffb060;
    } else {                                 // long text, e.g. discard address
      q_font = &lv_font_montserrat_ext_16;
      box_h  = 250;
    }
    const int BOX_W = 400;
    const int BTN_H = 56;
    const int BTN_Y = box_h - BTN_H - 18;

    lv_obj_set_size(box, BOX_W, box_h);
    lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_pad_all(box, 0, 0);

    lv_obj_t *lbl_icon = lv_label_create(box);
    lv_label_set_text(lbl_icon, icon);
    lv_obj_set_style_text_color(lbl_icon, lv_color_hex(icon_col), 0);
    // 24 rather than something larger on purpose: it is the biggest size the
    // firmware already links. Pulling in a font for one glyph cost 74 kB of
    // flash when this was first written at 32.
    lv_obj_set_style_text_font(lbl_icon, &lv_font_montserrat_ext_24, 0);
    lv_obj_align(lbl_icon, LV_ALIGN_TOP_MID, 0, 14);

    lv_obj_set_style_text_font(lbl_q, q_font, 0);
    lv_obj_set_width(lbl_q, BOX_W - 40);
    lv_obj_align(lbl_q, LV_ALIGN_TOP_MID, 0, 62);

    lv_obj_t *btn_ja = lv_btn_create(box);
    lv_obj_set_size(btn_ja, 170, BTN_H);
    lv_obj_set_pos(btn_ja, 12, BTN_Y);
    lv_obj_set_style_bg_color(btn_ja, lv_color_hex(0x1a4020), 0);
    lv_obj_set_style_bg_color(btn_ja, lv_color_hex(0x2a7030), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_ja, 8, 0);
    lv_obj_set_style_shadow_width(btn_ja, 0, 0);
    lv_obj_add_event_cb(btn_ja, [](lv_event_t *e) {
      int act = confirm_action;
      closeConfirmPopup();
      if (act == 1) btn_dried_cb(nullptr);
      if (act == 3) patchArchiveSpool();
      if (act == 4) spoolmanClearHost();
      // 5 = downgrade confirmed on the OTA screen. Only the flag here; the
      // download runs from appLoop().
      if (act == 5) gh_downgrade_pending = true;
      // 6 = reset the calibration. The flag again: it writes NVS and rebuilds
      // the screen this button was opened from.
      if (act == 6) cal_reset_pending = true;
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_ja = lv_label_create(btn_ja);
    lv_label_set_text(lbl_ja, T(STR_BTN_CONFIRMED));
    lv_obj_set_style_text_font(lbl_ja, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_color(lbl_ja, lv_color_hex(0x80ffb0), 0);
    lv_obj_center(lbl_ja);

    lv_obj_t *btn_nein = lv_btn_create(box);
    lv_obj_set_size(btn_nein, 170, BTN_H);
    lv_obj_set_pos(btn_nein, 218, BTN_Y);
    lv_obj_set_style_bg_color(btn_nein, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_nein, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_nein, 8, 0);
    lv_obj_set_style_shadow_width(btn_nein, 0, 0);
    lv_obj_add_event_cb(btn_nein, [](lv_event_t *e){ closeConfirmPopup(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_nein = lv_label_create(btn_nein);
    lv_label_set_text(lbl_nein, T(STR_CANCEL));
    lv_obj_set_style_text_font(lbl_nein, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_color(lbl_nein, lv_color_hex(0xff8080), 0);
    lv_obj_center(lbl_nein);
  }
}

// ============================================================
//  BAMBUDDY: MEASUREMENT ABOVE THE LABEL WEIGHT
//
//  BamBuddy's built-in inventory keeps the consumed grams and derives the
//  rest, so a spool holding more than its label says cannot be stored - the
//  remainder clamps back to full. Raising the label is the only way to keep
//  the number, and that changes a field the user owns, so it is asked.
// ============================================================
void showBamBuddyCapPopup(float measured_g, float label_g) {
  lv_obj_t *popup = lv_obj_create(lv_scr_act());
  lv_obj_set_size(popup, 480, 320);
  lv_obj_set_pos(popup, 0, 0);
  lv_obj_set_style_bg_color(popup, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(popup, 0, 0);
  lv_obj_set_style_radius(popup, 0, 0);
  lv_obj_set_style_pad_all(popup, 0, 0);
  lv_obj_clear_flag(popup, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *title = lv_label_create(popup);
  char title_buf[40];
  strncpy(title_buf, T(STR_BB_CAP_TITLE), sizeof(title_buf) - 1);
  title_buf[sizeof(title_buf) - 1] = '\0';
  lv_label_set_text(title, title_buf);
  lv_obj_set_style_text_color(title, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 14);

  lv_obj_t *body = lv_label_create(popup);
  char body_buf[240];
  snprintf(body_buf, sizeof(body_buf), T(STR_BB_CAP_BODY), measured_g, label_g);
  lv_label_set_text(body, body_buf);
  lv_obj_set_style_text_color(body, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(body, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(body, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(body, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(body, 440);
  lv_obj_align(body, LV_ALIGN_TOP_MID, 0, 52);

  // Remembered for the two handlers, which cannot capture anything.
  s_cap_measured = measured_g;

  lv_obj_t *b_raise = lv_btn_create(popup);
  lv_obj_set_size(b_raise, 440, 56); lv_obj_set_pos(b_raise, 20, 150);
  lv_obj_set_style_bg_color(b_raise, lv_color_hex(0x14402e), 0);
  lv_obj_set_style_radius(b_raise, 8, 0);
  lv_obj_set_style_shadow_width(b_raise, 0, 0);
  { lv_obj_t *l = lv_label_create(b_raise);
    char buf[48];
    snprintf(buf, sizeof(buf), T(STR_BB_CAP_RAISE), measured_g);
    lv_label_set_text(l, buf);
    lv_obj_set_style_text_color(l, lv_color_hex(0x40c080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(l); }
  lv_obj_add_event_cb(b_raise, [](lv_event_t *e) {
    const float g = s_cap_measured;
    lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
    // Order matters: the label first, so the weight that follows has room.
    // patchInitialWeight writes label and consumption together, which already
    // leaves the spool at full - the weight write after it is what stamps
    // last_weighed_at and last_scale_weight.
    patchInitialWeight(g);
    patchSpoolmanWeight(g, true);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *b_keep = lv_btn_create(popup);
  lv_obj_set_size(b_keep, 440, 48); lv_obj_set_pos(b_keep, 20, 216);
  lv_obj_set_style_bg_color(b_keep, lv_color_hex(0x1a2a40), 0);
  lv_obj_set_style_radius(b_keep, 8, 0);
  lv_obj_set_style_shadow_width(b_keep, 0, 0);
  { lv_obj_t *l = lv_label_create(b_keep);
    char buf[40];
    strncpy(buf, T(STR_BB_CAP_KEEP), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    lv_label_set_text(l, buf);
    lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(l); }
  lv_obj_add_event_cb(b_keep, [](lv_event_t *e) {
    const float g = s_cap_measured;
    lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
    // Written anyway, so the scale and the server agree that a weighing
    // happened. BamBuddy clamps it, which is what the user just accepted.
    patchSpoolmanWeight(g, true);
  }, LV_EVENT_CLICKED, NULL);
}
