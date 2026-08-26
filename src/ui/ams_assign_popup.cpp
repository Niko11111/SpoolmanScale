#include "ams_assign_popup.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/ams_assign.h"
#include "services/http_progress.h"
#include "services/auto_weight_state.h"
#include "services/location_state.h"
#include "ui/more_info_screen.h"
#include "ui_common.h"

static lv_obj_t *scr_ams_popup = nullptr;
static lv_obj_t *lbl_ams_count = nullptr;

// Captured when the popup is built. The callbacks stay free of any lookup,
// they only raise a flag; the work happens one loop pass later.
static int  s_spool_id        = 0;
static bool s_confirm_pending = false;
static bool s_cancel_pending  = false;
static bool s_close_pending   = false;

static unsigned long s_opened_ms   = 0;
// What the blocking-time counter stood at when the popup opened. The wait for
// a whole inventory does not count against the ten seconds: the loop is not
// running then, so no button on this popup can be pressed. Without this the
// question regularly expired unanswered while a fetch was in flight, and the
// log recorded it as the user saying no.
static uint32_t      s_opened_stall = 0;
static int           s_last_shown_s = -1;

bool isAmsAssignPopupOpen() { return scr_ams_popup != nullptr; }

static void closeAmsAssignPopup() {
  if (scr_ams_popup) { lv_obj_del(scr_ams_popup); scr_ams_popup = nullptr; }
  lbl_ams_count = nullptr;
  s_last_shown_s = -1;
}

// Seconds still on the clock, never below zero. Measured as an elapsed
// difference rather than against an absolute deadline, so the millis()
// rollover after 49 days cannot make it expire on the spot.
static int remainingSeconds() {
  unsigned long elapsed = millis() - s_opened_ms;
  // Minus whatever of that time the loop spent inside a blocking backend call.
  // Guarded rather than trusted: the two are measured independently, and a
  // stall longer than the elapsed time would wrap the subtraction.
  const uint32_t stalled = httpStallTotalMs() - s_opened_stall;
  elapsed = (stalled >= elapsed) ? 0 : (elapsed - stalled);
  if (elapsed >= AMS_ASK_COUNTDOWN_MS) return 0;
  return (int)((AMS_ASK_COUNTDOWN_MS - elapsed + 999) / 1000);
}

static void updateCountdownLabel() {
  if (!lbl_ams_count) return;
  const int rem = remainingSeconds();
  if (rem == s_last_shown_s) return;
  s_last_shown_s = rem;
  char buf[48];
  snprintf(buf, sizeof(buf),
           T(g_ams_timer_yes ? STR_AMS_POPUP_STARTS_IN : STR_AMS_POPUP_CLOSES_IN), rem);
  lv_label_set_text(lbl_ams_count, buf);
}

void showAmsAssignPopup(int spool_id, float netto_g, const char* spool_name,
                        bool already_saved) {
  closeAmsAssignPopup();

  s_spool_id        = spool_id;
  s_confirm_pending = false;
  s_cancel_pending  = false;
  s_close_pending   = false;
  s_opened_ms       = millis();
  s_opened_stall    = httpStallTotalMs();

  scr_ams_popup = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_ams_popup, 480, 320);
  lv_obj_set_pos(scr_ams_popup, 0, 0);
  lv_obj_set_style_bg_color(scr_ams_popup, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_ams_popup, LV_OPA_70, 0);
  lv_obj_set_style_border_width(scr_ams_popup, 0, 0);
  lv_obj_set_style_radius(scr_ams_popup, 0, 0);
  lv_obj_set_style_pad_all(scr_ams_popup, 0, 0);  // no default padding
  lv_obj_clear_flag(scr_ams_popup, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(scr_ams_popup);
  lv_obj_set_size(box, 400, 236);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x2a4080), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // Which spool this is about. Without it the question is ambiguous the
  // moment two spools are handled in quick succession.
  lv_obj_t *lbl_spool = lv_label_create(box);
  { char sbuf[64];
    if (spool_name && spool_name[0]) {
      snprintf(sbuf, sizeof(sbuf), "%s  -  %.0f g", spool_name, netto_g);
    } else {
      snprintf(sbuf, sizeof(sbuf), "%.0f g", netto_g);
    }
    lv_label_set_text(lbl_spool, sbuf); }
  lv_obj_set_style_text_color(lbl_spool, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_spool, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_width(lbl_spool, 360);
  lv_label_set_long_mode(lbl_spool, LV_LABEL_LONG_DOT);
  lv_obj_set_style_text_align(lbl_spool, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_spool, LV_ALIGN_TOP_MID, 0, 16);

  lv_obj_t *lbl_q = lv_label_create(box);
  { char qbuf[64]; strncpy(qbuf, T(STR_AMS_POPUP_Q), sizeof(qbuf)-1);
    qbuf[sizeof(qbuf)-1] = '\0';
    lv_label_set_text(lbl_q, qbuf); }
  lv_obj_set_style_text_color(lbl_q, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl_q, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_width(lbl_q, 360);
  lv_label_set_long_mode(lbl_q, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(lbl_q, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_q, LV_ALIGN_TOP_MID, 0, 44);

  // What happens to the weight, which is not the same in both directions:
  // after a real weighing it is in FilaMan already and declining costs
  // nothing, while a spool that was only rested on the pad has not been
  // written at all and a yes is what writes it.
  lv_obj_t *lbl_saved = lv_label_create(box);
  { char vbuf[48];
    snprintf(vbuf, sizeof(vbuf),
             T(already_saved ? STR_AMS_POPUP_SAVED : STR_AMS_POPUP_WILL_SAVE),
             netto_g);
    lv_label_set_text(lbl_saved, vbuf); }
  lv_obj_set_style_text_color(lbl_saved, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_saved, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_saved, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(lbl_saved, 360);
  lv_label_set_long_mode(lbl_saved, LV_LABEL_LONG_WRAP);
  lv_obj_align(lbl_saved, LV_ALIGN_TOP_MID, 0, 80);

  // The countdown says out loud what happens on its own, so nobody is
  // surprised by an answer they did not give.
  lbl_ams_count = lv_label_create(box);
  lv_label_set_text(lbl_ams_count, "");
  lv_obj_set_style_text_color(lbl_ams_count, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_ams_count, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_ams_count, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_ams_count, LV_ALIGN_TOP_MID, 0, 106);
  updateCountdownLabel();

  lv_obj_t *btn_yes = lv_btn_create(box);
  lv_obj_set_size(btn_yes, 170, 56);
  lv_obj_set_pos(btn_yes, 12, 156);
  lv_obj_set_style_bg_color(btn_yes, lv_color_hex(0x1a4020), 0);
  lv_obj_set_style_bg_color(btn_yes, lv_color_hex(0x2a7030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_yes, 8, 0);
  lv_obj_set_style_shadow_width(btn_yes, 0, 0);
  lv_obj_add_event_cb(btn_yes, [](lv_event_t *e) {
    // No HTTP and no delete in here, both happen one loop pass later.
    s_confirm_pending = true;
    s_close_pending   = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_yes = lv_label_create(btn_yes);
  { char ybuf[24]; strncpy(ybuf, T(STR_AMS_BTN_YES), sizeof(ybuf)-1);
    ybuf[sizeof(ybuf)-1] = '\0'; lv_label_set_text(lbl_yes, ybuf); }
  lv_obj_set_style_text_color(lbl_yes, lv_color_hex(0x80ffa0), 0);
  lv_obj_set_style_text_font(lbl_yes, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_yes);

  lv_obj_t *btn_no = lv_btn_create(box);
  lv_obj_set_size(btn_no, 170, 56);
  lv_obj_set_pos(btn_no, 218, 156);
  lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x702020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_no, 8, 0);
  lv_obj_set_style_shadow_width(btn_no, 0, 0);
  lv_obj_add_event_cb(btn_no, [](lv_event_t *e) {
    s_cancel_pending = true;
    s_close_pending  = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_no = lv_label_create(btn_no);
  { char nbuf[24]; strncpy(nbuf, T(STR_AMS_TIMER_NO), sizeof(nbuf)-1);
    nbuf[sizeof(nbuf)-1] = '\0'; lv_label_set_text(lbl_no, nbuf); }
  lv_obj_set_style_text_color(lbl_no, lv_color_hex(0xffa0a0), 0);
  lv_obj_set_style_text_font(lbl_no, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_no);

  logSDf("AMS: asking for id=%d (%.0fg, %s), %lus, timeout means %s",
         spool_id, netto_g, already_saved ? "saved" : "not written yet",
         (unsigned long)(AMS_ASK_COUNTDOWN_MS / 1000),
         g_ams_timer_yes ? "yes" : "no");
}

// Offers the location question the AMS answer did not already settle.
static void offerLocationPicker(int spool_id) {
  if (!g_auto_loc_popup || !wifi_ok) return;
  if (!sm_found || sm_archived || sm_id != spool_id) return;
  if (g_loc_popup_shown_for_id == spool_id) return;
  g_loc_popup_shown_for_id = spool_id;
  requestLocationPicker(true);
}

void handleAmsAssignDeferredActions() {
  // Countdown first: while the popup stands it is the only thing moving.
  if (scr_ams_popup && !s_close_pending) {
    updateCountdownLabel();
    if (remainingSeconds() == 0) {
      if (g_ams_timer_yes) s_confirm_pending = true;
      else                 s_cancel_pending  = true;
      s_close_pending = true;
      logSDf("AMS: no answer for id=%d, counted down to %s",
             s_spool_id, g_ams_timer_yes ? "yes" : "no");
    }
  }

  if (!s_close_pending) return;
  s_close_pending = false;

  const int spool_id = s_spool_id;
  closeAmsAssignPopup();

  // A different spool may have landed on the pad while the question stood.
  // Reporting the parked measurement would then be right, but opening a
  // window for it would assign the wrong spool to the next tray.
  if (amsHasPending() && amsPendingSpoolId() != spool_id) {
    logSDf("AMS: answer discarded, parked spool changed from %d to %d",
           spool_id, amsPendingSpoolId());
    s_confirm_pending = false;
    s_cancel_pending  = false;
    return;
  }

  if (s_confirm_pending) {
    s_confirm_pending = false;
    s_cancel_pending  = false;
    // Three requests, roughly a second, with the popup already gone. Nothing
    // is written to the weight button here: it belongs to the auto weight
    // state machine, and on success the window countdown in appLoop picks the
    // status line up by itself.
    amsCommitWithWindow();
    // The spool is going into a printer, so where it sits on a shelf is not
    // a question worth asking. Latching the id keeps the debounced popup in
    // app_loop from firing for it later.
    g_loc_popup_shown_for_id = spool_id;
    return;
  }

  if (s_cancel_pending) {
    s_cancel_pending = false;
    // The weight was written when it was measured, so declining costs
    // nothing and touches nothing.
    amsDropPending();
    offerLocationPicker(spool_id);
  }
}
