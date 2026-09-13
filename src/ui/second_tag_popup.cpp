#include "second_tag_popup.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/http_progress.h"
#include "services/tag_uid.h"
#include "ui/spool_flow.h"
#include "ui_common.h"

static lv_obj_t *scr_tag2      = nullptr;
static lv_obj_t *lbl_tag2_count = nullptr;

// Captured when the popup is built. The button callback only raises a flag;
// the link behind it costs HTTP requests and happens one loop pass later.
static int  s_spool_id    = 0;
static bool s_link_pending = false;
static bool s_close_pending = false;

// The tag that was just linked, normalised, and the one that turned up after
// it. Comparing normalised is what makes putting the same tag back a non
// event: the reader reports colons, the field may hold plain hex, and neither
// is a second chip.
static char s_first_uid[CARD_UIDS_MAX]  = "";
static char s_second_uid[CARD_UIDS_MAX] = "";

static unsigned long s_opened_ms    = 0;
// What the blocking-time counter stood at when the popup opened, same
// reasoning as in ams_assign_popup.cpp: a fetch that stalls the loop is time
// in which no tag can be read and no button can be pressed, so it must not
// count against the question.
static uint32_t      s_opened_stall = 0;
static int           s_last_shown_s = -1;

bool isSecondTagPopupOpen() { return scr_tag2 != nullptr; }

static void closeSecondTagPopup() {
  if (scr_tag2) { lv_obj_del(scr_tag2); scr_tag2 = nullptr; }
  lbl_tag2_count = nullptr;
  s_last_shown_s = -1;
}

// Seconds still on the clock, never below zero. Measured as an elapsed
// difference rather than against an absolute deadline, so the millis()
// rollover after 49 days cannot make it expire on the spot.
static int remainingSeconds() {
  unsigned long elapsed = millis() - s_opened_ms;
  const uint32_t stalled = httpStallTotalMs() - s_opened_stall;
  // Guarded rather than trusted: the two are measured independently, and a
  // stall longer than the elapsed time would wrap the subtraction.
  elapsed = (stalled >= elapsed) ? 0 : (elapsed - stalled);
  if (elapsed >= SECOND_TAG_COUNTDOWN_MS) return 0;
  return (int)((SECOND_TAG_COUNTDOWN_MS - elapsed + 999) / 1000);
}

static void updateCountdownLabel() {
  if (!lbl_tag2_count) return;
  const int rem = remainingSeconds();
  if (rem == s_last_shown_s) return;   // no repaint between seconds
  s_last_shown_s = rem;
  char buf[48];
  snprintf(buf, sizeof(buf), T(STR_TAG2_CLOSES_IN), rem);
  lv_label_set_text(lbl_tag2_count, buf);
}

void showSecondTagPopup(int spool_id, const char* first_uid) {
  closeSecondTagPopup();

  s_spool_id      = spool_id;
  s_link_pending  = false;
  s_close_pending = false;
  s_second_uid[0] = '\0';
  tagUidNormalize(first_uid, s_first_uid, sizeof(s_first_uid));
  s_opened_ms     = millis();
  s_opened_stall  = httpStallTotalMs();

  scr_tag2 = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_tag2, 480, 320);
  lv_obj_set_pos(scr_tag2, 0, 0);
  lv_obj_set_style_bg_color(scr_tag2, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_tag2, LV_OPA_70, 0);
  lv_obj_set_style_border_width(scr_tag2, 0, 0);
  lv_obj_set_style_radius(scr_tag2, 0, 0);
  lv_obj_set_style_pad_all(scr_tag2, 0, 0);
  lv_obj_clear_flag(scr_tag2, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(scr_tag2);
  lv_obj_set_size(box, 400, 236);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x2a4080), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_title = lv_label_create(box);
  { char tbuf[32]; copyT(tbuf, sizeof(tbuf), STR_TAG2_TITLE); lv_label_set_text(lbl_title, tbuf); }
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 14);

  // Which spool this is about. Two links in quick succession are the normal
  // case at a shelf, and without the name the question is ambiguous.
  lv_obj_t *lbl_spool = lv_label_create(box);
  { char sbuf[64];
    if (sm_filament_name[0]) snprintf(sbuf, sizeof(sbuf), "%s  -  ID %d",
                                      sm_filament_name, spool_id);
    else                     snprintf(sbuf, sizeof(sbuf), "ID %d", spool_id);
    lv_label_set_text(lbl_spool, sbuf); }
  lv_obj_set_style_text_color(lbl_spool, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_spool, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_width(lbl_spool, 360);
  lv_label_set_long_mode(lbl_spool, LV_LABEL_LONG_DOT);
  lv_obj_set_style_text_align(lbl_spool, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_spool, LV_ALIGN_TOP_MID, 0, 46);

  lv_obj_t *lbl_prompt = lv_label_create(box);
  { char pbuf[96]; copyT(pbuf, sizeof(pbuf), STR_TAG2_PROMPT); lv_label_set_text(lbl_prompt, pbuf); }
  lv_obj_set_style_text_color(lbl_prompt, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl_prompt, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_width(lbl_prompt, 360);
  lv_label_set_long_mode(lbl_prompt, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(lbl_prompt, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_prompt, LV_ALIGN_TOP_MID, 0, 74);

  // The countdown says out loud that this closes by itself, so a user who
  // does not want a second tag can simply walk away.
  lbl_tag2_count = lv_label_create(box);
  lv_label_set_text(lbl_tag2_count, "");
  lv_obj_set_style_text_color(lbl_tag2_count, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_tag2_count, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_tag2_count, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_tag2_count, LV_ALIGN_TOP_MID, 0, 132);
  updateCountdownLabel();

  // One button, because there is only one answer to give. The other answer is
  // a tag on the reader, and waiting is the third.
  lv_obj_t *btn_done = lv_btn_create(box);
  lv_obj_set_size(btn_done, 170, 56);
  lv_obj_set_pos(btn_done, (400 - 170) / 2, 160);
  lv_obj_set_style_bg_color(btn_done, lv_color_hex(0x1a2840), 0);
  lv_obj_set_style_bg_color(btn_done, lv_color_hex(0x2a4080), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_done, 8, 0);
  lv_obj_set_style_shadow_width(btn_done, 0, 0);
  lv_obj_add_event_cb(btn_done, [](lv_event_t *e) {
    // No HTTP and no delete in here, both happen one loop pass later.
    s_close_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_done = lv_label_create(btn_done);
  { char dbuf[24]; copyT(dbuf, sizeof(dbuf), STR_TAG2_BTN_DONE); lv_label_set_text(lbl_done, dbuf); }
  lv_obj_set_style_text_color(lbl_done, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl_done, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_done);

  logSDf("TAG2: asking for a second tag on spool %d, first is '%s', %lus",
         spool_id, s_first_uid,
         (unsigned long)(SECOND_TAG_COUNTDOWN_MS / 1000));
}

void handleSecondTagDeferredActions() {
  if (scr_tag2 && !s_close_pending) {
    updateCountdownLabel();

    // What the reader currently has. g_tag.uid_str is written by both scan
    // branches the moment a new UID turns up - the NTAG one directly, the
    // Bambu one inside scanTag() - so there is exactly one place to look.
    //
    // The lookup in app_loop is held off while this popup stands, which is
    // what keeps sm_id pointing at the spool that was just linked. Without
    // that, a second NTAG would come back "not in Spoolman" and take the
    // target of this question away with it.
    char now[CARD_UIDS_MAX];
    tagUidNormalize(g_tag.uid_str, now, sizeof(now));
    if (now[0] && strcmp(now, s_first_uid) != 0) {
      strncpy(s_second_uid, g_tag.uid_str, sizeof(s_second_uid) - 1);
      s_second_uid[sizeof(s_second_uid) - 1] = '\0';
      s_link_pending  = true;
      s_close_pending = true;
    } else if (remainingSeconds() == 0) {
      s_close_pending = true;
      logSDf("TAG2: no second tag for spool %d, question expired", s_spool_id);
    }
  }

  if (!s_close_pending) return;
  s_close_pending = false;

  const int spool_id = s_spool_id;
  closeSecondTagPopup();

  if (!s_link_pending) return;
  s_link_pending = false;

  // The spool has to still be the one the question was about. Nothing should
  // have moved sm_id while the lookup was held off, but this costs one
  // comparison and the alternative is binding a tag to whatever came after.
  if (sm_id != spool_id) {
    logSDf("TAG2: discarded, spool moved from %d to %d", spool_id, sm_id);
    return;
  }

  linkAdditionalTag(spool_id, s_second_uid);
}
