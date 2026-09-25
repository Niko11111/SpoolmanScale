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
#include "ui/theme.h"

// The card's answer row, the whole width like the result's OK. The prompt
// starts a line below the spool's name, the seconds sit just above the row.
#define TAG2_BTN_W     (UI_POPUP_W - 2 * UI_CARD_ROW_X)
#define TAG2_PROMPT_Y  (UI_CARD_TEXT_Y + 24)
#define TAG2_COUNT_Y   (UI_CARD_ROW_Y - 22)

static lv_obj_t *scr_tag2      = nullptr;
static lv_obj_t *lbl_tag2_count = nullptr;
static lv_obj_t *bar_tag2_fill  = nullptr;
static lv_coord_t s_fill_w      = -1;   // the width last set, so a pass without a change draws nothing

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

static SecondTagState s_state = T2_IDLE;
static unsigned long  s_state_ms = 0;
static int  s_web_start_id = 0;
static bool s_web_cancel   = false;

static void setState(SecondTagState st) {
  s_state = st;
  s_state_ms = millis();
}

void secondTagLinked(bool ok) { setState(ok ? T2_OK : T2_FAILED); }
void secondTagWebStart(int spool_id) { if (spool_id > 0) s_web_start_id = spool_id; }
void secondTagWebCancel() { s_web_cancel = true; }

static void closeSecondTagPopup() {
  if (scr_tag2) { lv_obj_del(scr_tag2); scr_tag2 = nullptr; }
  lbl_tag2_count = nullptr;
  bar_tag2_fill  = nullptr;
  s_fill_w       = -1;
  s_last_shown_s = -1;
}

// Milliseconds still on the clock, never below zero. Measured as an elapsed
// difference rather than against an absolute deadline, so the millis()
// rollover after 49 days cannot make it expire on the spot.
static unsigned long remainingMs() {
  unsigned long elapsed = millis() - s_opened_ms;
  const uint32_t stalled = httpStallTotalMs() - s_opened_stall;
  // Guarded rather than trusted: the two are measured independently, and a
  // stall longer than the elapsed time would wrap the subtraction.
  elapsed = (stalled >= elapsed) ? 0 : (elapsed - stalled);
  if (elapsed >= SECOND_TAG_COUNTDOWN_MS) return 0;
  return SECOND_TAG_COUNTDOWN_MS - elapsed;
}

static int remainingSeconds() { return (int)((remainingMs() + 999) / 1000); }

SecondTagReport secondTagReport() {
  SecondTagReport r;
  r.state = s_state;
  r.spool_id = s_spool_id;
  r.seconds_left = scr_tag2 ? remainingSeconds() : 0;
  r.age_ms = millis() - s_state_ms;
  return r;
}

// The button's fill, to the pixel. At 376 px over 30 s that is a dozen
// small redraws a second, each only the strip that changed.
static void updateCountdownFill() {
  if (!bar_tag2_fill) return;
  const lv_coord_t w = (lv_coord_t)((uint64_t)TAG2_BTN_W * remainingMs()
                                    / SECOND_TAG_COUNTDOWN_MS);
  if (w == s_fill_w) return;
  s_fill_w = w;
  lv_obj_set_width(bar_tag2_fill, w);
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
  setState(T2_WAITING);

  scr_tag2 = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_tag2, LV_HOR_RES, LV_VER_RES);
  lv_obj_set_pos(scr_tag2, 0, 0);
  lv_obj_set_style_bg_color(scr_tag2, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(scr_tag2, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(scr_tag2, 0, 0);
  lv_obj_set_style_radius(scr_tag2, 0, 0);
  lv_obj_set_style_pad_all(scr_tag2, 0, 0);
  lv_obj_clear_flag(scr_tag2, LV_OBJ_FLAG_SCROLLABLE);

  // The card the link's result and the second tag's result stand on, so the
  // answer takes this question's place without anything moving.
  lv_obj_t *box = lv_obj_create(scr_tag2);
  lv_obj_set_size(box, UI_POPUP_W, UI_CARD_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // Turn the spool over: the two arrows say it before the title does.
  lv_obj_t *icon = lv_label_create(box);
  lv_label_set_text(icon, LV_SYMBOL_LOOP);
  lv_obj_set_style_text_color(icon, lv_color_hex(UI_COL_WARN), 0);
  lv_obj_set_style_text_font(icon, UI_FONT_ICON, 0);
  lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, UI_CARD_ICON_Y);

  lv_obj_t *lbl_title = lv_label_create(box);
  lv_label_set_text(lbl_title, T(STR_TAG2_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(lbl_title, UI_FONT_HEADLINE, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, UI_CARD_TITLE_Y);

  // Which spool this is about. Two links in quick succession are the normal
  // case at a shelf, and without the name the question is ambiguous.
  lv_obj_t *lbl_spool = lv_label_create(box);
  { char sbuf[64];
    if (sm_filament_name[0]) snprintf(sbuf, sizeof(sbuf), "%s  -  ID %d",
                                      sm_filament_name, spool_id);
    else                     snprintf(sbuf, sizeof(sbuf), "ID %d", spool_id);
    lv_label_set_text(lbl_spool, sbuf); }
  lv_obj_set_style_text_color(lbl_spool, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(lbl_spool, UI_FONT_BODY, 0);
  lv_obj_set_style_text_align(lbl_spool, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_spool, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_spool, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(lbl_spool, LV_ALIGN_TOP_MID, 0, UI_CARD_TEXT_Y);

  lv_obj_t *lbl_prompt = lv_label_create(box);
  lv_label_set_text(lbl_prompt, T(STR_TAG2_PROMPT));
  lv_obj_set_style_text_color(lbl_prompt, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(lbl_prompt, UI_FONT_BODY, 0);
  lv_obj_set_style_text_align(lbl_prompt, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_prompt, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_prompt, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(lbl_prompt, LV_ALIGN_TOP_MID, 0, TAG2_PROMPT_Y);

  // The seconds in words, quietly: the draining button below says the same
  // at a glance, this line says it to anyone who reads.
  lbl_tag2_count = lv_label_create(box);
  lv_label_set_text(lbl_tag2_count, "");
  lv_obj_set_style_text_color(lbl_tag2_count, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_style_text_font(lbl_tag2_count, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_align(lbl_tag2_count, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_tag2_count, LV_ALIGN_TOP_MID, 0, TAG2_COUNT_Y);
  updateCountdownLabel();

  // One button, because there is only one answer to give. The other answer is
  // a tag on the reader, and waiting is the third. The whole row, like the
  // result's OK that follows it, and neutral rather than green: nothing has
  // happened yet, time is only running out.
  lv_obj_t *btn_done = lv_btn_create(box);
  lv_obj_set_size(btn_done, TAG2_BTN_W, UI_POPUP_BTN_H);
  lv_obj_set_pos(btn_done, UI_CARD_ROW_X, UI_CARD_ROW_Y);
  lv_obj_set_style_bg_color(btn_done, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_bg_color(btn_done, lv_color_hex(UI_COL_POPUP_BORDER), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_done, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn_done, 0, 0);
  lv_obj_set_style_border_width(btn_done, 0, 0);
  lv_obj_set_style_pad_all(btn_done, 0, 0);
  lv_obj_clear_flag(btn_done, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(btn_done, [](lv_event_t *e) {
    // No HTTP and no delete in here, both happen one loop pass later.
    s_close_pending = true;
    setState(T2_CANCELLED);
  }, LV_EVENT_CLICKED, NULL);

  // The countdown as a lighter fill that drains from the right, behind the
  // label and not clickable. Not an lv_anim like the result's OK: the time a
  // blocking fetch holds the loop does not count against the question, and
  // an animation would run through it and then jump. The width is set from
  // the same remaining time the question closes on, every loop pass.
  bar_tag2_fill = lv_obj_create(btn_done);
  lv_obj_remove_style_all(bar_tag2_fill);
  lv_obj_set_size(bar_tag2_fill, TAG2_BTN_W, UI_POPUP_BTN_H);
  lv_obj_set_pos(bar_tag2_fill, 0, 0);
  lv_obj_set_style_bg_color(bar_tag2_fill, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_bg_opa(bar_tag2_fill, LV_OPA_COVER, 0);
  lv_obj_set_style_radius(bar_tag2_fill, UI_RADIUS_BTN, 0);
  lv_obj_clear_flag(bar_tag2_fill, LV_OBJ_FLAG_CLICKABLE);
  s_fill_w = TAG2_BTN_W;

  lv_obj_t *lbl_done = lv_label_create(btn_done);
  lv_label_set_text(lbl_done, T(STR_TAG2_BTN_DONE));
  lv_obj_set_style_text_color(lbl_done, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(lbl_done, UI_FONT_TITLE, 0);
  lv_obj_center(lbl_done);

  logSDf("TAG2: asking for a second tag on spool %d, first is '%s', %lus",
         spool_id, s_first_uid,
         (unsigned long)(SECOND_TAG_COUNTDOWN_MS / 1000));
}

void handleSecondTagDeferredActions() {
  // Asked for from the browser. The same question the scale asks after a
  // link, for the spool that is on it and the tag that is on the reader.
  if (s_web_start_id) {
    const int id = s_web_start_id;
    s_web_start_id = 0;
    if (!scr_tag2 && tag_present && sm_found && sm_id == id) {
      logSDf("TAG2: asked for from the browser, spool %d", id);
      showSecondTagPopup(id, g_tag.uid_str);
    } else if (!scr_tag2) {
      logSDf("TAG2: browser asked for spool %d, but the scale shows %d", id, sm_id);
      s_spool_id = id;
      setState(T2_FAILED);
    }
  }
  if (s_web_cancel) {
    s_web_cancel = false;
    if (scr_tag2 && !s_close_pending) {
      logSD("TAG2: cancelled from the browser");
      s_close_pending = true;
      setState(T2_CANCELLED);
    }
  }

  if (scr_tag2 && !s_close_pending) {
    updateCountdownLabel();
    updateCountdownFill();

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
      setState(T2_LINKING);
    } else if (remainingSeconds() == 0) {
      s_close_pending = true;
      setState(T2_EXPIRED);
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
    setState(T2_FAILED);
    return;
  }

  linkAdditionalTag(spool_id, s_second_uid);
}
