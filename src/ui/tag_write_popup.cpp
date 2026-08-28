#include "tag_write_popup.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/tag_write.h"
#include "services/user_options.h"
#include "confirm_popup.h"
#include "info_popup.h"
#include "spool_flow.h"
#include "ui_common.h"

// The house measurements for a two button question, same as confirm_popup.cpp:
// buttons 170 wide with 12 px gutters on a 400 px box, and 18 px of air below
// them.
#define BOX_W  400
#define BOX_H  236
#define BTN_W  170
#define BTN_H  56
#define BTN_Y  (BOX_H - BTN_H - 18)

// Which of the two questions is on screen. They differ in their words and in
// what confirming does, in nothing else - one builder serves both.
enum AskMode : uint8_t { ASK_WRITE, ASK_ERASE, ASK_REWRITE };

static lv_obj_t *scr_tag_write = nullptr;
static bool     close_pending   = false;
static bool     confirm_pending = false;
static bool     erase_ask_pending = false;
static bool     mismatch_ask_pending = false;
static int      s_spool_id      = 0;
static AskMode  s_mode          = ASK_WRITE;
// What the tag held when the unlink asked. Taken then and not later, because
// clearTagDisplay() runs immediately afterwards and sets tag_present false and
// g_tag.uid_str empty - by the next loop pass refreshCache() has wiped the
// cache, and the question about a tag that is still lying there would never be
// asked at all.
static char     s_erase_fmt[12] = "";

// Both sides of a mismatch, laid out over two lines. Built while the spool is
// still in hand, because the question is shown a pass later.
static char     s_mismatch_detail[96] = "";

// Set while a write is on its way, so the result is picked up once.
static bool s_watching = false;

bool isTagWritePopupOpen() { return scr_tag_write != nullptr; }

void requestTagEraseAsk() {
  s_erase_fmt[0] = 0;
  // Only worth asking when there is something to erase. An unlink from the
  // more info screen usually happens with no tag anywhere near the reader, and
  // a tag that carries nothing has nothing to lose.
  if (!tagIsWritableNtag() || !tagCachedHasRecord()) return;
  snprintf(s_erase_fmt, sizeof(s_erase_fmt), "%s", tagCachedInfo()->fmt);
  erase_ask_pending = true;
}

// A modal, not the status line. lbl_status is repainted by the NFC poll from
// app_loop.cpp:984 onward, which runs after the deferred handlers in the same
// pass - a result put there was overwritten before anyone could read it, and
// a refused write looked like nothing had happened at all.
static void showResult(uint8_t code) {
  const bool ok = (code == TW_OK);
  const uint8_t tone = ok ? INFO_DONE : INFO_WARN;
  if (s_mode == ASK_ERASE)
    showInfoPopup(ok ? STR_TW_ERASED : STR_TW_ERASE_FAILED,
                  ok ? STR_TW_ERASED_INFO : tagWriteResultString(code), tone);
  else
    showInfoPopup(ok ? STR_TW_OK : STR_TW_FAILED,
                  ok ? STR_TW_OK_INFO : tagWriteResultString(code), tone);
}

// Title, consequence, and the two answers. Everything else is fixed.
static void buildAsk(StringID title, StringID hint, StringID yes, StringID no) {
  scr_tag_write = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_tag_write, 480, 320);
  lv_obj_set_pos(scr_tag_write, 0, 0);
  lv_obj_set_style_bg_color(scr_tag_write, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_tag_write, LV_OPA_70, 0);
  lv_obj_set_style_border_width(scr_tag_write, 0, 0);
  lv_obj_set_style_radius(scr_tag_write, 0, 0);
  lv_obj_set_style_pad_all(scr_tag_write, 0, 0);
  lv_obj_clear_flag(scr_tag_write, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(scr_tag_write);
  lv_obj_set_size(box, BOX_W, BOX_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x2a4080), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *icon = lv_label_create(box);
  lv_label_set_text(icon, LV_SYMBOL_WARNING);
  lv_obj_set_style_text_color(icon, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(icon, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, 14);

  lv_obj_t *lbl_q = lv_label_create(box);
  { char qb[48]; strncpy(qb, T(title), sizeof(qb) - 1);
    qb[sizeof(qb) - 1] = '\0'; lv_label_set_text(lbl_q, qb); }
  lv_obj_set_style_text_color(lbl_q, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl_q, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(lbl_q, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_q, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_q, BOX_W - 40);
  lv_obj_align(lbl_q, LV_ALIGN_TOP_MID, 0, 52);

  // The format belongs in the sentence. "The tag is written" says nothing about
  // what a reader will make of it afterwards, and for the erase it is the only
  // thing that says what is about to be lost.
  lv_obj_t *lbl_hint = lv_label_create(box);
  { char hb[192];
    // The erase says what is about to be lost, the write says what is about
    // to be put there - and that is now a setting, not a constant.
    // The rewrite has neither to say: its hint is the comparison itself.
    const char *arg = (s_mode == ASK_ERASE)   ? s_erase_fmt
                    : (s_mode == ASK_REWRITE) ? s_mismatch_detail
                                              : tagFormatLabel(g_tagwrite_fmt);
    snprintf(hb, sizeof(hb), T(hint), arg[0] ? arg : "OpenSpool");
    lv_label_set_text(lbl_hint, hb); }
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint, BOX_W - 40);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 96);

  lv_obj_t *btn_ok = lv_btn_create(box);
  lv_obj_set_size(btn_ok, BTN_W, BTN_H);
  lv_obj_set_pos(btn_ok, 12, BTN_Y);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x1a4020), 0);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x2a7030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok, 8, 0);
  lv_obj_set_style_shadow_width(btn_ok, 0, 0);
  lv_obj_add_event_cb(btn_ok, [](lv_event_t *e) {
    // Flags only. The NFC work takes as long as it takes and must not run
    // inside the callback, and the overlay cannot delete itself here.
    confirm_pending = true;
    close_pending   = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ok = lv_label_create(btn_ok);
  { char bb[32]; strncpy(bb, T(yes), sizeof(bb) - 1);
    bb[sizeof(bb) - 1] = '\0'; lv_label_set_text(lbl_ok, bb); }
  lv_obj_set_style_text_color(lbl_ok, lv_color_hex(0x80ffb0), 0);
  lv_obj_set_style_text_font(lbl_ok, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_ok);

  lv_obj_t *btn_no = lv_btn_create(box);
  lv_obj_set_size(btn_no, BTN_W, BTN_H);
  lv_obj_set_pos(btn_no, BOX_W - BTN_W - 12, BTN_Y);
  lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_no, 8, 0);
  lv_obj_set_style_shadow_width(btn_no, 0, 0);
  lv_obj_add_event_cb(btn_no, [](lv_event_t *e) {
    close_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_no = lv_label_create(btn_no);
  { char cb[32]; strncpy(cb, T(no), sizeof(cb) - 1);
    cb[sizeof(cb) - 1] = '\0'; lv_label_set_text(lbl_no, cb); }
  lv_obj_set_style_text_color(lbl_no, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_no, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_no);
}

void startTagWriteNoAsk(int spool_id) {
  if (spool_id <= 0 || scr_tag_write) return;
  s_spool_id = spool_id;
  s_mode     = ASK_WRITE;
  logSDf("TagWrite: writing spool %d without asking", spool_id);
  if (tagWriteRequest(spool_id, (TagFormat)g_tagwrite_fmt, false)) {
    // The same watch a confirmed question sets, so the result popup appears
    // through the one path that already knows how to show it.
    s_watching = true;
  } else {
    showResult(TW_ERR_WRITE);
    logSD("TagWrite: writer busy, nothing queued");
  }
}

void showTagWriteAskPopup(int spool_id) {
  if (scr_tag_write || spool_id <= 0) return;
  s_spool_id = spool_id;
  s_mode     = ASK_WRITE;
  logSDf("SHOW: TagWriteAskPopup spool=%d", spool_id);
  buildAsk(STR_TW_ASK_TITLE, STR_TW_ASK_HINT, STR_TW_BTN_WRITE, STR_TW_BTN_SKIP);
}

// The decision was taken in requestTagEraseAsk(); by now the tag state is gone.
static void showTagEraseAskPopup() {
  if (scr_tag_write || !s_erase_fmt[0]) return;
  s_mode = ASK_ERASE;
  logSDf("SHOW: TagEraseAskPopup, tag holds %s", s_erase_fmt);
  buildAsk(STR_TW_ERASE_ASK_TITLE, STR_TW_ERASE_ASK_HINT,
           STR_TW_BTN_ERASE, STR_TW_BTN_KEEP);
}

// The decision was taken in tagMismatchTick(), which also built the two lines.
static void showTagMismatchPopup() {
  if (scr_tag_write || !s_mismatch_detail[0]) return;
  s_mode = ASK_REWRITE;
  logSDf("SHOW: TagMismatchPopup spool=%d", s_spool_id);
  buildAsk(STR_TW_MISM_TITLE, STR_TW_MISM_HINT, STR_TW_BTN_REWRITE, STR_TW_BTN_KEEP);
}

// Asks once per tag and spool whether a record that disagrees with the spool
// should be written again. Off by default - see g_tagmismatch_ask.
//
// On the loop task and nowhere else: it fetches the spool to compare against.
// The marker survives lifting the spool off the pad on purpose: answering
// "keep" and being asked again the next time the same spool is weighed is the
// behaviour testers reported as the most annoying thing the scale did.
void tagMismatchTick() {
  static char asked_uid[26] = "";
  static int  asked_id = 0;

  if (!g_tagmismatch_ask) return;
  if (!wifi_ok || !tag_present || !sm_found || sm_id <= 0) return;
  if (!tagIsWritableNtag() || !tagCachedHasRecord()) return;
  if (scr_tag_write || erase_ask_pending || mismatch_ask_pending) return;
  // Not over somebody else's question, and not while a list is being worked
  // through: this one can wait, all of those were asked for.
  if (isConfirmPopupOpen() || isSpoolFlowIdInputOpen() || isSpoolFlowLinkEntryOpen())
    return;

  if (asked_id == sm_id && strcmp(asked_uid, g_tag.uid_str) == 0) return;
  // Before the request, not after: the comparison costs a GET, and a pair that
  // turns out to agree must not pay for it again on the very next pass.
  snprintf(asked_uid, sizeof(asked_uid), "%s", g_tag.uid_str);
  asked_id = sm_id;

  TagInfo want;
  if (!tagDiffersFromSpool(sm_id, (TagFormat)g_tagwrite_fmt, &want)) return;

  const TagInfo *have = tagCachedInfo();
  char have_col[10] = "", want_col[10] = "";
  if (have->has_color) snprintf(have_col, sizeof(have_col), " #%02X%02X%02X",
                                have->r, have->g, have->b);
  if (want.has_color)  snprintf(want_col, sizeof(want_col), " #%02X%02X%02X",
                                want.r, want.g, want.b);
  snprintf(s_mismatch_detail, sizeof(s_mismatch_detail), "%s: %s %s%s\n%s: %s %s%s",
           T(STR_TW_MISM_TAG), have->brand, have->material, have_col,
           T(STR_TW_MISM_SERVER), want.brand, want.material, want_col);

  s_spool_id = sm_id;
  mismatch_ask_pending = true;
  logSDf("Tag: spool %d disagrees with the tag, asking", sm_id);
}

void handleTagWritePopupDeferredActions() {
  // The result of a write or erase that is already running. tagWriteTick()
  // carries it out on this same loop task, so the state settles within a pass.
  if (s_watching && strcmp(tagWriteState(), "pending") != 0) {
    s_watching = false;
    const uint8_t code = tagWriteResultCode();
    showResult(code);
    logSDf("TagWritePopup: finished, mode=%d code=%u", (int)s_mode,
           (unsigned)code);
  }

  if (erase_ask_pending) {
    erase_ask_pending = false;
    showTagEraseAskPopup();
  }

  if (mismatch_ask_pending) {
    mismatch_ask_pending = false;
    showTagMismatchPopup();
  }

  if (!close_pending) return;
  close_pending = false;

  if (scr_tag_write) { lv_obj_del(scr_tag_write); scr_tag_write = nullptr; }

  if (!confirm_pending) {
    logSDf("TagWritePopup: declined, mode=%d", (int)s_mode);
    return;
  }
  confirm_pending = false;

  // No link flag any of the three ways: the write follows a link that already
  // happened, the rewrite a spool that is already bound, and the erase an
  // unlink. The format is the one set in Settings > Scale; it used to be
  // OpenSpool with no way to say otherwise, which left an ACE user no path at
  // all from the device.
  const bool queued = (s_mode == ASK_ERASE)
                        ? tagWriteRequest(0, TAG_FMT_ERASE, false)
                        : tagWriteRequest(s_spool_id, (TagFormat)g_tagwrite_fmt, false);
  if (queued) {
    s_watching = true;
  } else {
    // Only reachable when another write is still parked, which the tag page
    // could have started. Saying so beats a popup that closes and does nothing.
    showResult(TW_ERR_WRITE);
    logSDf("TagWritePopup: writer busy, nothing queued");
  }
}
