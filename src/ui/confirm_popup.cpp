#include "confirm_popup.h"
#include "ui_common.h"
#include <math.h>
#include "app/app_state.h"
#include "services/backend.h"
#include "services/backend_api.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "hardware/sound.h"
#include "services/ams_assign.h"
#include "services/ams_pick.h"
#include "services/auto_weight_state.h"
#include "services/prefs_store.h"
#include "services/spoolman_actions.h"
#include "services/tag_write.h"
#include "dried_action.h"
#include "more_info_screen.h"
#include "app/deferred_actions.h"
#include "app/id_spool.h"
#include "spoolman_screen.h"
#include "tare_entry.h"
#include "weight_popup.h"
#include "lang.h"
#include "theme.h"


static lv_obj_t *confirm_popup = nullptr;
static int confirm_action = 0;
// The dialogs this file opens besides the question itself. They used to be
// locals of the callback that built them, so nothing could close them from
// outside and a navigation left them standing over the next screen.
static lv_obj_t *s_scope_popup = nullptr;   // where the empty spool weight goes
static lv_obj_t *s_cap_popup   = nullptr;   // BamBuddy's label weight question

void closeConfirmPopups() {
  closeConfirmPopup();
  closeWeightPopups();
  releaseScreen(&s_scope_popup);
  releaseScreen(&s_cap_popup);
  closeTareEntry();
}

// The weight popup counts as one of these. It lived in this file until
// 26.10.2026, and every place that waits for a question to be answered -
// the automatic weighing, the tag lookups, uiModalWaiting() - asks here.
bool isConfirmPopupOpen() {
  return confirm_popup != nullptr || isWeightPopupOpen();
}

bool isSpoolWeightScopeOpen() {
  return s_scope_popup != nullptr;
}

void closeConfirmPopup() {
  // Deleted on the next timer pass, not here: every caller of this is one of
  // the popup's own buttons, and deleting a button's ancestor from inside its
  // callback is the one thing LVGL's event dispatch cannot be trusted with.
  // The pointer is dropped now, so the popup counts as closed from this line.
  if (confirm_popup) { lv_obj_del_async(confirm_popup); confirm_popup = nullptr; }
  confirm_action = 0;
}

// What a button asked for, carried to appLoop(). Every one of these reaches
// the backend, and they used to run inside the button's own callback with
// the touch panel dead for the length of the request. One slot is enough:
// the popups are modal, a second press cannot land before the first has run.
enum ConfirmJob : uint8_t {
  CJ_NONE = 0,
  CJ_WEIGHT,          // the remaining weight, plus the AMS notes
  CJ_INITIAL,         // a new spool's initial weight
  CJ_TARE_SPOOL,      // the empty spool weight, on this spool
  CJ_TARE_FILAMENT,   // ... on the filament
  CJ_TARE_VENDOR,     // ... on the brand
  CJ_ARCHIVE,
  CJ_CAP_RAISE,       // BamBuddy: raise the label weight, then write
  CJ_CAP_KEEP         // BamBuddy: keep the label, write anyway
};
static ConfirmJob s_job       = CJ_NONE;
static float      s_job_value = 0.0f;
static float      s_job_gross = 0.0f;   // the pad reading the AMS note wants
// The spool an empty spool weight was meant for. Every tare write goes to
// whatever spool is loaded when it runs, and a spool swapped while the scope
// question stood would take a tare that belongs to the one before it.
static int        s_tare_spool_id = 0;  // the spool the scope question is for
static int        s_job_spool_id  = 0;  // ... carried with the parked write

static void tareFollowUp();
static void tareDropFollowUp();
static void askFreeTag();
// The question follows the archive a pass later: the popup that asked for
// the archive is deleted at the end of its pass, and the pool holds one
// question at a time.
static bool s_ask_free_tag_pending = false;

static void beepForWeightSave(int rc) {
  if (backendWriteOk(rc)) soundPlay(SND_WEIGHT_MANUAL);
  else if (rc != PATCH_WEIGHT_ASKING) soundPlay(SND_WEIGHT_FAIL);
}

void handleConfirmPopupDeferredActions() {
  if (s_ask_free_tag_pending) {
    s_ask_free_tag_pending = false;
    askFreeTag();
  }
  if (s_job == CJ_NONE) return;
  const ConfirmJob job = s_job;
  s_job = CJ_NONE;
  const bool tare_job = job == CJ_TARE_SPOOL || job == CJ_TARE_FILAMENT ||
                        job == CJ_TARE_VENDOR;
  if (tare_job && sm_id != s_job_spool_id) {
    logSDf("Tare: %.1f g was for spool %d, spool %d is loaded now - not stored",
           s_job_value, s_job_spool_id, sm_id);
    tareDropFollowUp();   // its initial weight would follow the same tare
    return;
  }
  switch (job) {
    case CJ_WEIGHT:
      beepForWeightSave(patchSpoolmanWeight(s_job_value));
      // Remembered so the question can come up on removal. A yes there
      // reports the same weight once more, which is the only way to open the
      // window. The cap check cannot interfere: it is BamBuddy only and
      // amsAskActive() requires FilaMan.
      if (amsAskActive()) amsNoteMeasurement(sm_id, s_job_value, s_job_gross, true);
      if (amsPickActive()) amsPickNote(sm_id, sm_filament_name);
      break;
    case CJ_INITIAL:
      patchInitialWeight(s_job_value);
      break;
    case CJ_TARE_SPOOL:    patchSpoolWeight(s_job_value);         tareFollowUp(); break;
    case CJ_TARE_FILAMENT: patchFilamentSpoolWeight(s_job_value); tareFollowUp(); break;
    case CJ_TARE_VENDOR:   patchVendorSpoolWeight(s_job_value);   tareFollowUp(); break;
    case CJ_ARCHIVE:
      if (patchArchiveSpool()) s_ask_free_tag_pending = true;
      break;
    case CJ_CAP_RAISE:
      // Order matters: the label first, so the weight that follows has room.
      // patchInitialWeight writes label and consumption together, which
      // already leaves the spool at full - the weight write after it is what
      // stamps last_weighed_at and last_scale_weight.
      patchInitialWeight(s_job_value);
      beepForWeightSave(patchSpoolmanWeight(s_job_value, true));
      break;
    case CJ_CAP_KEEP:
      // Written anyway, so the scale and the server agree that a weighing
      // happened. BamBuddy clamps it, which is what the user just accepted.
      beepForWeightSave(patchSpoolmanWeight(s_job_value, true));
      break;
    default: break;
  }
}


// The spool "release the tag" was asked for. The answer comes a touch later,
// and a spool lifted off meanwhile clears sm_id, so the unlink is dropped
// rather than sent to whatever lies there then.
static int s_free_tag_spool_id = 0;
// The tag the erase line was about, as the cache spelt it; empty when the
// question had no erase line.
static char s_free_tag_uid[26] = "";

// Asked once the archive is through, never before: a failed archive must not
// leave a spool that is still active without its tag. Only for a spool that
// has a binding, and the erase line only when the tag on the reader is one
// requestTagEraseNow() would actually erase.
static void askFreeTag() {
  if (!sm_found || sm_id <= 0) return;
  if (smBoundUidCount() == 0 && !tag_present) return;
  s_free_tag_spool_id = sm_id;
  char msg[224];
  const bool erase = tagIsWritableNtag() && tagCachedHasRecord();
  snprintf(s_free_tag_uid, sizeof(s_free_tag_uid), "%s", erase ? tagCachedUid() : "");
  snprintf(msg, sizeof(msg), erase ? "%s\n\n%s" : "%s", T(STR_FREE_TAG_ASK),
           T(STR_FREE_TAG_ERASE_LINE));
  logSDf("Archive: asking to release the tag of spool %d (erase=%d)", sm_id, erase ? 1 : 0);
  showConfirmPopup(msg, 7);
}

static void freeTagConfirmed() {
  if (sm_id != s_free_tag_spool_id || sm_id <= 0) {
    logSDf("Release tag: was for spool %d, spool %d is loaded now - not sent",
           s_free_tag_spool_id, sm_id);
    return;
  }
  // Every tag of the spool, the other flange too: an archived spool keeps
  // none. Only the one on the reader can be erased, the other keeps its data.
  requestSpoolUnlink(s_free_tag_spool_id, true, true, s_free_tag_uid);
}

// The weight the scope buttons below will store. Normally whatever is on the
// pad, but a brand new spool can derive it instead -- see the New spool button.
static float s_tare_prompt_g = 0.0f;
static float s_cap_measured  = 0.0f;
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

static void tareDropFollowUp() {
  s_tare_then_new = false;
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

// The question where an empty spool weight goes, rebuilt 26.10.2026 with the
// weight popup: the three places in words rather than backend field names,
// each with what it reaches, and the one whose value applies now saying so.
// One screen's coordinates, inside the box.
#define SW_BOX_W     460
#define SW_X          10
#define SW_INNER_W   436
#define SW_TITLE_Y    10
#define SW_WARN_Y     38
#define SW_WARN_H     28
#define SW_ROWS_Y     40     // without the bag warning
#define SW_ROWS_Y_WARN 74
#define SW_ROW_H      52
#define SW_ROW_STEP   58
#define SW_BTN_H      46
#define SW_SUB_W     260

static void scopePicked(ConfirmJob job) {
  s_job = job; s_job_value = s_tare_prompt_g; s_job_spool_id = s_tare_spool_id;
  releaseScreen(&s_scope_popup);
}

struct ScopeRow { int title_id; const char *sub; uint8_t source; lv_event_cb_t cb; };

static void scopeRow(lv_obj_t *box, int y, const ScopeRow &r) {
  lv_obj_t *b = lv_btn_create(box);
  lv_obj_set_size(b, SW_INNER_W, SW_ROW_H);
  lv_obj_set_pos(b, SW_X, y);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(b, 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_ROW_PRESSED), 0);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_pad_all(b, 0, 0);
  lv_obj_add_event_cb(b, r.cb, LV_EVENT_CLICKED, NULL);

  lv_obj_t *t = lv_label_create(b);
  lv_label_set_text(t, T(r.title_id));
  lv_obj_set_style_text_font(t, UI_FONT_BODY, 0);
  lv_obj_set_style_text_color(t, lv_color_hex(UI_COL_INK), 0);
  lv_obj_align(t, LV_ALIGN_LEFT_MID, 14, -9);
  lv_obj_t *sub = labelOneLine(b, r.sub, UI_FONT_CAPTION, SW_SUB_W);
  lv_obj_set_style_text_color(sub, lv_color_hex(UI_COL_CAPTION), 0);
  lv_obj_align(sub, LV_ALIGN_LEFT_MID, 14, 11);

  if (sm_tare_source != TARE_NONE && sm_tare_source == r.source) {
    char cur[32];
    snprintf(cur, sizeof(cur), T(STR_SW_CURRENT), (float)sm_spool_weight);
    lv_obj_t *c = lv_label_create(b);
    lv_label_set_text(c, cur);
    lv_obj_set_style_text_font(c, UI_FONT_SMALL, 0);
    lv_obj_set_style_text_color(c, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_align(c, LV_ALIGN_RIGHT_MID, -36, 0);
  }
  lv_obj_t *arr = lv_label_create(b);
  lv_label_set_text(arr, LV_SYMBOL_RIGHT);
  lv_obj_set_style_text_font(arr, UI_FONT_BODY, 0);
  lv_obj_set_style_text_color(arr, lv_color_hex(UI_COL_INK_FAINT), 0);
  lv_obj_align(arr, LV_ALIGN_RIGHT_MID, -14, 0);
}

// A bag on the pad is counted into the reading, and this number may be
// written to an entire brand. The device cannot tell whether one is there,
// so it says so rather than silently subtracting a weight that might not be
// on the scale at all.
static void scopeBagWarning(lv_obj_t *box) {
  lv_obj_t *strip = lv_obj_create(box);
  lv_obj_set_size(strip, SW_INNER_W, SW_WARN_H);
  lv_obj_set_pos(strip, SW_X, SW_WARN_Y);
  lv_obj_set_style_bg_color(strip, lv_color_hex(UI_COL_AMBER_BG), 0);
  lv_obj_set_style_border_color(strip, lv_color_hex(UI_COL_AMBER_LINE), 0);
  lv_obj_set_style_border_width(strip, 1, 0);
  lv_obj_set_style_radius(strip, UI_RADIUS_BTN, 0);
  lv_obj_set_style_pad_all(strip, 0, 0);
  lv_obj_clear_flag(strip, LV_OBJ_FLAG_SCROLLABLE);
  char num[64], buf[72];
  snprintf(num, sizeof(num), T(STR_SPOOL_WEIGHT_BAG_HINT), bag_weight_g);
  snprintf(buf, sizeof(buf), LV_SYMBOL_WARNING "  %s", num);
  lv_obj_t *l = lv_label_create(strip);
  lv_label_set_text(l, buf);
  lv_obj_set_style_text_font(l, UI_FONT_CAPTION, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_WARN), 0);
  lv_obj_align(l, LV_ALIGN_LEFT_MID, 10, 0);
}

// measured: the value is a reading off the pad, so a bag on it would be in
// there too. A typed value knows nothing of the bag.
static void showSpoolWeightPopup(float grams, bool then_new_spool, bool measured = true) {
  s_tare_prompt_g = grams;
  s_tare_then_new = then_new_spool;
  // The typed value only gets here for the spool its entry was opened for,
  // see tare_entry.cpp.
  s_tare_spool_id = sm_id;

  // Not every backend has all three places to put it. BamBuddy has no
  // filament and no vendor object at all, and behind its Spoolman proxy even
  // the spool's own core weight is discarded on write. Rows for those are
  // not built rather than built and left to fail.
  const bool shared = backendCanTareFilamentOrVendor();
  char spool_sub[48], fil_sub[72];
  snprintf(spool_sub, sizeof(spool_sub), "#%d  %s", sm_id, sm_filament_name);
  snprintf(fil_sub, sizeof(fil_sub), "%s%s%s", sm_vendor_g, sm_vendor_g[0] ? " " : "", sm_filament_name);
  const ScopeRow rows[] = {
    { STR_SW_ONLY_SPOOL,   spool_sub,   TARE_SPOOL,    [](lv_event_t *e) { scopePicked(CJ_TARE_SPOOL); } },
    { STR_SW_ALL_FILAMENT, fil_sub,     TARE_FILAMENT, [](lv_event_t *e) { scopePicked(CJ_TARE_FILAMENT); } },
    { STR_SW_ALL_VENDOR,   sm_vendor_g, TARE_VENDOR,   [](lv_event_t *e) { scopePicked(CJ_TARE_VENDOR); } },
  };
  const bool shown[] = { backendCanTareSpool(), shared, shared };
  const int n = (shown[0] ? 1 : 0) + (shared ? 2 : 0);
  const bool warn = measured && bag_weight_g > 0.0f;
  const int y0 = warn ? SW_ROWS_Y_WARN : SW_ROWS_Y;
  const int cancel_y = y0 + n * SW_ROW_STEP;
  lv_obj_t *box = uiPopupBox(&s_scope_popup, SW_BOX_W, cancel_y + SW_BTN_H + 12);

  char title[64];
  snprintf(title, sizeof(title), T(STR_SW_SCOPE_TITLE), grams);
  lv_obj_t *t = labelOneLine(box, title, UI_FONT_BODY, SW_INNER_W);
  lv_obj_set_style_text_color(t, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_pos(t, SW_X + 4, SW_TITLE_Y);
  if (warn) scopeBagWarning(box);

  int y = y0;
  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
    if (!shown[i]) continue;
    scopeRow(box, y, rows[i]);
    y += SW_ROW_STEP;
  }

  // Neutral like the weight popup's Close: nothing is lost by leaving.
  lv_obj_t *cancel = padButton(box, SW_X, cancel_y, SW_INNER_W, SW_BTN_H, UI_COL_ROW, UI_COL_ROW_PRESS_FILL);
  lv_obj_set_style_radius(cancel, UI_RADIUS_BTN, 0);
  padLabel(cancel, T(STR_CANCEL), UI_COL_INK_2, UI_FONT_SMALL);
  styleLeaveButton(cancel);
  lv_obj_add_event_cb(cancel, [](lv_event_t *e) {
    s_tare_then_new = false;
    releaseScreen(&s_scope_popup);
  }, LV_EVENT_CLICKED, NULL);
}

void showSpoolWeightScope(float grams, bool measured) {
  showSpoolWeightPopup(grams, false, measured);
}

void confirmQueueWeight(float netto_g, float gross_g) {
  // The numbers are taken now, the request runs on the next loop pass.
  s_job = CJ_WEIGHT; s_job_value = netto_g; s_job_gross = gross_g;
}

// Where nothing is known about the empty spool, taking it as full derives
// that first and asks where it goes; the initial weight follows from it.
void confirmNewSpool(float netto_g) {
  float derived = 0.0f;
  if (newSpoolDerivesTare(&derived)) {
    showSpoolWeightPopup(derived, true);   // stores the tare, then the initial
    return;
  }
  s_job = CJ_INITIAL; s_job_value = netto_g;
}

// Name the weight the button will really write. Where the tare is derived
// that is the nominal filament weight, not the reading minus a tare that is
// about to be replaced - and those two differ by the whole spool.
float confirmNewSpoolShownG(float netto_g) {
  return newSpoolDerivesTare(nullptr) ? sm_total : netto_g;
}

void showConfirmPopup(const char* msg, int action) {
  closeConfirmPopup();
  confirm_action = action;

  confirm_popup = lv_obj_create(lv_scr_act());
  lv_obj_set_size(confirm_popup, 480, 320);
  lv_obj_set_pos(confirm_popup, 0, 0);
  lv_obj_set_style_bg_color(confirm_popup, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(confirm_popup, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(confirm_popup, 0, 0);
  lv_obj_set_style_radius(confirm_popup, 0, 0);
  lv_obj_set_style_pad_all(confirm_popup, 0, 0);  // KRITISCH: kein Default-Padding!
  lv_obj_clear_flag(confirm_popup, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(confirm_popup);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_q = lv_label_create(box);
  lv_label_set_text(lbl_q, msg);
  lv_obj_set_style_text_color(lbl_q, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(lbl_q, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_q, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_q, LV_LABEL_LONG_WRAP);

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
  uint32_t         icon_col = UI_COL_WARN;
  const lv_font_t* q_font   = &lv_font_montserrat_ext_20;
  int              box_h    = 210;
  if (action == 1) {                       // dried today
    icon = LV_SYMBOL_TINT;  icon_col = UI_COL_DRY;
  } else if (action == 3) {                // archive spool
    icon = LV_SYMBOL_TRASH; icon_col = UI_COL_ARCHIVE_TEXT;
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
  lv_obj_set_style_bg_color(btn_ja, lv_color_hex(UI_COL_OK_BG), 0);
  lv_obj_set_style_bg_color(btn_ja, lv_color_hex(UI_COL_OK_BG_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ja, 8, 0);
  lv_obj_set_style_shadow_width(btn_ja, 0, 0);
  lv_obj_add_event_cb(btn_ja, [](lv_event_t *e) {
    int act = confirm_action;
    closeConfirmPopup();
    if (act == 1) btn_dried_cb(nullptr);
    if (act == 3) s_job = CJ_ARCHIVE;
    // 7 = release the tag of the spool just archived. Flags only.
    if (act == 7) freeTagConfirmed();
    if (act == 4) spoolmanClearHost();
    // 5 = downgrade confirmed on the OTA screen. Only the flag here; the
    // download runs from appLoop().
    if (act == 5) gh_downgrade_pending = true;
    // 6 = reset the calibration. The flag again: it writes NVS and rebuilds
    // the screen this button was opened from.
    if (act == 6) cal_reset_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ja = lv_label_create(btn_ja);
  lv_label_set_text(lbl_ja, T(action == 7 ? STR_BTN_FREE_TAG : STR_BTN_CONFIRMED));
  lv_obj_set_style_text_font(lbl_ja, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_color(lbl_ja, lv_color_hex(UI_COL_OK_TEXT), 0);
  lv_obj_center(lbl_ja);

  lv_obj_t *btn_nein = lv_btn_create(box);
  lv_obj_set_size(btn_nein, 170, BTN_H);
  lv_obj_set_pos(btn_nein, 218, BTN_Y);
  lv_obj_set_style_bg_color(btn_nein, lv_color_hex(UI_COL_BAD_BG), 0);
  lv_obj_set_style_bg_color(btn_nein, lv_color_hex(UI_COL_BAD_BG_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_nein, 8, 0);
  lv_obj_set_style_shadow_width(btn_nein, 0, 0);
  lv_obj_add_event_cb(btn_nein, [](lv_event_t *e){ closeConfirmPopup(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_nein = lv_label_create(btn_nein);
  // Keeping the tag is a fine answer after an archive, not a cancel.
  lv_label_set_text(lbl_nein, T(action == 7 ? STR_TW_BTN_KEEP : STR_CANCEL));
  lv_obj_set_style_text_font(lbl_nein, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_color(lbl_nein, lv_color_hex(UI_COL_BAD_TEXT), 0);
  lv_obj_center(lbl_nein);
  if (action != 7) styleLeaveButton(btn_nein);
}

// ============================================================
//  BAMBUDDY: MEASUREMENT ABOVE THE LABEL WEIGHT
//
//  BamBuddy's built-in inventory keeps the consumed grams and derives the
//  rest, and Spoolman behind BamBuddy clamps the same way, so a spool holding
//  more than its label says cannot be stored - the remainder clamps back to
//  full. Raising the label is the only way to keep the number, and that
//  changes a field the user owns, so it is asked.
// ============================================================
void showBamBuddyCapPopup(float measured_g, float label_g) {
  releaseScreen(&s_cap_popup);
  lv_obj_t *popup = lv_obj_create(lv_scr_act());
  s_cap_popup = popup;
  lv_obj_set_size(popup, 480, 320);
  lv_obj_set_pos(popup, 0, 0);
  lv_obj_set_style_bg_color(popup, lv_color_hex(UI_COL_GROUND), 0);
  lv_obj_set_style_border_width(popup, 0, 0);
  lv_obj_set_style_radius(popup, 0, 0);
  lv_obj_set_style_pad_all(popup, 0, 0);
  lv_obj_clear_flag(popup, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *title = lv_label_create(popup);
  char title_buf[40];
  copyT(title_buf, sizeof(title_buf), STR_BB_CAP_TITLE);
  lv_label_set_text(title, title_buf);
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_WARN), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 14);

  lv_obj_t *body = lv_label_create(popup);
  char body_buf[240];
  snprintf(body_buf, sizeof(body_buf), T(STR_BB_CAP_BODY), measured_g, label_g);
  lv_label_set_text(body, body_buf);
  lv_obj_set_style_text_color(body, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(body, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(body, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(body, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(body, 440);
  lv_obj_align(body, LV_ALIGN_TOP_MID, 0, 52);

  // Remembered for the two handlers, which cannot capture anything.
  s_cap_measured = measured_g;

  lv_obj_t *b_raise = lv_btn_create(popup);
  lv_obj_set_size(b_raise, 440, 56); lv_obj_set_pos(b_raise, 20, 150);
  lv_obj_set_style_bg_color(b_raise, lv_color_hex(UI_COL_PICKED_BG), 0);
  lv_obj_set_style_radius(b_raise, 8, 0);
  lv_obj_set_style_shadow_width(b_raise, 0, 0);
  { lv_obj_t *l = lv_label_create(b_raise);
    char buf[48];
    snprintf(buf, sizeof(buf), T(STR_BB_CAP_RAISE), measured_g);
    lv_label_set_text(l, buf);
    lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_OK_TEXT_2), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(l); }
  lv_obj_add_event_cb(b_raise, [](lv_event_t *e) {
    s_job = CJ_CAP_RAISE; s_job_value = s_cap_measured;
    releaseScreen(&s_cap_popup);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *b_keep = lv_btn_create(popup);
  lv_obj_set_size(b_keep, 440, 48); lv_obj_set_pos(b_keep, 20, 216);
  lv_obj_set_style_bg_color(b_keep, lv_color_hex(UI_COL_LINE_SOFT), 0);
  lv_obj_set_style_radius(b_keep, 8, 0);
  lv_obj_set_style_shadow_width(b_keep, 0, 0);
  { lv_obj_t *l = lv_label_create(b_keep);
    char buf[40];
    copyT(buf, sizeof(buf), STR_BB_CAP_KEEP);
    lv_label_set_text(l, buf);
    lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK_2), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(l); }
  lv_obj_add_event_cb(b_keep, [](lv_event_t *e) {
    s_job = CJ_CAP_KEEP; s_job_value = s_cap_measured;
    releaseScreen(&s_cap_popup);
  }, LV_EVENT_CLICKED, NULL);
}
