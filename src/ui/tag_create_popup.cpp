#include "ui/tag_create_popup.h"

#include <Arduino.h>
#include <HTTPClient.h>
#include <lvgl.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

// backend_api.h brings ArduinoJson, whose templates have a parameter T:
// before lang.h, which defines T().
#include "services/backend_api.h"
#include "app/app_state.h"
#include "app/backend_switch.h"
#include "app_config.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/server_reach.h"
#include "services/spool_cache.h"
#include "services/tag_create.h"
#include "services/tag_db_match.h"
#include "ui/main_screen_helpers.h"
#include "ui/price_pad.h"
#include "ui/spool_flow_internal.h"
#include "ui/tag_db_diff_popup.h"
#include "ui/theme.h"
#include "ui/ui_common.h"

// The lines of the card, as on the copy confirmation.
#define TCP_LINE_H   26
#define TCP_SWATCH   18
#define TCP_GAP       8
// The answer row: create and cancel on either side, the price between them.
#define TCP_PRICE_W  80
#define TCP_ANSWER_W ((UI_POPUP_W - 2 * UI_CARD_ROW_X - 2 * TCP_GAP - TCP_PRICE_W) / 2)

// What the loop is to do for the card on its next pass.
enum TcpJob : uint8_t { TCP_IDLE = 0, TCP_PLAN, TCP_CREATE };

static lv_obj_t*       s_scr    = nullptr;
static lv_obj_t*       s_status = nullptr;
static lv_obj_t*       s_btn_ok = nullptr;
static lv_obj_t*       s_lbl_price = nullptr;
static lv_obj_t*       s_swatch = nullptr;
static lv_obj_t*       s_meta   = nullptr;
// Where the tag and the database entry for its filament disagree.
static TagDbDiff       s_diffs[TAG_DB_DIFFS_MAX];
static int             s_diff_n = 0;
// What the spool cost, 0 while none was typed in.
static float           s_price  = 0.0f;
static TcpJob          s_job    = TCP_IDLE;
static TagCreateInput  s_in;
// The input came from the database picker, not from the tag: its colours are
// drawn from the input, the tag on the pad may have none.
static bool            s_picked = false;
static TagFilamentPlan s_plan;
static int             s_label_weight = 0;
// Cancel hides the card from its own callback; the loop deletes it.
static bool            s_close_pending = false;
// The plan is asked again before a create when it may no longer hold: after
// a failed try that left no filament behind, so a vendor made on the way, or
// a filament the server made although its answer was lost, is found rather
// than made twice; and after a switch of backend or host.
static bool            s_plan_stale = false;
static uint32_t        s_plan_gen   = 0;

lv_obj_t* tagCreatePopupScreen() { return s_scr; }

bool tagCreateOffered() {
  TagCreateInput in;
  return backendCanCreateFromTag() && tagCreateInputFromTag(&in);
}

void tagCreateEntryTap(lv_event_t*) {
  logSD("BTN: New from tag");
  newtag_open_pending = true;
}

void closeTagCreatePopup() {
  closePricePad();
  closeTagDbDiffPopup();
  releaseScreen(&s_scr);
  s_status = nullptr;
  s_btn_ok = nullptr;
  s_lbl_price = nullptr;
  s_swatch = nullptr;
  s_meta = nullptr;
  s_job = TCP_IDLE;
}

// ------------------------------------------------------------
//  Weights
// ------------------------------------------------------------

// What the new spool starts with: the net reading when the spool lies on the
// pad, otherwise a full one - a spool still in its box has not been touched.
// Without the empty spool's weight nothing can be subtracted: full as well.
static float remainingWeight() {
  const float core = (float)s_in.spool_weight_g;
  if (core <= 0.0f || scale_weight_g < core) return (float)s_label_weight;
  return scale_weight_g - core;
}

// The tag's own net weight; without it the nominal size nearest the reading.
static int labelWeight() {
  if (s_in.net_weight_g > 0) return s_in.net_weight_g;
  static const int choices[NEWTAG_LABEL_COUNT] = NEWTAG_LABEL_CHOICES;
  const float netto = scale_weight_g - (float)s_in.spool_weight_g;
  int best = choices[NEWTAG_LABEL_COUNT - 1], best_diff = -1;
  for (int i = 0; i < NEWTAG_LABEL_COUNT; i++) {
    const int diff = (int)fabsf(netto - (float)choices[i]);
    if (best_diff < 0 || diff < best_diff) { best_diff = diff; best = choices[i]; }
  }
  return best;
}

// ------------------------------------------------------------
//  The status line and the create button
// ------------------------------------------------------------

static void showStatus(const char* text, uint32_t color, bool can_create) {
  if (!s_status) return;
  lv_label_set_text(s_status, text);
  lv_obj_set_style_text_color(s_status, lv_color_hex(color), 0);
  if (!s_btn_ok) return;
  if (can_create) lv_obj_clear_state(s_btn_ok, LV_STATE_DISABLED);
  else            lv_obj_add_state(s_btn_ok, LV_STATE_DISABLED);
}

static void showPlan() {
  char buf[96];
  switch (s_plan.state) {
    case TFS_FOUND:
      snprintf(buf, sizeof(buf), T(STR_TAGNEW_FOUND), s_plan.filament_id);
      showStatus(buf, UI_COL_GOOD, true);
      break;
    case TFS_CREATE_DB:
      // A tag the database knows: the tag's values, the entry's for the rest.
      if (!s_picked && (s_plan.db_found || s_in.db_id[0]))
        showStatus(T(STR_TAGNEW_TAG_PLUS_DB), UI_COL_ACCENT, true);
      else
        showStatus(T(backendIsFilaMan() ? STR_TAGNEW_FROM_FDB : STR_TAGNEW_FROM_DB), UI_COL_ACCENT, true);
      break;
    case TFS_CREATE_TAG:    showStatus(T(STR_TAGNEW_FROM_TAG), UI_COL_ACCENT, true);        break;
    case TFS_NOT_NEEDED:    showStatus(T(STR_TAGNEW_BAMBUDDY), UI_COL_INK_SOFT, true);      break;
    case TFS_NEEDS_CATALOG: showStatus(T(STR_TAGNEW_NEEDS_CATALOG), UI_COL_WARN, false);    break;
    default:
      snprintf(buf, sizeof(buf), T(STR_TAGNEW_FAILED), s_plan.http_code);
      showStatus(buf, UI_COL_BAD_TEXT, false);
      break;
  }
}

// ------------------------------------------------------------
//  The card
// ------------------------------------------------------------

static lv_obj_t* buildBox() {
  s_scr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(s_scr, LV_HOR_RES, LV_VER_RES);
  lv_obj_set_pos(s_scr, 0, 0);
  lv_obj_set_style_bg_color(s_scr, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(s_scr, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(s_scr, 0, 0);
  lv_obj_set_style_radius(s_scr, 0, 0);
  lv_obj_set_style_pad_all(s_scr, 0, 0);
  lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t* box = lv_obj_create(s_scr);
  lv_obj_set_size(box, UI_POPUP_W, UI_CARD_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);
  return box;
}

static void buildHead(lv_obj_t* box) {
  lv_obj_t* icon = lv_label_create(box);
  lv_label_set_text(icon, LV_SYMBOL_PLUS);
  lv_obj_set_style_text_color(icon, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(icon, UI_FONT_ICON, 0);
  lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, UI_CARD_ICON_Y);

  lv_obj_t* title = lv_label_create(box);
  lv_label_set_text(title, T(s_picked ? STR_COPY_CONFIRM_TITLE : STR_NEWTAG_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(title, UI_FONT_HEADLINE, 0);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(title, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, UI_CARD_TITLE_Y);
}

// Line 1: the colour and the product, as one centred group.
static void buildIdentity(lv_obj_t* box) {
  lv_obj_t* row = lv_obj_create(box);
  lv_obj_remove_style_all(row);
  lv_obj_set_size(row, UI_POPUP_W - UI_CARD_TEXT_PAD, TCP_LINE_H);
  lv_obj_align(row, LV_ALIGN_TOP_MID, 0, UI_CARD_TEXT_Y - 4);
  lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(row, TCP_GAP, 0);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t* sw = lv_obj_create(row);
  lv_obj_set_size(sw, TCP_SWATCH, TCP_SWATCH);
  lv_obj_set_style_radius(sw, UI_RADIUS_INPUT, 0);
  lv_obj_set_style_border_width(sw, 1, 0);
  lv_obj_set_style_border_color(sw, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_pad_all(sw, 0, 0);
  lv_obj_clear_flag(sw, LV_OBJ_FLAG_SCROLLABLE);
  s_swatch = sw;
  if (s_picked) {
    char rgba[10];
    snprintf(rgba, sizeof(rgba), "%s", s_in.clear ? "FFFFFF00" : s_in.color_hex);
    swatchPaintHex(sw, rgba);
  } else {
    swatchPaint(sw, g_tag.color);
  }
  // A gradient or dual colour spool: its first two colours, the way the tag
  // view draws it.
  if (s_in.color_count >= 2) {
    lv_obj_set_style_bg_grad_color(sw, lv_color_hex(strtoul(s_in.colors_hex[1], nullptr, 16)), 0);
    lv_obj_set_style_bg_grad_dir(sw, LV_GRAD_DIR_VER, 0);
  }

  char name[80];
  joinMaterialName(s_in.product, s_in.color_name, name, sizeof(name));
  lv_obj_t* lbl = lv_label_create(row);
  lv_label_set_text(lbl, name);
  lv_obj_set_style_text_color(lbl, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(lbl, UI_FONT_TITLE, 0);
  lv_label_set_long_mode(lbl, LV_LABEL_LONG_DOT);
  lv_obj_set_style_max_width(lbl, UI_POPUP_W - UI_CARD_TEXT_PAD - TCP_SWATCH - TCP_GAP, 0);
}

static lv_obj_t* textLine(lv_obj_t* box, const lv_font_t* font, uint32_t color, int y) {
  lv_obj_t* lbl = lv_label_create(box);
  lv_obj_set_style_text_color(lbl, lv_color_hex(color), 0);
  lv_obj_set_style_text_font(lbl, font, 0);
  lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(lbl, LV_ALIGN_TOP_MID, 0, y);
  return lbl;
}

// Line 2: whose it is, the article number, and what the spool starts with.
static void refreshMeta() {
  if (!s_meta) return;
  char meta[96];
  if (s_in.article[0])
    snprintf(meta, sizeof(meta), T(STR_TAGNEW_META_ART), s_in.vendor, s_in.article,
             remainingWeight(), s_label_weight);
  else
    snprintf(meta, sizeof(meta), T(STR_TAGNEW_META), s_in.vendor, remainingWeight(), s_label_weight);
  lv_label_set_text(s_meta, meta);
}

// Line 3: the filament, filled in once the lookup has answered.
static void buildLines(lv_obj_t* box) {
  s_meta = textLine(box, UI_FONT_SMALL, UI_COL_INK_SOFT, UI_CARD_TEXT_Y - 4 + TCP_LINE_H + 4);
  refreshMeta();

  s_status = textLine(box, UI_FONT_BODY, UI_COL_INK_SOFT, UI_CARD_TEXT_Y - 4 + 2 * TCP_LINE_H + 8);
  lv_label_set_text(s_status, T(STR_TAGNEW_SEARCHING));
}

static lv_obj_t* answerButton(lv_obj_t* box, int x, int w, bool ok, int text_id) {
  lv_obj_t* btn = lv_btn_create(box);
  lv_obj_set_size(btn, w, UI_POPUP_BTN_H);
  lv_obj_set_pos(btn, x, UI_CARD_ROW_Y);
  lv_obj_set_style_bg_color(btn, lv_color_hex(ok ? UI_COL_OK_BG : UI_COL_BAD_BG), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(ok ? UI_COL_OK_BG_PRESSED : UI_COL_BAD_BG_PRESSED),
                            LV_STATE_PRESSED);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_DISABLED_BG), LV_STATE_DISABLED);
  lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_t* lbl = lv_label_create(btn);
  lv_label_set_text(lbl, T(text_id));
  lv_obj_set_style_text_color(lbl, lv_color_hex(ok ? UI_COL_OK_TEXT : UI_COL_BAD_TEXT), 0);
  lv_obj_set_style_text_color(lbl, lv_color_hex(UI_COL_DISABLED_TEXT), LV_STATE_DISABLED);
  lv_obj_set_style_text_font(lbl, UI_FONT_TITLE, 0);
  lv_obj_center(lbl);
  return btn;
}

// The price button shows what was typed in, or that there is none yet.
static void refreshPrice() {
  if (!s_lbl_price) return;
  if (s_price <= 0.0f) { lv_label_set_text(s_lbl_price, T(STR_TAGNEW_PRICE_BTN)); return; }
  char buf[16];
  snprintf(buf, sizeof(buf), "%.2f", s_price);
  lv_label_set_text(s_lbl_price, buf);
}

static void onPrice(float price) {
  s_price = price;
  refreshPrice();
}

static void buildPriceButton(lv_obj_t* box) {
  lv_obj_t* btn = lv_btn_create(box);
  lv_obj_set_size(btn, TCP_PRICE_W, UI_POPUP_BTN_H);
  lv_obj_set_pos(btn, UI_CARD_ROW_X + TCP_ANSWER_W + TCP_GAP, UI_CARD_ROW_Y);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn, 1, 0);
  lv_obj_set_style_border_color(btn, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, [](lv_event_t*) {
    if (s_job != TCP_IDLE) return;
    logSD("BTN: TagCreate -> Price");
    showPricePad(s_price, onPrice);
  }, LV_EVENT_CLICKED, NULL);
  s_lbl_price = lv_label_create(btn);
  lv_obj_set_style_text_color(s_lbl_price, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(s_lbl_price, UI_FONT_SMALL, 0);
  lv_obj_center(s_lbl_price);
  refreshPrice();
}

static void buildAnswers(lv_obj_t* box) {
  s_btn_ok = answerButton(box, UI_CARD_ROW_X, TCP_ANSWER_W, true, STR_COPY_CARD_CREATE);
  lv_obj_add_state(s_btn_ok, LV_STATE_DISABLED);   // until the lookup has answered
  lv_obj_add_event_cb(s_btn_ok, [](lv_event_t*) {
    if (s_job != TCP_IDLE) return;
    logSD("BTN: TagCreate -> Create");
    showStatus(T(STR_TAGNEW_CREATING), UI_COL_INK_SOFT, false);
    s_job = TCP_CREATE;
  }, LV_EVENT_CLICKED, NULL);

  buildPriceButton(box);

  lv_obj_t* no = answerButton(box, UI_POPUP_W - TCP_ANSWER_W - UI_CARD_ROW_X, TCP_ANSWER_W,
                              false, STR_CANCEL);
  lv_obj_add_event_cb(no, [](lv_event_t*) {
    logSD("BTN: TagCreate -> Cancel");
    // Hidden here, deleted by the loop: this is the button's own callback.
    if (s_scr) lv_obj_add_flag(s_scr, LV_OBJ_FLAG_HIDDEN);
    s_job = TCP_IDLE;
    s_close_pending = true;
  }, LV_EVENT_CLICKED, NULL);
}

static void buildCard() {
  s_label_weight = labelWeight();
  s_price = 0.0f;
  tagFilamentPlanClear(&s_plan);

  lv_obj_t* box = buildBox();
  buildHead(box);
  buildIdentity(box);
  buildLines(box);
  buildAnswers(box);
  s_job = TCP_PLAN;
}

void showTagCreatePopup() {
  logSD("SHOW: TagCreatePopup");
  closeTagCreatePopup();
  if (!tagCreateInputFromTag(&s_in)) {
    logSD("TagCreate: no tag to create from");
    return;
  }
  s_picked = false;
  buildCard();
}

void showTagCreatePopupFor(const TagCreateInput& in) {
  logSD("SHOW: TagCreatePopup (picked)");
  closeTagCreatePopup();
  s_in = in;
  s_picked = true;
  buildCard();
}

// ------------------------------------------------------------
//  The loop's part
// ------------------------------------------------------------

// The user's answer to the differences: the database's values, or the tag's
// as they stand.
static void onDiffAnswer(bool take_db) {
  logSDf("TagCreate: %d difference(s), %s", s_diff_n, take_db ? "database taken" : "tag kept");
  if (!take_db) return;
  for (int i = 0; i < s_diff_n; i++) {
    tagDbTake(&s_in, s_diffs[i]);
    if (s_diffs[i].field == TDF_COLOR && s_swatch) swatchPaintHex(s_swatch, s_in.color_hex);
  }
  s_label_weight = labelWeight();
  refreshMeta();
}

// The database knows the tag's filament: what the tag lacks comes from the
// entry, and where both say something different, the user is asked. The
// tag stays as it is until then (tag_db_match.h).
static void mergeDbEntry() {
  s_diff_n = tagDbCompare(s_in, s_plan.db, s_diffs, TAG_DB_DIFFS_MAX);
  tagDbFill(&s_in, s_plan.db);
  // The plan was made from the tag alone; the create asks it again with the
  // entry linked, so the backend writes what the card now holds.
  s_plan_stale = true;
  logSDf("TagCreate: database entry #%s merged, %d difference(s)", s_plan.db.id, s_diff_n);
  s_label_weight = labelWeight();
  refreshMeta();
  if (s_diff_n > 0) showTagDbDiffPopup(s_diffs, s_diff_n, onDiffAnswer);
}

static void runPlan() {
  s_plan_stale = false;
  s_plan_gen   = backendGeneration();
  if (!wifi_ok) { s_plan.state = TFS_FAILED; showPlan(); return; }
  backendPlanTagFilament(s_in, &s_plan);
  serverReachNote(s_plan.state == TFS_FAILED ? s_plan.http_code : 200, true);
  showPlan();
  if (s_plan.state == TFS_CREATE_DB && s_plan.db_found && !s_in.db_id[0]) mergeDbEntry();
}

// What the create button can act on.
static bool planCanCreate(TagFilamentState state) {
  return state == TFS_FOUND || state == TFS_CREATE_DB ||
         state == TFS_CREATE_TAG || state == TFS_NOT_NEEDED;
}

// The request reached the server but its answer did not come back, so the
// server may have done it: a read timeout, a dropped link, a proxy that gave
// up waiting. A refused connection or a 502 never got that far.
static bool answerLost(int code) {
  return code == HTTPC_ERROR_READ_TIMEOUT || code == HTTPC_ERROR_CONNECTION_LOST ||
         code == HTTP_CODE_GATEWAY_TIMEOUT;
}

static void runCreate() {
  // Without Wi-Fi the create would sit in the HTTP stack until its connect
  // timeout; the plan's own path says so on the card instead.
  if (!wifi_ok) { runPlan(); return; }
  if (s_plan_stale || s_plan_gen != backendGeneration()) {
    logSD("TagCreate: plan asked again before the create");
    runPlan();
    if (!planCanCreate(s_plan.state)) return;   // showPlan() has said why
  }
  TagCreateResult r;
  const TagSpoolValues values = { s_label_weight, remainingWeight(), s_price };
  const int code = serverReachNote(backendCreateFromTag(s_in, s_plan, values, &r), true);
  logSDf("TagCreate: HTTP %d, spool %d, filament %d, label %d g, price %.2f, link %s",
         code, r.spool_id, r.filament_id, s_label_weight, s_price, s_in.link_id);
  char buf[96];
  if ((code == 200 || code == 201) && r.spool_id > 0) {
    spoolCacheForget("spool created from a tag");
    char link_id[sizeof(s_in.link_id)];
    memcpy(link_id, s_in.link_id, sizeof(link_id));
    const bool with_filament = r.filament_id > 0;
    const bool price_lost = r.price_lost;
    closeTagCreatePopup();
    // The spool exists either way; a tag that could not be bound has said so
    // on the status line, and that must stay readable.
    if (!finishCopyFlow(r.spool_id, link_id)) return;
    if (price_lost) statusMessageShow(T(STR_TAGNEW_PRICE_LOST), UI_COL_WARN);
    else statusMessageShow(T(with_filament ? STR_TAGNEW_OK_BOTH : STR_NEWTAG_OK), UI_COL_GOOD);
    return;
  }
  // The spool may exist without the tag's link. Another try would make a
  // second one, so the card stops here and the inventory has the answer.
  if (r.spool_sent && answerLost(code)) {
    showStatus(T(STR_TAGNEW_SPOOL_UNSURE), UI_COL_BAD_TEXT, false);
    return;
  }
  // A filament that was created stays; the next try uses it.
  if (r.filament_id > 0) {
    s_plan.state = TFS_FOUND;
    s_plan.filament_id = r.filament_id;
    snprintf(buf, sizeof(buf), T(STR_TAGNEW_FILAMENT_ONLY), r.filament_id, code);
  } else {
    s_plan_stale = true;
    snprintf(buf, sizeof(buf), T(STR_TAGNEW_CREATE_FAIL), code);
  }
  showStatus(buf, UI_COL_BAD_TEXT, true);
}

void tagCreatePopupTick() {
  pricePadTick();
  tagDbDiffPopupTick();
  if (s_close_pending) {
    s_close_pending = false;
    closeTagCreatePopup();
    return;
  }
  if (!s_scr || s_job == TCP_IDLE) return;
  const TcpJob job = s_job;
  s_job = TCP_IDLE;
  // The card as it stands now, before the loop waits on the server.
  lv_refr_now(NULL);
  if (job == TCP_PLAN) runPlan();
  else                 runCreate();
}
