#include "ui/unknown_spool_popup.h"

#include <Arduino.h>
#include <lvgl.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "app/app_state.h"
#include "app_config.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/tag_create.h"
#include "services/user_options.h"
#include "ui/db_pick_screen.h"
#include "ui/spool_flow.h"
#include "ui/spool_flow_internal.h"
#include "ui/spoolman_lookup.h"
#include "ui/tag_create_popup.h"
#include "ui/copy_tagless.h"
#include "ui/theme.h"
#include "ui/ui_common.h"
// Last, see the note on ArduinoJson and T() in tag_create_popup.cpp.
#include "lang.h"

// The card's own coordinates, inside its box. Measured on the mockups of
// 24.10.2026: a head of three lines, a caption, the suggestion, the answers.
#define UNK_BOX_W        440
#define UNK_BOX_H        292
#define UNK_X             12   // the inset of every row, left and right
#define UNK_ROW_W        412   // what is left between the insets
#define UNK_GAP            8
#define UNK_TEXT_W       400
#define UNK_TITLE_Y       14
#define UNK_IDENT_Y       46
#define UNK_IDENT_H       26
#define UNK_META_Y        76
#define UNK_CAPTION_Y    102
#define UNK_MID_Y        126
#define UNK_MID_H         60
#define UNK_TILE_Y       108
#define UNK_TILE_H        96
#define UNK_ANSWER_Y     222
#define UNK_SWATCH_HEAD   18
#define UNK_SWATCH_ROW    32
#define UNK_SWATCH_CHIP   24
#define UNK_TEXT_X        56   // text beside the swatch in a row
#define UNK_CHIP_TEXT_X   42   // and in a chip
#define UNK_LINE1_Y        8
#define UNK_LINE2_Y       32
#define UNK_ID_W          64   // the spool id at the right end of the row
#define UNK_TILE_SYMBOL_Y 16
#define UNK_TILE_TEXT_Y   48   // a caption of two lines still ends inside
// More spools than chips: the last chip says how many more there are.
#define UNK_CHIPS          3
// The card waits for the spool to settle on the pad, by the same stillness
// as the AMS question (PAD_SETTLE_* in app_config.h): before that the reading
// is still climbing, the weight in the head is wrong, and no stored weight can
// match it. Not for ever - a spool that keeps rocking still gets its card.
#define UNK_SETTLE_MAX_MS   4000
// A spool held up to the reader rather than put down - still in its
// packaging, say - takes its tag away the moment the card opens. Below this
// load on the pad the card counts the spool as held: it stays when the tag
// goes, for UNK_HELD_MS, and its Cancel counts that time down, so the card
// ends on its own without anything being filed. Without a load cell every
// spool is held.
#define UNK_HELD_BELOW_G    ID_SPOOL_LOAD_MIN_G
#define UNK_HELD_MS         60000UL

enum UnkMode : uint8_t { UNK_ONE, UNK_MANY, UNK_CREATE, UNK_TILES };

enum UnkAction : uint8_t {
  UA_NONE = 0, UA_LINK_PICK, UA_LINK_LIST, UA_CREATE, UA_OTHER,
  UA_LINK_ENTRY, UA_DB, UA_COPY, UA_WEIGH, UA_CANCEL
};

static lv_obj_t*     s_scr = nullptr;
// Offered by the verdict, opened by the next tick.
static bool          s_offer_pending = false;
static bool          s_offer_bambu   = false;
static char          s_offer_key[40] = "";
static uint32_t      s_offer_ms = 0;
static float         s_settle_g = 0.0f;
static uint32_t      s_settle_ms = 0;
// What the open card, or the one this placement already had, is about.
static bool          s_bambu = false;
static char          s_asked_key[40] = "";
// A held spool's card: since when, which tag it opened on, and its countdown.
static bool          s_held = false;
static uint32_t      s_held_ms = 0;
static char          s_held_uid[24] = "";
static lv_obj_t*     s_held_fill = nullptr;
static lv_coord_t    s_held_fill_full = 0;
static lv_coord_t    s_held_fill_w = -1;
// What was tapped, for the loop.
static UnkAction     s_action    = UA_NONE;
static int           s_action_id = 0;
static LinkCandidate s_cands[UNK_CHIPS];
static int           s_cand_total = 0;

lv_obj_t* unknownSpoolPopupScreen() { return s_scr; }

void closeUnknownSpoolPopup() {
  s_held_fill = nullptr;
  releaseScreen(&s_scr);
}

void unknownSpoolOffer(bool is_bambu, const char* key) {
  if (!g_unk_ask || !key || !key[0]) return;
  // Asked once per placement. A lookup that runs again for the same spool -
  // the recheck, a backend that came back - does not ask a second time.
  if (strcmp(key, s_asked_key) == 0) return;
  s_offer_pending = true;
  s_offer_bambu = is_bambu;
  snprintf(s_offer_key, sizeof(s_offer_key), "%s", key);
  s_offer_ms = s_settle_ms = millis();
  s_settle_g = scale_weight_g;
}

void unknownSpoolForget() {
  s_offer_pending = false;
  // Leaving the reader is what a held spool does: its card stays for its
  // countdown, and the same tag again does not ask a second time.
  if (s_scr && s_held) {
    logSD("UnknownSpool: the tag left a held spool, the card stays");
    return;
  }
  s_asked_key[0] = '\0';
  s_action = UA_NONE;
  if (s_scr) logSD("UnknownSpool: the spool left the pad, card closed");
  closeUnknownSpoolPopup();
}

// ------------------------------------------------------------
//  When the card may open, and when it has to go
// ------------------------------------------------------------

// The tag on the pad is still the one the verdict was about.
static bool keyIsOnPad(bool bambu, const char* key) {
  return strcmp(bambu ? g_tag.tray_uuid : link_tag_uid, key) == 0;
}

// Not tag_present: an NTAG whose reception drops out leaves it false with the
// spool still on the pad, and the loop keeps that spool on the main screen.
// Whether the spool left is the loop's call, made through unknownSpoolForget().
static bool stillUnknown(bool bambu, const char* key) {
  return !sm_found && !lookupPending() && keyIsOnPad(bambu, key);
}

// The open card still belongs on screen. A held spool's tag comes and goes,
// and a read of the same tag again empties the fields on the way, so its card
// ends only on an answer: the spool was found, or another tag was read.
static bool cardStillFits() {
  if (!s_held) return stillUnknown(s_bambu, s_asked_key);
  if (sm_found) return false;
  return !g_tag.uid_str[0] || strcmp(g_tag.uid_str, s_held_uid) == 0;
}

// The reading has stood still long enough, or the card has waited long enough.
static bool weightReady() {
  if (!g_scale_fitted) return true;
  const uint32_t now = millis();
  if (now - s_offer_ms >= UNK_SETTLE_MAX_MS) return true;
  if (fabsf(scale_weight_g - s_settle_g) > PAD_SETTLE_TOL_G) {
    s_settle_g = scale_weight_g;
    s_settle_ms = now;
    return false;
  }
  return now - s_settle_ms >= PAD_SETTLE_MS;
}

// ------------------------------------------------------------
//  Taps: parked for the loop
// ------------------------------------------------------------

static void onAction(lv_event_t* e) {
  s_action = (UnkAction)(intptr_t)lv_event_get_user_data(e);
  // Only the green button of the one-spool card picks without a spool of its
  // own: it means the spool in the row above it.
  if (s_action == UA_LINK_PICK) s_action_id = s_cands[0].id;
  logSDf("BTN: UnknownSpool -> %d", (int)s_action);
}

// A spool of the suggestion. Its id rides along, not an index: the list it
// came from is gone, the link list is built afresh from the cache.
static void onSpool(lv_event_t* e) {
  s_action_id = (int)(intptr_t)lv_event_get_user_data(e);
  s_action = UA_LINK_PICK;
  logSDf("BTN: UnknownSpool -> spool %d", s_action_id);
}

// ------------------------------------------------------------
//  Building blocks
// ------------------------------------------------------------

static lv_obj_t* label(lv_obj_t* p, const char* text, const lv_font_t* font, uint32_t color) {
  lv_obj_t* l = lv_label_create(p);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(color), 0);
  return l;
}

static void centredLine(lv_obj_t* box, const char* text, const lv_font_t* font,
                        uint32_t color, int y) {
  lv_obj_t* l = label(box, text, font, color);
  lv_obj_set_size(l, UNK_TEXT_W, lv_font_get_line_height(font));
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
  lv_obj_align(l, LV_ALIGN_TOP_MID, 0, y);
}

static lv_obj_t* swatch(lv_obj_t* p, int size) {
  lv_obj_t* sw = lv_obj_create(p);
  lv_obj_set_size(sw, size, size);
  lv_obj_set_style_radius(sw, UI_RADIUS_INPUT, 0);
  lv_obj_set_style_border_width(sw, 1, 0);
  lv_obj_set_style_border_color(sw, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_pad_all(sw, 0, 0);
  lv_obj_clear_flag(sw, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(sw, LV_OBJ_FLAG_CLICKABLE);
  return sw;
}

// A tag without a colour: an empty square with a question mark.
static void swatchUnknown(lv_obj_t* sw) {
  lv_obj_set_style_bg_color(sw, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_border_color(sw, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_t* q = label(sw, T(STR_UNK_NO_COLOR), UI_FONT_SMALL, UI_COL_INK_SOFT);
  lv_obj_center(q);
}

// A tappable surface in the quiet look of the entry tiles.
static lv_obj_t* surface(lv_obj_t* p, int x, int y, int w, int h, bool framed_good) {
  lv_obj_t* b = lv_btn_create(p);
  lv_obj_set_size(b, w, h);
  lv_obj_set_pos(b, x, y);
  lv_obj_set_style_radius(b, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_pad_all(b, 0, 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(b, framed_good ? 2 : 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(framed_good ? UI_COL_GOOD : UI_COL_LINE), 0);
  return b;
}

// An answer: the suggested step in green, the others quiet. "Just weigh" is
// one of them, not a red Cancel - weighing a spool without filing it is a
// fine thing to do, nothing is being abandoned.
static lv_obj_t* answer(lv_obj_t* box, int x, int w, int text_id, UnkAction a, bool primary) {
  lv_obj_t* b = surface(box, x, UNK_ANSWER_Y, w, UI_POPUP_BTN_H, false);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  if (primary) {
    lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_OK_BG), 0);
    lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_OK_BG_PRESSED), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(b, 0, 0);
  }
  lv_obj_add_event_cb(b, onAction, LV_EVENT_CLICKED, (void*)(intptr_t)a);
  lv_obj_t* l = label(b, T(text_id), primary ? UI_FONT_TITLE : UI_FONT_BODY,
                      primary ? UI_COL_OK_TEXT : UI_COL_INK_2);
  lv_obj_center(l);
  return b;
}

// The countdown of a held spool, as the lighter fill the other questions
// drain, inside the border and behind the label.
static void addHeldFill(lv_obj_t* btn, int w) {
  const lv_coord_t border = lv_obj_get_style_border_width(btn, LV_PART_MAIN);
  s_held_fill_full = w - 2 * border;
  s_held_fill = lv_obj_create(btn);
  lv_obj_remove_style_all(s_held_fill);
  lv_obj_set_size(s_held_fill, s_held_fill_full, UI_POPUP_BTN_H - 2 * border);
  lv_obj_set_pos(s_held_fill, 0, 0);
  lv_obj_set_style_bg_color(s_held_fill, lv_color_hex(UI_COL_COUNTDOWN_FILL), 0);
  lv_obj_set_style_bg_opa(s_held_fill, LV_OPA_COVER, 0);
  lv_obj_set_style_radius(s_held_fill, UI_RADIUS_BTN, 0);
  lv_obj_clear_flag(s_held_fill, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_move_to_index(s_held_fill, 0);
  s_held_fill_w = s_held_fill_full;
}

// The way out. On the pad that is "Just weigh"; for a spool only held up there
// is nothing to weigh, so it is Cancel, with the time left in it.
static void answerOut(lv_obj_t* box, int x, int w) {
  if (!s_held) {
    answer(box, x, w, STR_UNK_BTN_WEIGH, UA_WEIGH, false);
    return;
  }
  lv_obj_t* cancel = answer(box, x, w, STR_CANCEL, UA_CANCEL, false);
  styleLeaveButton(cancel);   // first: the fill sits inside its border
  addHeldFill(cancel, w);
}

// The suggested step, "Other ways" and the way out, one width each.
static void answerRow(lv_obj_t* box, int text_id, UnkAction a) {
  const int w = (UNK_ROW_W - 2 * UNK_GAP) / 3;
  answer(box, UNK_X, w, text_id, a, true);
  answer(box, UNK_X + w + UNK_GAP, w, STR_UNK_BTN_OTHER, UA_OTHER, false);
  answerOut(box, UNK_X + 2 * (w + UNK_GAP), w);
}

// ------------------------------------------------------------
//  The head: what lies on the pad
// ------------------------------------------------------------

// " | " between the parts that are there.
static void appendPart(char* out, size_t n, const char* part) {
  if (!part || !part[0]) return;
  const size_t len = strlen(out);
  snprintf(out + len, n - len, "%s%s", len ? " | " : "", part);
}

// The filament on the pad: net when the empty spool is known, else all of it.
static void weightPart(char* out, size_t n, int core_g) {
  out[0] = '\0';
  if (!g_scale_fitted || !scale_ready || scale_weight_g <= 0.0f) return;
  if (core_g > 0 && scale_weight_g > (float)core_g)
    snprintf(out, n, T(STR_UNK_NET), scale_weight_g - (float)core_g);
  else
    snprintf(out, n, T(STR_UNK_GROSS), scale_weight_g);
}

static void identityRow(lv_obj_t* box, const char* name, const TagCreateInput* in) {
  lv_obj_t* row = lv_obj_create(box);
  lv_obj_remove_style_all(row);
  lv_obj_set_size(row, UNK_TEXT_W, UNK_IDENT_H);
  lv_obj_align(row, LV_ALIGN_TOP_MID, 0, UNK_IDENT_Y);
  lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(row, UNK_GAP, 0);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t* sw = swatch(row, UNK_SWATCH_HEAD);
  if (!s_bambu) {
    swatchUnknown(sw);
  } else {
    swatchPaint(sw, g_tag.color);
    // A gradient or dual colour spool: its first two colours, as on the
    // new-from-tag card.
    if (in && in->color_count >= 2) {
      lv_obj_set_style_bg_grad_color(sw, lv_color_hex(strtoul(in->colors_hex[1], nullptr, 16)), 0);
      lv_obj_set_style_bg_grad_dir(sw, LV_GRAD_DIR_VER, 0);
    }
  }
  lv_obj_t* l = labelOneLine(row, name, UI_FONT_TITLE, UNK_TEXT_W - UNK_SWATCH_HEAD - UNK_GAP);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK), 0);
}

static void buildHead(lv_obj_t* box) {
  char title[48];
  backendText(T(STR_NOT_IN_SPOOLMAN), title, sizeof(title));
  centredLine(box, title, UI_FONT_HEADLINE, UI_COL_INK, UNK_TITLE_Y);

  TagCreateInput in;
  const bool known = s_bambu && tagCreateInputFromTag(&in);
  char name[80], meta[96] = "", weight[32];
  if (known && in.product[0])
    joinMaterialName(in.product, in.color_name, name, sizeof(name));
  else if (s_bambu)
    snprintf(name, sizeof(name), "%s", g_tag.material);
  else
    snprintf(name, sizeof(name), T(STR_UNK_UID), link_tag_uid);
  identityRow(box, name, known ? &in : nullptr);

  weightPart(weight, sizeof(weight), known ? in.spool_weight_g : 0);
  if (s_bambu) appendPart(meta, sizeof(meta), known ? in.vendor : g_tag.vendor);
  if (known)   appendPart(meta, sizeof(meta), in.article);
  appendPart(meta, sizeof(meta), weight);
  centredLine(box, meta, UI_FONT_SMALL, UI_COL_INK_SOFT, UNK_META_Y);
}

// ------------------------------------------------------------
//  The middle: the suggestion
// ------------------------------------------------------------

// What the spool weighs on file, with a tick when the scale agrees: the tick
// says it to those who cannot tell the green from the grey. The row says the
// grams as the list row does, "new" included for a spool never weighed, and
// where they come from; a chip has room for the grams alone.
static void storedText(char* out, size_t n, const LinkCandidate& c, bool long_form) {
  char grams[24], line[64];
  if (long_form && c.unused) snprintf(grams, sizeof(grams), T(STR_NEW_SPOOL_WEIGHT_FMT), c.weight_g);
  else                       snprintf(grams, sizeof(grams), "%.0f g", c.weight_g);
  if (long_form) snprintf(line, sizeof(line), T(c.weight_hit ? STR_UNK_STORED_HIT : STR_UNK_STORED), grams);
  else           snprintf(line, sizeof(line), "%s", grams);
  if (c.weight_hit) snprintf(out, n, LV_SYMBOL_OK " %s", line);
  else              snprintf(out, n, "%s", line);
}

static void buildOne(lv_obj_t* box) {
  const LinkCandidate& c = s_cands[0];
  centredLine(box, T(STR_UNK_SUGGEST_ONE), UI_FONT_SMALL, UI_COL_INK_SOFT, UNK_CAPTION_Y);
  lv_obj_t* r = surface(box, UNK_X, UNK_MID_Y, UNK_ROW_W, UNK_MID_H, true);
  lv_obj_add_event_cb(r, onSpool, LV_EVENT_CLICKED, (void*)(intptr_t)c.id);

  lv_obj_t* sw = swatch(r, UNK_SWATCH_ROW);
  swatchPaintHex(sw, c.color_hex);
  lv_obj_align(sw, LV_ALIGN_LEFT_MID, UNK_X, 0);

  char id[12], sub[64];
  snprintf(id, sizeof(id), "#%d", c.id);
  // On the name's line, so the weight below has the whole width: "1000 g"
  // and the tick would not fit beside the id.
  lv_obj_t* l3 = label(r, id, UI_FONT_BODY, UI_COL_INK_2);
  lv_obj_align(l3, LV_ALIGN_TOP_RIGHT, -UNK_X, UNK_LINE1_Y);
  lv_obj_t* l1 = label(r, c.name, UI_FONT_BODY, UI_COL_INK);
  lv_label_set_long_mode(l1, LV_LABEL_LONG_DOT);
  // The height too: with only a width a long name wraps onto the line below.
  lv_obj_set_size(l1, UNK_ROW_W - UNK_TEXT_X - UNK_X - UNK_ID_W, lv_font_get_line_height(UI_FONT_BODY));
  lv_obj_set_pos(l1, UNK_TEXT_X, UNK_LINE1_Y);
  storedText(sub, sizeof(sub), c, true);
  lv_obj_t* l2 = label(r, sub, UI_FONT_SMALL, c.weight_hit ? UI_COL_GOOD : UI_COL_INK_SOFT);
  lv_label_set_long_mode(l2, LV_LABEL_LONG_DOT);
  lv_obj_set_size(l2, UNK_ROW_W - UNK_TEXT_X - UNK_X, lv_font_get_line_height(UI_FONT_SMALL));
  lv_obj_set_pos(l2, UNK_TEXT_X, UNK_LINE2_Y);
  answerRow(box, STR_REMOTE_LINK_CONFIRM, UA_LINK_PICK);
}

static void buildChip(lv_obj_t* box, int slot, int w, const LinkCandidate& c) {
  lv_obj_t* chip = surface(box, UNK_X + slot * (w + UNK_GAP), UNK_MID_Y, w, UNK_MID_H, c.weight_hit);
  lv_obj_add_event_cb(chip, onSpool, LV_EVENT_CLICKED, (void*)(intptr_t)c.id);
  lv_obj_t* sw = swatch(chip, UNK_SWATCH_CHIP);
  swatchPaintHex(sw, c.color_hex);
  lv_obj_align(sw, LV_ALIGN_LEFT_MID, UNK_X - 2, 0);
  char id[12], grams[32];
  snprintf(id, sizeof(id), "#%d", c.id);
  lv_obj_t* l1 = label(chip, id, UI_FONT_BODY, UI_COL_INK);
  lv_obj_set_pos(l1, UNK_CHIP_TEXT_X, UNK_LINE1_Y);
  storedText(grams, sizeof(grams), c, false);
  lv_obj_t* l2 = label(chip, grams, UI_FONT_SMALL, c.weight_hit ? UI_COL_GOOD : UI_COL_INK_SOFT);
  lv_obj_set_pos(l2, UNK_CHIP_TEXT_X, UNK_LINE2_Y);
}

// Up to three chips; with more spools than that, two and a third that opens
// the list with all of them.
static void buildMany(lv_obj_t* box) {
  char caption[64];
  snprintf(caption, sizeof(caption), T(STR_UNK_SUGGEST_MANY), s_cand_total);
  centredLine(box, caption, UI_FONT_SMALL, UI_COL_INK_SOFT, UNK_CAPTION_Y);
  const int w = (UNK_ROW_W - (UNK_CHIPS - 1) * UNK_GAP) / UNK_CHIPS;
  const bool more = s_cand_total > UNK_CHIPS;
  const int shown = more ? UNK_CHIPS - 1 : s_cand_total;
  for (int i = 0; i < shown; i++) buildChip(box, i, w, s_cands[i]);
  if (more) {
    lv_obj_t* chip = surface(box, UNK_X + shown * (w + UNK_GAP), UNK_MID_Y, w, UNK_MID_H, false);
    lv_obj_add_event_cb(chip, onAction, LV_EVENT_CLICKED, (void*)(intptr_t)UA_LINK_LIST);
    char text[24];
    snprintf(text, sizeof(text), T(STR_UNK_MORE), s_cand_total - shown);
    lv_obj_center(label(chip, text, UI_FONT_BODY, UI_COL_ACCENT));
  }
  answerRow(box, STR_UNK_BTN_ALL, UA_LINK_LIST);
}

static void buildCreate(lv_obj_t* box) {
  centredLine(box, T(STR_UNK_SUGGEST_NEW), UI_FONT_SMALL, UI_COL_INK_SOFT, UNK_CAPTION_Y);
  lv_obj_t* note = surface(box, UNK_X, UNK_MID_Y, UNK_ROW_W, UNK_MID_H, false);
  lv_obj_add_event_cb(note, onAction, LV_EVENT_CLICKED, (void*)(intptr_t)UA_CREATE);
  lv_obj_t* ic = label(note, LV_SYMBOL_PLUS, UI_FONT_ICON, UI_COL_ACCENT);
  lv_obj_align(ic, LV_ALIGN_LEFT_MID, UNK_X + 4, 0);
  lv_obj_t* l1 = label(note, T(STR_UNK_NONE_LINE), UI_FONT_BODY, UI_COL_INK);
  lv_obj_set_pos(l1, UNK_TEXT_X, UNK_LINE1_Y);
  lv_obj_t* l2 = label(note, T(STR_UNK_NONE_SUB), UI_FONT_SMALL, UI_COL_ACCENT);
  lv_obj_set_pos(l2, UNK_TEXT_X, UNK_LINE2_Y);
  answerRow(box, STR_COPY_CARD_CREATE, UA_CREATE);
}

static void tile(lv_obj_t* box, int i, int n, const char* symbol, int text_id, UnkAction a) {
  const int w = (UNK_ROW_W - (n - 1) * UNK_GAP) / n;
  lv_obj_t* t = surface(box, UNK_X + i * (w + UNK_GAP), UNK_TILE_Y, w, UNK_TILE_H, false);
  lv_obj_add_event_cb(t, onAction, LV_EVENT_CLICKED, (void*)(intptr_t)a);
  lv_obj_t* s = label(t, symbol, UI_FONT_ICON, UI_COL_ACCENT);
  lv_obj_align(s, LV_ALIGN_TOP_MID, 0, UNK_TILE_SYMBOL_Y);
  lv_obj_t* c = label(t, T(text_id), UI_FONT_BODY, UI_COL_INK_2);
  lv_obj_set_width(c, w - UNK_X);
  lv_obj_set_style_text_align(c, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(c, LV_LABEL_LONG_WRAP);
  lv_obj_align(c, LV_ALIGN_TOP_MID, 0, UNK_TILE_TEXT_Y);
}

// Every way in, none suggested: the tag says nothing about the spool, or the
// spool cache could not say which spool it might be.
static void buildTiles(lv_obj_t* box) {
  const bool from_tag = s_bambu && tagCreateOffered();
  const bool from_db  = !s_bambu && dbPickOffered();
  const int n = (from_tag || from_db) ? 3 : 2;
  int i = 0;
  tile(box, i++, n, LV_SYMBOL_LIST, STR_REMOTE_LINK_CONFIRM, UA_LINK_ENTRY);
  if (from_tag) tile(box, i++, n, LV_SYMBOL_PLUS, STR_NEWTAG_BTN, UA_CREATE);
  if (from_db)  tile(box, i++, n, LV_SYMBOL_PLUS, STR_DBPICK_BTN, UA_DB);
  tile(box, i, n, LV_SYMBOL_COPY, STR_UNK_TILE_COPY, UA_COPY);
  answerOut(box, UNK_X, UNK_ROW_W);
}

static void buildCard(UnkMode mode) {
  closeUnknownSpoolPopup();
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
  lv_obj_set_size(box, UNK_BOX_W, UNK_BOX_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  buildHead(box);
  switch (mode) {
    case UNK_ONE:    buildOne(box);    break;
    case UNK_MANY:   buildMany(box);   break;
    case UNK_CREATE: buildCreate(box); break;
    default:         buildTiles(box);  break;
  }
  logSDf("SHOW: UnknownSpool mode=%d bambu=%d candidates=%d", (int)mode, (int)s_bambu,
         s_cand_total);
}

// ------------------------------------------------------------
//  The loop's part
// ------------------------------------------------------------

// Which card the spool gets. The candidates cost one stamp request and are
// read from the spool cache, which the lookup's own scan has just filled.
static UnkMode chooseMode() {
  s_cand_total = 0;
  if (!s_bambu) return UNK_TILES;
  const int total = linkSuggestCandidates(s_cands, UNK_CHIPS);
  if (total < 0) return UNK_TILES;
  s_cand_total = total;
  if (total == 1) return UNK_ONE;
  if (total > 1)  return UNK_MANY;
  return tagCreateOffered() ? UNK_CREATE : UNK_TILES;
}

static void openOffered() {
  if (!g_unk_ask || !wifi_ok || !lookupUnknownIsCertain() ||
      !stillUnknown(s_offer_bambu, s_offer_key)) {
    s_offer_pending = false;
    return;
  }
  if (!weightReady()) return;
  s_offer_pending = false;
  if (uiMainScreenCovered()) {
    logSD("UnknownSpool: the main screen is covered, not asked");
    return;
  }
  s_bambu = s_offer_bambu;
  snprintf(s_asked_key, sizeof(s_asked_key), "%s", s_offer_key);
  s_held = !g_scale_fitted || scale_weight_g < UNK_HELD_BELOW_G;
  s_held_ms = millis();
  snprintf(s_held_uid, sizeof(s_held_uid), "%s", g_tag.uid_str);
  if (s_held) logSDf("UnknownSpool: %.0fg on the pad, the spool is held up", scale_weight_g);
  buildCard(chooseMode());
}

// A held spool's card counts down and then closes as if Cancel was tapped.
static void heldTick() {
  if (!s_scr || !s_held) return;
  const uint32_t elapsed = millis() - s_held_ms;
  const uint32_t left = elapsed >= UNK_HELD_MS ? 0 : UNK_HELD_MS - elapsed;
  uiCountdownFillSet(s_held_fill, s_held_fill_full, &s_held_fill_w, left, UNK_HELD_MS);
  if (left > 0) return;
  logSDf("UnknownSpool: nothing chosen in %lu s, card closed", UNK_HELD_MS / 1000UL);
  s_action = UA_NONE;
  closeUnknownSpoolPopup();
}

// Every way out closes the card first; the flow it leads to builds its own.
static void runAction() {
  const UnkAction a = s_action;
  s_action = UA_NONE;
  if (a == UA_OTHER) {
    s_cand_total = 0;
    buildCard(UNK_TILES);
    return;
  }
  closeUnknownSpoolPopup();
  copyTaglessEnd("a tag's flow");
  switch (a) {
    case UA_LINK_PICK:  linkSuggestOpenList(s_action_id);  break;
    case UA_LINK_LIST:  linkSuggestOpenList(0);            break;
    case UA_CREATE:     newtag_open_pending = true;        break;
    case UA_LINK_ENTRY: showLinkEntryPopup(s_bambu);       break;
    case UA_DB:         dbPickEntryTap(nullptr);           break;
    case UA_COPY:       showCopyEntryPopup();              break;
    default:            break;
  }
}

void unknownSpoolTick() {
  if (s_scr && !cardStillFits()) {
    logSD("UnknownSpool: the spool was found or replaced, card closed");
    s_action = UA_NONE;
    closeUnknownSpoolPopup();
  }
  if (s_action != UA_NONE && s_scr) runAction();
  s_action = UA_NONE;
  heldTick();
  if (s_offer_pending) openOffered();
}
