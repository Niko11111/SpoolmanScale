#include "ui/spool_id_pad.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app/app_state.h"
#include "app/id_spool.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/server_reach.h"
#include "services/server_refusal.h"
#include "services/spool_color.h"
#include "ui/copy_tagless.h"
#include "ui/theme.h"
#include "ui/ui_common.h"
#include "ui/weight_format.h"

// Six digits: more spools than any inventory holds, and what the box shows whole.
#define SIP_ID_MAX_DIGITS   6
#define SIP_TIMEOUT_MS      8000

// The price pad's geometry (price_pad.cpp): keys on the left, the value above
// them, the answer column on the right.
#define SIP_KEY_W    90
#define SIP_KEY_H    48
#define SIP_GAP       6
#define SIP_EDGE     10
#define SIP_TOP_Y    38
#define SIP_KEYS_Y  100
#define SIP_PAD_W   (3 * SIP_KEY_W + 2 * SIP_GAP)
#define SIP_COL_X   (SIP_EDGE + SIP_PAD_W + SIP_EDGE)
#define SIP_COL_W   (480 - SIP_COL_X - SIP_EDGE)
#define SIP_BOTTOM_Y (SIP_KEYS_Y + 4 * SIP_KEY_H + 3 * SIP_GAP)
#define SIP_CANCEL_H (UI_TOUCH_MIN + 10)
#define SIP_CARD_H  150
#define SIP_SWATCH  44
#define SIP_NAME_Y  62   // under the swatch row
#define SIP_LINE_GAP 4
// The action button sits at the same place in every state, under the card.
#define SIP_ACTION_Y (SIP_TOP_Y + SIP_CARD_H + SIP_GAP)
#define SIP_ACTION_H (SIP_BOTTOM_Y - SIP_CANCEL_H - SIP_GAP - SIP_ACTION_Y)

enum SipState : uint8_t { SIP_EDIT, SIP_SEARCHING, SIP_FOUND, SIP_NOT_FOUND, SIP_FAILED };
enum SipAnswer : uint8_t { SIP_NONE, SIP_ACTION, SIP_NEW, SIP_CANCEL };

// What the pad shows of a spool it found: just enough to recognise it.
struct SipSpool {
  int        id;
  char       material[24];
  char       vendor[40];
  char       name[64];
  SpoolColor color;
  float      remaining_g;   // < 0: never weighed
  bool       archived;
};

static lv_obj_t*  s_pad       = nullptr;
static lv_obj_t*  s_col       = nullptr;   // the answer column, rebuilt per state
static lv_obj_t*  s_lbl_input = nullptr;
static char       s_input[SIP_ID_MAX_DIGITS + 1] = "";
static SipState   s_state     = SIP_EDIT;
static SipAnswer  s_answer    = SIP_NONE;
static bool       s_col_dirty = false;
static bool       s_search_due = false;
static int        s_searched_id = 0;
static int        s_fail_code = 0;     // the code behind SIP_FAILED
static SipSpool   s_spool;
static void     (*s_done)(int) = nullptr;
static void     (*s_on_new)()  = nullptr;

bool spoolIdPadOpen() { return s_pad != nullptr; }

void closeSpoolIdPad() {
  // Hidden now, freed on the next pass: hideAllOverlays() reaches this from
  // the callbacks of whatever rose over the pad.
  releaseScreen(&s_pad);
  s_col = nullptr;
  s_lbl_input = nullptr;
  s_answer = SIP_NONE;
  s_search_due = false;
}

static void refreshInput() {
  if (!s_lbl_input) return;
  char buf[SIP_ID_MAX_DIGITS + 4];
  snprintf(buf, sizeof(buf), "# %s", s_input);
  lv_label_set_text(s_lbl_input, buf);
}

// Any edit makes an answer on the right stale: it was for another number.
// An empty field offers a new spool instead of the search, so the button
// changes too when the field empties or fills.
static void inputChanged(bool was_empty) {
  refreshInput();
  const bool empty_flipped = (was_empty != (s_input[0] == '\0')) && s_on_new;
  if (s_state != SIP_EDIT || empty_flipped) {
    s_state = SIP_EDIT;
    s_col_dirty = true;
  }
}

static void onKey(lv_event_t* e) {
  lv_obj_t* lbl = lv_obj_get_child(lv_event_get_target(e), 0);
  const char* ch = lv_label_get_text(lbl);
  const size_t len = strlen(s_input);
  if (len >= SIP_ID_MAX_DIGITS) return;
  if (len == 0 && ch[0] == '0') return;   // ids start at 1
  s_input[len] = ch[0];
  s_input[len + 1] = '\0';
  inputChanged(len == 0);
}

static void onBackspace(lv_event_t*) {
  const size_t len = strlen(s_input);
  if (len) s_input[len - 1] = '\0';
  inputChanged(len == 0);
}

static lv_obj_t* colText(lv_obj_t* parent, const char* text, int y, uint32_t col, const lv_font_t* font,
                         lv_label_long_mode_t mode) {
  lv_obj_t* l = lv_label_create(parent);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_color(l, lv_color_hex(col), 0);
  lv_obj_set_style_text_font(l, font, 0);
  lv_label_set_long_mode(l, mode);
  lv_obj_set_width(l, SIP_COL_W - 2 * SIP_EDGE);
  // A dotted label only cuts once its height is bounded; without one it wraps
  // like any other and runs into the line below.
  if (mode == LV_LABEL_LONG_DOT) lv_obj_set_height(l, lv_font_get_line_height(font));
  lv_obj_set_pos(l, SIP_EDGE, y);
  return l;
}

static lv_obj_t* buildCard() {
  lv_obj_t* c = lv_obj_create(s_col);
  lv_obj_set_size(c, SIP_COL_W, SIP_CARD_H);
  lv_obj_set_pos(c, 0, 0);
  lv_obj_set_style_bg_color(c, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(c, lv_color_hex(UI_COL_LINE_SOFT), 0);
  lv_obj_set_style_border_width(c, 1, 0);
  lv_obj_set_style_radius(c, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(c, 0, 0);
  lv_obj_clear_flag(c, LV_OBJ_FLAG_SCROLLABLE);
  return c;
}

static void buildFoundCard() {
  lv_obj_t* c = buildCard();
  lv_obj_t* sw = lv_obj_create(c);
  lv_obj_set_size(sw, SIP_SWATCH, SIP_SWATCH);
  lv_obj_set_pos(sw, SIP_EDGE, SIP_EDGE);
  lv_obj_set_style_radius(sw, UI_RADIUS_BTN, 0);
  lv_obj_set_style_border_width(sw, 1, 0);
  lv_obj_set_style_border_color(sw, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_clear_flag(sw, LV_OBJ_FLAG_SCROLLABLE);
  swatchPaint(sw, s_spool.color);

  const int text_x = 2 * SIP_EDGE + SIP_SWATCH;
  const int text_w = SIP_COL_W - text_x - SIP_EDGE;
  lv_obj_t* mat = colText(c, s_spool.material[0] ? s_spool.material : "-", 8, UI_COL_INK, UI_FONT_TITLE,
                          LV_LABEL_LONG_DOT);
  lv_obj_set_pos(mat, text_x, 8);
  lv_obj_set_width(mat, text_w);
  lv_obj_t* ven = colText(c, s_spool.vendor, 32, UI_COL_CAPTION, UI_FONT_CAPTION, LV_LABEL_LONG_DOT);
  lv_obj_set_pos(ven, text_x, 32);
  lv_obj_set_width(ven, text_w);

  // Up to two lines for the name: "Matte - Scarlet Red (11200)" is what tells
  // two spools of one material apart. A third line is cut, and what follows
  // moves down by as much as the name took.
  lv_obj_t* name = colText(c, s_spool.name[0] ? s_spool.name : "-", SIP_NAME_Y, UI_COL_INK, UI_FONT_BODY,
                           LV_LABEL_LONG_WRAP);
  const lv_coord_t two_lines = 2 * lv_font_get_line_height(UI_FONT_BODY);
  lv_obj_update_layout(name);
  lv_coord_t name_h = lv_obj_get_height(name);
  if (name_h > two_lines) {
    lv_label_set_long_mode(name, LV_LABEL_LONG_DOT);
    lv_obj_set_height(name, two_lines);
    name_h = two_lines;   // the new height only lands with the next layout pass
  }
  int y = SIP_NAME_Y + name_h + SIP_LINE_GAP;
  char grams[24] = "-";
  if (s_spool.remaining_g >= 0) fmtG(grams, sizeof(grams), s_spool.remaining_g);
  colText(c, grams, y, UI_COL_GOOD, UI_FONT_SMALL, LV_LABEL_LONG_DOT);
  y += lv_font_get_line_height(UI_FONT_SMALL) + SIP_LINE_GAP;
  if (s_spool.archived) colText(c, T(STR_ARCHIVED), y, UI_COL_ARCHIVED, UI_FONT_CAPTION, LV_LABEL_LONG_DOT);
}

static void buildMessageCard(const char* head, uint32_t head_col, const char* hint) {
  lv_obj_t* c = buildCard();
  colText(c, head, 12, head_col, UI_FONT_SMALL, LV_LABEL_LONG_WRAP);
  if (hint) colText(c, hint, 64, UI_COL_CAPTION, UI_FONT_CAPTION, LV_LABEL_LONG_WRAP);
}

// Search and confirm share one button, at one place: what it says follows
// the state, what it does is decided in the tick.
static void buildAction(int text_id, uint32_t bg, uint32_t bg_pressed) {
  lv_obj_t* b = padButton(s_col, 0, SIP_ACTION_Y - SIP_TOP_Y, SIP_COL_W, SIP_ACTION_H, bg, bg_pressed);
  padLabel(b, T(text_id), UI_COL_OK_TEXT, UI_FONT_BODY);
  lv_obj_add_event_cb(b, [](lv_event_t*) { s_answer = SIP_ACTION; }, LV_EVENT_CLICKED, NULL);
}

// The same place for a new spool, in the house colour: a button that changes
// its colour with its meaning is seen to change when the first digit lands.
static void buildNewAction() {
  lv_obj_t* b = padButton(s_col, 0, SIP_ACTION_Y - SIP_TOP_Y, SIP_COL_W, SIP_ACTION_H, UI_COL_ACCENT,
                          uiShade(UI_COL_ACCENT, UI_SHADE_PRESSED));
  char text[48];
  snprintf(text, sizeof(text), LV_SYMBOL_PLUS " %s", T(STR_IDPAD_NEW));
  padLabel(b, text, UI_COL_ON_ACCENT, UI_FONT_BODY);
  lv_obj_add_event_cb(b, [](lv_event_t*) { s_answer = SIP_NEW; }, LV_EVENT_CLICKED, NULL);
}

// Room for the info text, the longest that lands here, with the backend name
// substituted and in French.
#define SIP_TEXT_MAX 224

static void buildColumn() {
  lv_obj_clean(s_col);
  char buf[SIP_TEXT_MAX];
  switch (s_state) {
    case SIP_EDIT:
      backendText(T(STR_IDPAD_INFO), buf, sizeof(buf));
      colText(s_col, buf, 0, UI_COL_CAPTION, UI_FONT_CAPTION, LV_LABEL_LONG_WRAP);
      if (!s_input[0] && s_on_new) buildNewAction();
      else buildAction(STR_IDPAD_SEARCH, UI_COL_GO_BG, UI_COL_GO_BG_PRESSED);
      break;
    case SIP_SEARCHING:
      buildMessageCard(T(STR_IDPAD_SEARCHING), UI_COL_CAPTION, nullptr);
      break;
    case SIP_FOUND:
      buildFoundCard();
      buildAction(STR_IDPAD_THIS_SPOOL, UI_COL_OK_BG, UI_COL_OK_BG_PRESSED);
      break;
    case SIP_NOT_FOUND:
      snprintf(buf, sizeof(buf), T(STR_IDPAD_NOT_FOUND), s_searched_id);
      buildMessageCard(buf, UI_COL_WARN, T(STR_IDPAD_NOT_FOUND_HINT));
      break;
    case SIP_FAILED:
      // A server that answered "no" is named for what it said, not as one
      // that is down.
      if (serverRefusalOf(s_fail_code) != REFUSAL_NONE) {
        snprintf(buf, sizeof(buf), "%s", T(serverRefusalTitleId(serverRefusalOf(s_fail_code))));
      } else {
        backendText(T(STR_NO_CONNECTION_TO), buf, sizeof(buf));
      }
      buildMessageCard(buf, UI_COL_WARN, nullptr);
      buildAction(STR_IDPAD_SEARCH, UI_COL_GO_BG, UI_COL_GO_BG_PRESSED);
      break;
  }
}

static void buildHead() {
  lv_obj_t* title = lv_label_create(s_pad);
  lv_label_set_text(title, T(STR_BTN_SPOOL_BY_ID));
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(title, UI_FONT_SMALL, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

  lv_obj_t* box = lv_obj_create(s_pad);
  lv_obj_set_size(box, SIP_PAD_W, 52);
  lv_obj_set_pos(box, SIP_EDGE, SIP_TOP_Y);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_INPUT, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);
  s_lbl_input = lv_label_create(box);
  lv_obj_set_style_text_color(s_lbl_input, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(s_lbl_input, UI_FONT_ICON, 0);
  lv_obj_center(s_lbl_input);
}

// The slot left of 0 stays empty: an id has no point, and a clear key next to
// the digits would wipe a number by accident.
static void buildKeys() {
  static const char* const KEYS[12] = { "1","2","3","4","5","6","7","8","9","","0",LV_SYMBOL_BACKSPACE };
  for (int i = 0; i < 12; i++) {
    if (!KEYS[i][0]) continue;
    const int x = SIP_EDGE + (i % 3) * (SIP_KEY_W + SIP_GAP);
    const int y = SIP_KEYS_Y + (i / 3) * (SIP_KEY_H + SIP_GAP);
    lv_obj_t* b = padButton(s_pad, x, y, SIP_KEY_W, SIP_KEY_H, UI_COL_SURFACE, UI_COL_LINE);
    const bool del = (i == 11);
    padLabel(b, KEYS[i], del ? UI_COL_INK_2 : UI_COL_INK, del ? UI_FONT_BODY : UI_FONT_HEADLINE);
    lv_obj_add_event_cb(b, del ? onBackspace : onKey, LV_EVENT_CLICKED, NULL);
  }
}

static void buildCancel() {
  lv_obj_t* no = padButton(s_pad, SIP_COL_X, SIP_BOTTOM_Y - SIP_CANCEL_H, SIP_COL_W, SIP_CANCEL_H,
                           UI_COL_BAD_BG, UI_COL_BAD_BG_PRESSED);
  padLabel(no, T(STR_CANCEL), UI_COL_BAD_TEXT, UI_FONT_SMALL);
  styleLeaveButton(no);
  lv_obj_add_event_cb(no, [](lv_event_t*) { s_answer = SIP_CANCEL; }, LV_EVENT_CLICKED, NULL);
}

void showSpoolIdPad(void (*done)(int spool_id), void (*on_new)()) {
  logSD("SHOW: SpoolIdPad");
  closeSpoolIdPad();
  s_done = done;
  s_on_new = on_new;
  s_input[0] = '\0';
  s_state = SIP_EDIT;

  s_pad = buildOverlayScreen();
  lv_obj_clear_flag(s_pad, LV_OBJ_FLAG_HIDDEN);

  s_col = lv_obj_create(s_pad);
  lv_obj_set_size(s_col, SIP_COL_W, SIP_BOTTOM_Y - SIP_CANCEL_H - SIP_GAP - SIP_TOP_Y);
  lv_obj_set_pos(s_col, SIP_COL_X, SIP_TOP_Y);
  lv_obj_set_style_bg_opa(s_col, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(s_col, 0, 0);
  lv_obj_set_style_pad_all(s_col, 0, 0);
  lv_obj_clear_flag(s_col, LV_OBJ_FLAG_SCROLLABLE);

  buildHead();
  buildKeys();
  buildCancel();
  buildColumn();
  refreshInput();
}

// The spool as the server has it, read into what the card shows. One request:
// the colour lives on the filament, which the spool answer carries anyway.
static SipState fetchSpool(int id) {
  JsonDocument doc;
  const int code = backendGetSpoolJson(cfg_spoolman_base, id, doc, SIP_TIMEOUT_MS);
  if (code == 404) return SIP_NOT_FOUND;
  if (code != 200) {
    logSDf("SpoolIdPad: spool %d not readable, code %d", id, code);
    s_fail_code = code;
    // A refusal asks for its popup there, as in every other flow. Only a
    // refusal: a server that is down keeps the pad's own line, as before.
    if (serverRefusalOf(code) != REFUSAL_NONE) serverReachNote(code, true);
    return SIP_FAILED;
  }
  JsonObjectConst sp = doc.as<JsonObjectConst>();
  JsonObjectConst fil = sp["filament"];
  s_spool = SipSpool{};
  s_spool.id = sp["id"] | id;
  snprintf(s_spool.material, sizeof(s_spool.material), "%s", fil["material"] | "");
  snprintf(s_spool.vendor, sizeof(s_spool.vendor), "%s", fil["vendor"]["name"] | "");
  snprintf(s_spool.name, sizeof(s_spool.name), "%s", fil["name"] | "");
  spoolColorParse(fil["color_hex"] | "", &s_spool.color);
  JsonVariantConst rem = sp["remaining_weight"];
  s_spool.remaining_g = rem.isNull() ? -1.0f : rem.as<float>();
  s_spool.archived = sp["archived"] | false;
  return SIP_FOUND;
}

static void startSearch() {
  if (!s_input[0]) return;
  s_searched_id = atoi(s_input);
  s_state = SIP_SEARCHING;
  s_col_dirty = true;
  s_search_due = true;
}

static void confirmSpool() {
  const int id = s_spool.id;
  void (*done)(int) = s_done;
  closeSpoolIdPad();
  logSDf("UI: spool by id %d confirmed", id);
  if (done) done(id);
}

void spoolIdPadTick() {
  if (!s_pad) return;
  // A tag put down while the id is typed is the better answer, and the
  // lookup's popups would rise over the pad: it steps aside.
  if (tag_present) {
    logSD("UI: spool by id closed, a tag is on the reader");
    closeSpoolIdPad();
    return;
  }
  const SipAnswer answer = s_answer;
  s_answer = SIP_NONE;
  if (answer == SIP_CANCEL) {
    logSD("UI: spool by id cancelled");
    closeSpoolIdPad();
    return;
  }
  if (answer == SIP_NEW && s_on_new) {
    void (*on_new)() = s_on_new;
    closeSpoolIdPad();
    on_new();
    return;
  }
  if (answer == SIP_ACTION) {
    if (s_state == SIP_FOUND) { confirmSpool(); return; }
    startSearch();
  }
  // Repainted first and asked on a later pass, so "Searching" is on the
  // panel while the request blocks the loop.
  if (s_col_dirty) {
    s_col_dirty = false;
    buildColumn();
    return;
  }
  if (s_search_due) {
    s_search_due = false;
    s_state = fetchSpool(s_searched_id);
    logSDf("SpoolIdPad: id %d -> state %d", s_searched_id, (int)s_state);
    s_col_dirty = true;
  }
}

lv_obj_t* buildSpoolByIdButton(lv_obj_t* bar) {
  lv_obj_t* b = lv_btn_create(bar);
  lv_obj_set_size(b, 202, 39);
  lv_obj_set_pos(b, 8, 8);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_WEIGHT_BG), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_WEIGHT_BG_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(b, 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_WEIGHT_BG_PRESSED), 0);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_add_flag(b, LV_OBJ_FLAG_HIDDEN);
  // Only opens the pad; the spool is fetched from the loop once confirmed.
  lv_obj_add_event_cb(b, [](lv_event_t*) {
    logSD("UI: Button -> Spool by ID");
    showSpoolIdPad(idSpoolAdopt, copyTaglessStart);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t* l = lv_label_create(b);
  char buf[48];
  snprintf(buf, sizeof(buf), LV_SYMBOL_KEYBOARD "  %s", T(STR_BTN_SPOOL_BY_ID));
  lv_label_set_text(l, buf);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_WEIGHT_TEXT), 0);
  lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
  lv_obj_center(l);
  return b;
}
