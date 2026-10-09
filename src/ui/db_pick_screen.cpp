#include "ui/db_pick_screen.h"

#include <Arduino.h>
#include <lvgl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// backend_api.h brings ArduinoJson, whose templates have a parameter T:
// before lang.h, which defines T().
#include "services/backend_api.h"
#include "services/filament_db.h"
#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui/link_wait_card.h"
#include "ui/spool_flow.h"
#include "ui/spool_flow_internal.h"
#include "ui/tag_create_popup.h"
#include "ui/theme.h"
#include "ui/ui_common.h"

// A list longer than this is cut by colour family first.
#define DBP_FAMILY_MIN_ROWS   20
// From this many makers on, a letter shows its makers instead of scrolling
// to them: the FilamentDB's 311 tiles would not fit the LVGL pool.
#define DBP_MAKER_FILTER_MIN  100
// Product lines a list is cut by (SUNLU PLA in the FilamentDB: 32).
#define DBP_LINES_MAX         48
// The frame: the header of the link lists, the list below it.
#define DBP_HEAD_H            52
#define DBP_HEAD_BTN          44
#define DBP_BODY_Y            (DBP_HEAD_H + 4)
#define DBP_BODY_W            460
#define DBP_BODY_H            (320 - DBP_BODY_Y)
#define DBP_GAP               4
// Inside a tile: little, so "REDLINE FILAMENT" fits a third of the width.
#define DBP_TILE_PAD          2
// Makers and materials: three tiles a row.
#define DBP_TILE_W            148
#define DBP_TILE_H            44
#define DBP_MAT_TILE_H        52
// Colour families: four a row, a strip of the colour above name and count.
#define DBP_FAM_TILE_W        110
#define DBP_FAM_TILE_H        56
#define DBP_FAM_STRIP_H       12
// The letters above the makers.
#define DBP_LETTER_H          36
#define DBP_LETTER_W          32
#define DBP_LETTERS           27     // one for digits and the rest, then A-Z
// Entry rows.
#define DBP_ROW_W             452
#define DBP_ROW_H             44
#define DBP_ROW_SWATCH        24
#define DBP_ROW_NAME_W        280
#define DBP_ROW_SIZES_W       120    // "1 kg / 3 kg / 5 kg"
// The size question: a button per size.
#define DBP_SIZE_BTN_H        44
#define DBP_SIZES_MAX         4
#define DBP_GRAMS_PER_KG      1000

enum DbpStep : uint8_t { DBP_CLOSED = 0, DBP_MAKER, DBP_MATERIAL, DBP_LINE, DBP_FAMILY, DBP_ENTRIES };
enum DbpNav : uint8_t {
  NAV_NONE = 0, NAV_OPEN, NAV_MAKER, NAV_MATERIAL, NAV_FAMILY, NAV_ENTRY,
  NAV_SIZE, NAV_SIZE_CANCEL, NAV_BACK, NAV_CLOSE, NAV_LETTER, NAV_LINE
};

static lv_obj_t* s_scr   = nullptr;
static lv_obj_t* s_title = nullptr;
static lv_obj_t* s_body  = nullptr;
static lv_obj_t* s_strip = nullptr;   // the letters, on the maker step only
static lv_obj_t* s_size  = nullptr;   // the size question, over the list
static DbpStep   s_step  = DBP_CLOSED;
static int       s_maker = -1;
static char      s_material[17] = "";
static int       s_family = -1;      // -1: every family
static bool      s_family_step = false;
// The product lines of the list: the first entry of each and its names.
static int16_t   s_line_first[DBP_LINES_MAX];
static uint16_t  s_line_count[DBP_LINES_MAX];
static int       s_line_n = 0;
static int       s_line = -1;        // -1: every line
static bool      s_line_step = false;
// The letter whose makers are shown, on a long maker list; -1: none yet.
static int       s_letter = -1;
// The load the screen waits for, and one that could not start yet.
static FdbJob    s_wait = FDB_JOB_NONE;
static FdbJob    s_want = FDB_JOB_NONE;
static DbpNav    s_nav = NAV_NONE;
static int       s_nav_arg = 0;
static lv_obj_t* s_letter_target[DBP_LETTERS];
static lv_obj_t* s_letter_btn[DBP_LETTERS];

// Shared styles. A list of 67 makers is some 140 objects, and every local
// style property is an allocation of its own in the LVGL pool: with local
// styles the pool ran low at tile 62 in the simulator.
static lv_style_t s_st_tile, s_st_tile_pressed, s_st_letter, s_st_swatch;
static lv_style_t s_st_text, s_st_text_body, s_st_text_soft;
static bool       s_styles_ready = false;

// Once, after boot: the palette is chosen at boot and fixed until a restart.
static void initStyles() {
  if (s_styles_ready) return;
  lv_style_init(&s_st_tile);
  lv_style_set_bg_opa(&s_st_tile, LV_OPA_COVER);
  lv_style_set_bg_color(&s_st_tile, lv_color_hex(UI_COL_SURFACE));
  lv_style_set_radius(&s_st_tile, UI_RADIUS_BTN);
  lv_style_set_shadow_width(&s_st_tile, 0);
  lv_style_set_border_width(&s_st_tile, 1);
  lv_style_set_border_color(&s_st_tile, lv_color_hex(UI_COL_LINE));
  lv_style_set_pad_all(&s_st_tile, DBP_TILE_PAD);
  lv_style_init(&s_st_tile_pressed);
  lv_style_set_bg_color(&s_st_tile_pressed, lv_color_hex(UI_COL_PRESS_FILL));
  lv_style_init(&s_st_letter);
  lv_style_set_bg_opa(&s_st_letter, LV_OPA_COVER);
  lv_style_set_bg_color(&s_st_letter, lv_color_hex(UI_COL_ROW));
  lv_style_set_radius(&s_st_letter, UI_RADIUS_INPUT);
  lv_style_set_shadow_width(&s_st_letter, 0);
  lv_style_init(&s_st_swatch);
  lv_style_set_radius(&s_st_swatch, UI_RADIUS_INPUT);
  lv_style_set_border_width(&s_st_swatch, 1);
  lv_style_set_border_color(&s_st_swatch, lv_color_hex(UI_COL_POPUP_BORDER));
  lv_style_set_pad_all(&s_st_swatch, 0);
  lv_style_init(&s_st_text);
  lv_style_set_text_font(&s_st_text, UI_FONT_SMALL);
  lv_style_set_text_color(&s_st_text, lv_color_hex(UI_COL_INK));
  lv_style_init(&s_st_text_body);
  lv_style_set_text_font(&s_st_text_body, UI_FONT_BODY);
  lv_style_set_text_color(&s_st_text_body, lv_color_hex(UI_COL_INK));
  lv_style_init(&s_st_text_soft);
  lv_style_set_text_font(&s_st_text_soft, UI_FONT_CAPTION);
  lv_style_set_text_color(&s_st_text_soft, lv_color_hex(UI_COL_INK_SOFT));
  s_styles_ready = true;
}

static const int FAMILY_TEXT[CF_COUNT] = {
  STR_DBPICK_FAM_RED, STR_DBPICK_FAM_ORANGE, STR_DBPICK_FAM_YELLOW, STR_DBPICK_FAM_GREEN,
  STR_DBPICK_FAM_BLUE, STR_DBPICK_FAM_PURPLE, STR_DBPICK_FAM_PINK, STR_DBPICK_FAM_BROWN,
  STR_DBPICK_FAM_BLACK, STR_DBPICK_FAM_GREY, STR_DBPICK_FAM_WHITE, STR_DBPICK_FAM_MULTI,
  STR_DBPICK_FAM_CLEAR
};

lv_obj_t* dbPickScreen() { return s_scr; }

bool dbPickOffered() {
  return strlen(g_tag.tray_uuid) != 32 && link_tag_uid[0] && fdbOffered();
}

// ------------------------------------------------------------
//  Taps: parked for the loop
// ------------------------------------------------------------

static void park(DbpNav nav, int arg) {
  s_nav = nav;
  s_nav_arg = arg;
}

static void onNav(lv_event_t* e) {
  const intptr_t v = (intptr_t)lv_event_get_user_data(e);
  park((DbpNav)(v >> 16), (int)(v & 0xFFFF));
}

static void* navData(DbpNav nav, int arg) {
  return (void*)(intptr_t)(((intptr_t)nav << 16) | (arg & 0xFFFF));
}

void dbPickEntryTap(lv_event_t*) {
  logSD("BTN: New from database");
  park(NAV_OPEN, 0);
}

// ------------------------------------------------------------
//  The frame
// ------------------------------------------------------------

static lv_obj_t* headButton(lv_obj_t* head, bool close) {
  lv_obj_t* b = lv_btn_create(head);
  lv_obj_set_size(b, DBP_HEAD_BTN, DBP_HEAD_BTN);
  if (close) lv_obj_align(b, LV_ALIGN_TOP_RIGHT, -DBP_GAP, DBP_GAP);
  else       lv_obj_set_pos(b, DBP_GAP, DBP_GAP);
  lv_obj_set_style_bg_color(b, lv_color_hex(close ? UI_COL_BAD_BG : UI_COL_SURFACE), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(close ? UI_COL_BAD_BG_PRESSED : UI_COL_PRESS_FILL),
                            LV_STATE_PRESSED);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_border_width(b, 0, 0);
  lv_obj_add_event_cb(b, onNav, LV_EVENT_CLICKED, navData(close ? NAV_CLOSE : NAV_BACK, 0));
  lv_obj_t* l = lv_label_create(b);
  lv_label_set_text(l, close ? LV_SYMBOL_CLOSE : LV_SYMBOL_LEFT);
  lv_obj_set_style_text_color(l, lv_color_hex(close ? UI_COL_BAD_TEXT : UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(l, UI_FONT_TITLE, 0);
  lv_obj_center(l);
  return b;
}

static void buildFrame() {
  s_scr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(s_scr, LV_HOR_RES, LV_VER_RES);
  lv_obj_set_pos(s_scr, 0, 0);
  lv_obj_set_style_bg_color(s_scr, lv_color_hex(UI_COL_GROUND), 0);
  lv_obj_set_style_border_width(s_scr, 0, 0);
  lv_obj_set_style_radius(s_scr, 0, 0);
  lv_obj_set_style_pad_all(s_scr, 0, 0);
  lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_SCROLLABLE);

  headButton(s_scr, false);
  headButton(s_scr, true);
  s_title = lv_label_create(s_scr);
  lv_obj_set_style_text_color(s_title, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(s_title, UI_FONT_BODY, 0);
  lv_label_set_long_mode(s_title, LV_LABEL_LONG_DOT);
  lv_obj_set_style_text_align(s_title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(s_title, LV_HOR_RES - 2 * (DBP_HEAD_BTN + 2 * DBP_GAP));
  lv_obj_align(s_title, LV_ALIGN_TOP_MID, 0, (DBP_HEAD_H - 20) / 2);

  lv_obj_t* rule = lv_obj_create(s_scr);
  lv_obj_set_size(rule, LV_HOR_RES, 1);
  lv_obj_set_pos(rule, 0, DBP_HEAD_H);
  lv_obj_set_style_bg_color(rule, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_border_width(rule, 0, 0);
  lv_obj_set_style_radius(rule, 0, 0);
  lv_obj_set_style_pad_all(rule, 0, 0);
}

// A scrolling container under the header: tiles flow in rows.
static lv_obj_t* makeBody(int y, int h) {
  s_body = lv_obj_create(s_scr);
  lv_obj_set_size(s_body, DBP_BODY_W, h);
  lv_obj_set_pos(s_body, (LV_HOR_RES - DBP_BODY_W) / 2, y);
  lv_obj_set_style_bg_opa(s_body, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(s_body, 0, 0);
  lv_obj_set_style_radius(s_body, 0, 0);
  lv_obj_set_style_pad_all(s_body, 2, 0);
  lv_obj_set_style_pad_row(s_body, DBP_GAP, 0);
  lv_obj_set_style_pad_column(s_body, DBP_GAP, 0);
  lv_obj_set_flex_flow(s_body, LV_FLEX_FLOW_ROW_WRAP);
  lv_obj_set_scroll_dir(s_body, LV_DIR_VER);
  return s_body;
}

// The same in place of what the screen showed, the letters included.
static lv_obj_t* newBody(int y, int h) {
  if (s_body) lv_obj_del(s_body);
  if (s_strip) lv_obj_del(s_strip);
  s_strip = nullptr;
  memset(s_letter_btn, 0, sizeof(s_letter_btn));
  return makeBody(y, h);
}

static void setTitle(const char* text) {
  if (s_title) lv_label_set_text(s_title, text);
}

// A caption across the whole width, between groups of tiles.
static void caption(lv_obj_t* parent, const char* text) {
  lv_obj_t* l = lv_label_create(parent);
  lv_label_set_text(l, text);
  lv_obj_set_width(l, DBP_ROW_W);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_CAPTION), 0);
  lv_obj_set_style_text_font(l, UI_FONT_SMALL, 0);
  lv_obj_set_style_pad_top(l, DBP_GAP, 0);
}

// A message where the list would be: an empty list, or one that did not load.
static void showMessage(const char* text) {
  lv_obj_t* body = newBody(DBP_BODY_Y, DBP_BODY_H);
  lv_obj_t* l = lv_label_create(body);
  lv_label_set_text(l, text);
  lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(l, DBP_ROW_W);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_pad_top(l, DBP_BODY_H / 3, 0);
}

static lv_obj_t* tile(lv_obj_t* parent, int w, int h, DbpNav nav, int arg) {
  lv_obj_t* b = lv_btn_create(parent);
  lv_obj_set_size(b, w, h);
  lv_obj_add_style(b, &s_st_tile, 0);
  lv_obj_add_style(b, &s_st_tile_pressed, LV_STATE_PRESSED);
  lv_obj_clear_flag(b, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
  lv_obj_add_event_cb(b, onNav, LV_EVENT_CLICKED, navData(nav, arg));
  return b;
}

// A tile that is one label: background, border and text in one object,
// where a button with a label in it is two. The maker list is 67 of them.
static lv_obj_t* labelTile(lv_obj_t* parent, int w, int h, const char* text, lv_style_t* look) {
  lv_obj_t* l = lv_label_create(parent);
  lv_label_set_text(l, text);
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
  lv_obj_set_size(l, w, h);
  lv_obj_add_style(l, look, 0);
  lv_obj_add_style(l, &s_st_tile_pressed, LV_STATE_PRESSED);
  lv_obj_add_style(l, &s_st_text, 0);
  // One line, centred: what the line does not fill is padding above and below.
  const int line_h = lv_font_get_line_height(UI_FONT_SMALL);
  lv_obj_set_style_pad_top(l, (h - line_h) / 2, 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_add_flag(l, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_clear_flag(l, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
  return l;
}

// A line of a tile, as wide as the tile's inside and centred in it: a name
// too long for the tile ends in dots instead of running over its border.
static lv_obj_t* tileText(lv_obj_t* t, const char* text, lv_style_t* style, lv_align_t align, int y) {
  lv_obj_t* l = lv_label_create(t);
  lv_label_set_text(l, text);
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
  lv_obj_set_width(l, lv_obj_get_style_width(t, 0) - 2 * (DBP_TILE_PAD + 1));
  lv_obj_add_style(l, style, 0);
  // One line: the dots need a height to end at, or the text wraps.
  lv_obj_set_height(l, lv_font_get_line_height(lv_obj_get_style_text_font(l, 0)));
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(l, align, 0, y);
  return l;
}

static lv_obj_t* swatch(lv_obj_t* parent, int w, int h, const FdbEntry& e) {
  lv_obj_t* sw = lv_obj_create(parent);
  lv_obj_set_size(sw, w, h);
  lv_obj_add_style(sw, &s_st_swatch, 0);
  lv_obj_clear_flag(sw, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(sw, LV_OBJ_FLAG_CLICKABLE);
  char rgba[10];
  // A clear filament as the glass fade swatchPaint() draws for a clear tag.
  snprintf(rgba, sizeof(rgba), "%s%s", e.hex[0], e.family == CF_CLEAR ? "00" : "");
  swatchPaintHex(sw, rgba);
  if (e.ncolors >= 2) {
    lv_obj_set_style_bg_grad_color(sw, lv_color_hex(strtoul(e.hex[1], nullptr, 16)), 0);
    lv_obj_set_style_bg_grad_dir(sw, LV_GRAD_DIR_VER, 0);
  }
  return sw;
}

// ------------------------------------------------------------
//  Step 1: the maker
// ------------------------------------------------------------

// 0 for a name that starts with a digit or a sign, as "3D-Fuel": those sort
// first. Then A-Z as 1-26.
static int letterOf(const char* name) {
  const char c = name[0];
  if (c >= 'a' && c <= 'z') return 1 + c - 'a';
  if (c >= 'A' && c <= 'Z') return 1 + c - 'A';
  return 0;
}

static void onLetter(lv_event_t* e) {
  lv_obj_t* target = (lv_obj_t*)lv_event_get_user_data(e);
  if (!target) return;
  // To the top of the list rather than just into view, so the letter's first
  // maker leads the rows under the strip. Scrolling moves nothing that holds
  // this button: allowed right here.
  lv_obj_scroll_to_y(lv_obj_get_parent(target), lv_obj_get_y(target), LV_ANIM_ON);
}

// A long list: a letter shows its makers. Every letter that leads one.
static bool filterMakers() { return fdbMakerCount() >= DBP_MAKER_FILTER_MIN; }

static void lettersInUse(bool used[DBP_LETTERS]) {
  memset(used, 0, sizeof(bool) * DBP_LETTERS);
  for (int i = 0; i < fdbMakerCount(); i++) used[letterOf(fdbMaker(i)->name)] = true;
}

// The letter whose makers are shown has a frame.
static void markLetter() {
  for (int i = 0; i < DBP_LETTERS; i++) {
    if (!s_letter_btn[i]) continue;
    lv_obj_set_style_border_width(s_letter_btn[i], i == s_letter ? 2 : 0, 0);
    lv_obj_set_style_border_color(s_letter_btn[i], lv_color_hex(UI_COL_ACCENT), 0);
  }
}

static void letterStrip() {
  bool used[DBP_LETTERS];
  const bool filter = filterMakers();
  if (filter) lettersInUse(used);
  lv_obj_t* strip = lv_obj_create(s_scr);
  s_strip = strip;
  lv_obj_set_size(strip, DBP_BODY_W, DBP_LETTER_H);
  lv_obj_set_pos(strip, (LV_HOR_RES - DBP_BODY_W) / 2, DBP_BODY_Y);
  lv_obj_set_style_bg_opa(strip, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(strip, 0, 0);
  lv_obj_set_style_pad_all(strip, 0, 0);
  lv_obj_set_style_pad_column(strip, 2, 0);
  lv_obj_set_flex_flow(strip, LV_FLEX_FLOW_ROW);
  lv_obj_set_scroll_dir(strip, LV_DIR_HOR);
  lv_obj_set_scrollbar_mode(strip, LV_SCROLLBAR_MODE_OFF);
  for (int i = 0; i < DBP_LETTERS; i++) {
    if (filter ? !used[i] : !s_letter_target[i]) continue;
    char text[2] = { i == 0 ? '#' : (char)('A' + i - 1), '\0' };
    lv_obj_t* b = labelTile(strip, DBP_LETTER_W, DBP_LETTER_H - 4, text, &s_st_letter);
    s_letter_btn[i] = b;
    if (filter) lv_obj_add_event_cb(b, onNav, LV_EVENT_CLICKED, navData(NAV_LETTER, i));
    else        lv_obj_add_event_cb(b, onLetter, LV_EVENT_CLICKED, s_letter_target[i]);
  }
  markLetter();
}

static lv_obj_t* makerTile(lv_obj_t* body, int i, bool owned) {
  lv_obj_t* t = labelTile(body, DBP_TILE_W, DBP_TILE_H, fdbMaker(i)->name, &s_st_tile);
  if (owned) lv_obj_set_style_border_color(t, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_add_event_cb(t, onNav, LV_EVENT_CLICKED, navData(NAV_MAKER, i));
  return t;
}

// The makers of the inventory, or the rest: each maker once, so the pool
// holds one tile per maker and not two for the ones used most.
static void addMakers(lv_obj_t* body, bool owned) {
  for (int i = 0; i < fdbMakerCount(); i++) {
    const FdbMaker* m = fdbMaker(i);
    if (m->owned != owned) continue;
    if (!lvPoolHasRoomForRow()) { logSDf("DbPick: LVGL pool low, makers cut at %d", i); return; }
    lv_obj_t* t = makerTile(body, i, owned);
    if (owned) continue;
    const int letter = letterOf(m->name);
    if (!s_letter_target[letter]) s_letter_target[letter] = t;
  }
}

static bool anyOwned() {
  for (int i = 0; i < fdbMakerCount(); i++)
    if (fdbMaker(i)->owned) return true;
  return false;
}

// Every maker: the inventory's on top, the rest A-Z.
static void fillAllMakers(lv_obj_t* body) {
  if (anyOwned()) {
    caption(body, T(STR_DBPICK_OWNED));
    addMakers(body, true);
    caption(body, T(STR_DBPICK_OTHER_MAKERS));
  }
  addMakers(body, false);
  caption(body, T(STR_DBPICK_NOT_LISTED));
}

// A long list: the inventory's makers until a letter is tapped, then that
// letter's, the inventory's among them.
static void fillFilteredMakers(lv_obj_t* body) {
  if (s_letter < 0) {
    if (anyOwned()) {
      caption(body, T(STR_DBPICK_OWNED));
      addMakers(body, true);
    }
    caption(body, T(STR_DBPICK_PICK_LETTER));
    return;
  }
  for (int i = 0; i < fdbMakerCount(); i++) {
    const FdbMaker* m = fdbMaker(i);
    if (letterOf(m->name) != s_letter) continue;
    if (!lvPoolHasRoomForRow()) { logSDf("DbPick: LVGL pool low, makers cut at %d", i); break; }
    makerTile(body, i, m->owned);
  }
  caption(body, T(STR_DBPICK_NOT_LISTED));
}

static void showMakers() {
  s_step = DBP_MAKER;
  setTitle(T(STR_DBPICK_MAKER_TITLE));
  if (fdbMakerCount() == 0) { showMessage(T(STR_DBPICK_EMPTY)); return; }
  memset(s_letter_target, 0, sizeof(s_letter_target));
  lv_obj_t* body = newBody(DBP_BODY_Y + DBP_LETTER_H, DBP_BODY_H - DBP_LETTER_H);
  logLvMem("dbpick-makers/pre", 0);
  if (filterMakers()) fillFilteredMakers(body);
  else                fillAllMakers(body);
  logLvMem("dbpick-makers/post", fdbMakerCount());
  letterStrip();
}

// A letter tapped on a long list: its makers in place of the others, the
// letters stay.
static void showLetter(int letter) {
  s_letter = letter;
  if (s_body) lv_obj_del(s_body);
  fillFilteredMakers(makeBody(DBP_BODY_Y + DBP_LETTER_H, DBP_BODY_H - DBP_LETTER_H));
  markLetter();
  logLvMem("dbpick-letter", letter);
}

// ------------------------------------------------------------
//  Step 2: the material
// ------------------------------------------------------------

static void showMaterials() {
  s_step = DBP_MATERIAL;
  const FdbMaker* m = fdbMaker(s_maker);
  if (!m) return;
  setTitle(m->name);
  uint16_t pairs[FDB_PAIRS_MAX];
  const int n = fdbPairsOf(s_maker, pairs, FDB_PAIRS_MAX);
  if (n == 0) { showMessage(T(STR_DBPICK_EMPTY)); return; }
  lv_obj_t* body = newBody(DBP_BODY_Y, DBP_BODY_H);
  caption(body, T(STR_MAT_TITLE));
  for (int i = 0; i < n; i++) {
    if (!lvPoolHasRoomForRow()) { logSDf("DbPick: LVGL pool low, materials cut at %d", i); break; }
    const FdbPair* p = fdbPair(pairs[i]);
    lv_obj_t* t = tile(body, DBP_TILE_W, DBP_MAT_TILE_H, NAV_MATERIAL, pairs[i]);
    tileText(t, p->material, &s_st_text_body, LV_ALIGN_TOP_MID, 0);
    char count[8];
    snprintf(count, sizeof(count), "%u", (unsigned)p->count);
    tileText(t, count, &s_st_text_soft, LV_ALIGN_BOTTOM_MID, 0);
  }
}

// Entries come sorted by name, then weight: one name, its sizes after it.
static int sizesFrom(int first) {
  const FdbEntry* e = fdbEntry(first);
  int n = 1;
  while (fdbEntry(first + n) && strcmp(fdbEntry(first + n)->name, e->name) == 0) n++;
  return n;
}

static bool inLine(const FdbEntry& e) {
  return s_line < 0 || strcmp(e.line, fdbEntry(s_line_first[s_line])->line) == 0;
}

static bool inFamily(const FdbEntry& e) {
  return inLine(e) && (s_family < 0 || e.family == s_family);
}

// "SUNLU PLA", with the line once one is picked: "SUNLU PLA Matte".
static void listTitle(char* out, size_t out_size) {
  char line[32] = "";
  if (s_line >= 0) fdbLineName(*fdbEntry(s_line_first[s_line]), T(STR_DBPICK_LINE_OTHER), line, sizeof(line));
  snprintf(out, out_size, "%s %s%s%s", fdbMaker(s_maker)->name, s_material, line[0] ? " " : "", line);
}

// ------------------------------------------------------------
//  Step 3: the product line, where the database names them
// ------------------------------------------------------------

static int findLine(const char* line) {
  for (int k = 0; k < s_line_n; k++)
    if (strcmp(fdbEntry(s_line_first[k])->line, line) == 0) return k;
  return -1;
}

// The lines of the list with their names, most first. A list past
// DBP_LINES_MAX lines keeps the rest under "All".
static void countLines() {
  s_line_n = 0;
  for (int i = 0; i < fdbEntryCount(); i += sizesFrom(i)) {
    int k = findLine(fdbEntry(i)->line);
    if (k < 0 && s_line_n < DBP_LINES_MAX) {
      k = s_line_n++;
      s_line_first[k] = (int16_t)i;
      s_line_count[k] = 0;
    }
    if (k >= 0) s_line_count[k]++;
  }
  for (int a = 1; a < s_line_n; a++) {
    for (int b = a; b > 0 && s_line_count[b - 1] < s_line_count[b]; b--) {
      const int16_t f = s_line_first[b]; s_line_first[b] = s_line_first[b - 1]; s_line_first[b - 1] = f;
      const uint16_t c = s_line_count[b]; s_line_count[b] = s_line_count[b - 1]; s_line_count[b - 1] = c;
    }
  }
}

static void showLines() {
  s_step = DBP_LINE;
  s_line = -1;
  char title[64];
  listTitle(title, sizeof(title));
  setTitle(title);
  lv_obj_t* body = newBody(DBP_BODY_Y, DBP_BODY_H);
  caption(body, T(STR_DBPICK_LINE_TITLE));
  int total = 0;
  for (int k = 0; k < s_line_n; k++) {
    total += s_line_count[k];
    if (!lvPoolHasRoomForRow()) { logSDf("DbPick: LVGL pool low, lines cut at %d", k); break; }
    lv_obj_t* t = tile(body, DBP_TILE_W, DBP_MAT_TILE_H, NAV_LINE, k);
    char text[32];
    fdbLineName(*fdbEntry(s_line_first[k]), T(STR_DBPICK_LINE_OTHER), text, sizeof(text));
    // The smaller font: "High Speed Matte" fits a tile in it.
    tileText(t, text, &s_st_text, LV_ALIGN_TOP_MID, DBP_GAP);
    snprintf(text, sizeof(text), "%u", (unsigned)s_line_count[k]);
    tileText(t, text, &s_st_text_soft, LV_ALIGN_BOTTOM_MID, 0);
  }
  lv_obj_t* all = tile(body, DBP_TILE_W, DBP_MAT_TILE_H, NAV_LINE, DBP_LINES_MAX);
  char text[24];
  snprintf(text, sizeof(text), T(STR_DBPICK_ALL), total);
  tileText(all, text, &s_st_text, LV_ALIGN_CENTER, 0);
}

// ------------------------------------------------------------
//  Step 4: the colour family, where the list is long
// ------------------------------------------------------------

// Names per family, and for each the entry that paints its tile: the most
// typical of its colours.
static int countNames(int counts[CF_COUNT], int typical[CF_COUNT]) {
  int total = 0, best[CF_COUNT];
  for (int f = 0; f < CF_COUNT; f++) { counts[f] = 0; typical[f] = -1; best[f] = -1; }
  for (int i = 0; i < fdbEntryCount(); i += sizesFrom(i)) {
    const FdbEntry* e = fdbEntry(i);
    if (!inLine(*e)) continue;
    const int f = e->family;
    const int score = colorFamilyTypicality(e->hex[0], (ColorFamily)f);
    if (score > best[f]) { best[f] = score; typical[f] = i; }
    counts[f]++;
    total++;
  }
  return total;
}

// The strip shows a real filament of the list, not a made-up colour for the
// family: the most typical one (countNames()).
static void familyTile(lv_obj_t* body, int family, int count, int first) {
  lv_obj_t* t = tile(body, DBP_FAM_TILE_W, DBP_FAM_TILE_H, NAV_FAMILY, family);
  lv_obj_t* sw = swatch(t, DBP_FAM_TILE_W - 2 * DBP_GAP - 2, DBP_FAM_STRIP_H, *fdbEntry(first));
  lv_obj_align(sw, LV_ALIGN_TOP_MID, 0, 0);
  tileText(t, T(FAMILY_TEXT[family]), &s_st_text, LV_ALIGN_TOP_MID, DBP_FAM_STRIP_H + 2);
  char text[8];
  snprintf(text, sizeof(text), "%d", count);
  tileText(t, text, &s_st_text_soft, LV_ALIGN_BOTTOM_MID, 0);
}

static void showFamilies(const int counts[CF_COUNT], const int typical[CF_COUNT], int total) {
  s_step = DBP_FAMILY;
  char title[64];
  listTitle(title, sizeof(title));
  setTitle(title);
  lv_obj_t* body = newBody(DBP_BODY_Y, DBP_BODY_H);
  caption(body, T(STR_DBPICK_COLOR_TITLE));
  for (int f = 0; f < CF_COUNT; f++)
    if (counts[f] > 0) familyTile(body, f, counts[f], typical[f]);
  lv_obj_t* all = tile(body, DBP_FAM_TILE_W, DBP_FAM_TILE_H, NAV_FAMILY, CF_COUNT);
  char text[24];
  snprintf(text, sizeof(text), T(STR_DBPICK_ALL), total);
  tileText(all, text, &s_st_text, LV_ALIGN_CENTER, 0);
}

// ------------------------------------------------------------
//  Step 5: the entries
// ------------------------------------------------------------

static void weightText(int grams, char* out, size_t out_size) {
  if (grams <= 0) { out[0] = '\0'; return; }
  if (grams % DBP_GRAMS_PER_KG == 0) snprintf(out, out_size, "%d kg", grams / DBP_GRAMS_PER_KG);
  else if (grams > DBP_GRAMS_PER_KG) snprintf(out, out_size, "%.1f kg", grams / (float)DBP_GRAMS_PER_KG);
  else snprintf(out, out_size, "%d g", grams);
}

// "1 kg", or "1 kg / 3 kg" for a filament sold in more than one size.
static void sizesText(int first, int n, char* out, size_t out_size) {
  out[0] = '\0';
  for (int k = 0; k < n; k++) {
    char w[12];
    weightText(fdbEntry(first + k)->weight_g, w, sizeof(w));
    const size_t used = strlen(out);
    snprintf(out + used, out_size - used, "%s%s", used ? " / " : "", w);
  }
}

static void entryRow(lv_obj_t* body, int first, int n) {
  const FdbEntry* e = fdbEntry(first);
  lv_obj_t* row = tile(body, DBP_ROW_W, DBP_ROW_H, NAV_ENTRY, first);
  lv_obj_t* sw = swatch(row, DBP_ROW_SWATCH, DBP_ROW_SWATCH, *e);
  lv_obj_align(sw, LV_ALIGN_LEFT_MID, DBP_GAP, 0);
  char shown[FDB_NAME_MAX];
  fdbEntryDisplayName(*e, fdbMaker(s_maker)->name, s_material, shown, sizeof(shown));
  lv_obj_t* name = lv_label_create(row);
  lv_label_set_text(name, shown);
  lv_label_set_long_mode(name, LV_LABEL_LONG_DOT);
  lv_obj_set_width(name, DBP_ROW_NAME_W);
  lv_obj_add_style(name, &s_st_text_body, 0);
  lv_obj_align(name, LV_ALIGN_LEFT_MID, DBP_ROW_SWATCH + 3 * DBP_GAP, 0);
  char sizes[40];
  sizesText(first, n, sizes, sizeof(sizes));
  lv_obj_t* l = tileText(row, sizes, &s_st_text_soft, LV_ALIGN_RIGHT_MID, 0);
  lv_obj_set_width(l, DBP_ROW_SIZES_W);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_RIGHT, 0);
}

static void showEntries() {
  s_step = DBP_ENTRIES;
  char title[96];
  listTitle(title, sizeof(title));
  if (s_family >= 0) {
    const size_t used = strlen(title);
    snprintf(title + used, sizeof(title) - used, ": %s", T(FAMILY_TEXT[s_family]));
  }
  setTitle(title);
  lv_obj_t* body = newBody(DBP_BODY_Y, DBP_BODY_H);
  logLvMem("dbpick-entries/pre", 0);
  int rows = 0;
  for (int i = 0; i < fdbEntryCount(); ) {
    const int n = sizesFrom(i);
    if (inFamily(*fdbEntry(i))) {
      if (!lvPoolHasRoomForRow()) { logSDf("DbPick: LVGL pool low, list cut at %d", rows); break; }
      entryRow(body, i, n);
      rows++;
    }
    i += n;
  }
  logLvMem("dbpick-entries/post", rows);
}

static void showFamilyStep() {
  int counts[CF_COUNT], typical[CF_COUNT];
  const int total = countNames(counts, typical);
  s_family = -1;
  showFamilies(counts, typical, total);
}

// The list of one line, or of all: straight to it, or through the families
// first.
static void showLineList() {
  int counts[CF_COUNT], typical[CF_COUNT];
  s_family = -1;
  const int total = countNames(counts, typical);
  if (total == 0) { showMessage(T(STR_DBPICK_EMPTY)); return; }
  s_family_step = total > DBP_FAMILY_MIN_ROWS;
  if (s_family_step) showFamilies(counts, typical, total);
  else showEntries();
}

// The list has come in: through the product lines where it has two or more.
static void showLoadedList() {
  s_line = -1;
  countLines();
  s_line_step = s_line_n >= 2;
  if (s_line_step) showLines();
  else showLineList();
}

// ------------------------------------------------------------
//  The size question
// ------------------------------------------------------------

static void closeSizeQuestion() {
  if (s_size) lv_obj_del(s_size);
  s_size = nullptr;
}

static void sizeButton(lv_obj_t* box, const char* text, int y, DbpNav nav, int arg) {
  lv_obj_t* b = lv_btn_create(box);
  lv_obj_set_size(b, UI_POPUP_W - 2 * UI_CARD_ROW_X, DBP_SIZE_BTN_H);
  lv_obj_align(b, LV_ALIGN_TOP_MID, 0, y);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(nav == NAV_SIZE ? UI_COL_ROW : UI_COL_BAD_BG), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(nav == NAV_SIZE ? UI_COL_ROW_PRESS_FILL : UI_COL_BAD_BG_PRESSED),
                            LV_STATE_PRESSED);
  lv_obj_add_event_cb(b, onNav, LV_EVENT_CLICKED, navData(nav, arg));
  lv_obj_t* l = lv_label_create(b);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_color(l, lv_color_hex(nav == NAV_SIZE ? UI_COL_INK : UI_COL_BAD_TEXT), 0);
  lv_obj_set_style_text_font(l, UI_FONT_TITLE, 0);
  lv_obj_center(l);
}

static void askSize(int first, int n) {
  if (n > DBP_SIZES_MAX) n = DBP_SIZES_MAX;
  const int box_h = UI_CARD_TITLE_Y + (n + 1) * (DBP_SIZE_BTN_H + DBP_GAP) + UI_CARD_ROW_X;
  s_size = lv_obj_create(s_scr);
  lv_obj_set_size(s_size, LV_HOR_RES, LV_VER_RES);
  lv_obj_set_pos(s_size, 0, 0);
  lv_obj_set_style_bg_color(s_size, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(s_size, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(s_size, 0, 0);
  lv_obj_set_style_radius(s_size, 0, 0);
  lv_obj_clear_flag(s_size, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_t* box = lv_obj_create(s_size);
  lv_obj_set_size(box, UI_POPUP_W, box_h);
  lv_obj_center(box);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_t* title = lv_label_create(box);
  lv_label_set_text(title, T(STR_DBPICK_SIZE_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(title, UI_FONT_HEADLINE, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, UI_CARD_ICON_Y);
  int y = UI_CARD_TITLE_Y;
  for (int k = 0; k < n; k++, y += DBP_SIZE_BTN_H + DBP_GAP) {
    char w[12];
    weightText(fdbEntry(first + k)->weight_g, w, sizeof(w));
    sizeButton(box, w, y, NAV_SIZE, first + k);
  }
  sizeButton(box, T(STR_CANCEL), y, NAV_SIZE_CANCEL, 0);
}

// ------------------------------------------------------------
//  Opening, loading, closing
// ------------------------------------------------------------

void dbPickClose() {
  closeSizeQuestion();
  if (s_wait != FDB_JOB_NONE) linkWaitCardHide();
  s_wait = s_want = FDB_JOB_NONE;
  s_body = nullptr;
  s_strip = nullptr;
  s_title = nullptr;
  releaseScreen(&s_scr);
  s_step = DBP_CLOSED;
  // A load still running hands its PSRAM back once it is collected.
  fdbReleaseEntries();
}

// Starts the load the screen needs, or keeps it wanted for the next pass:
// the task cannot start while another load is still running.
static bool startJob(FdbJob job) {
  if (job == FDB_JOB_INDEX) return fdbStartIndex();
  if (job == FDB_JOB_PAIRS) return fdbStartPairs(fdbMaker(s_maker)->name);
  return fdbStartEntries(fdbMaker(s_maker)->name, s_material);
}

static void startLoad(FdbJob job) {
  const bool started = startJob(job);
  s_want = started ? FDB_JOB_NONE : job;
  if (!started) return;
  s_wait = job;
  linkWaitCardShow();
  linkWaitCardTitle(T(STR_DBPICK_LOADING));
}

static void openPicker() {
  logSD("SHOW: DbPick");
  closeCopyEntryPopup();
  dbPickClose();
  initStyles();
  buildFrame();
  s_letter = -1;
  setTitle(T(STR_DBPICK_MAKER_TITLE));
  if (fdbIndexReady()) showMakers();
  else startLoad(FDB_JOB_INDEX);
}

// An index the server says it has not got: an older Spoolman, or a FilaMan
// without its FilamentDB plugin.
static void showLoadFailure(FdbJob job, int code) {
  char text[96];
  const bool missing = job == FDB_JOB_INDEX && (code == 404 || code == 405);
  if (missing) copyT(text, sizeof(text), backendIsFilaMan() ? STR_DBPICK_FM_NO_PLUGIN : STR_DBPICK_NEEDS_NEWER);
  else snprintf(text, sizeof(text), T(STR_DBPICK_FAILED), code);
  showMessage(text);
}

// A finished load: shown when the screen waits for it, dropped otherwise.
static void collectLoad() {
  if (fdbState() != FDB_DONE) return;
  const FdbJob job = fdbJob();
  const int code = fdbResultCode();
  const bool current = fdbResultCurrent();
  fdbTake();
  if (!s_scr) { fdbReleaseEntries(); return; }
  if (job != s_wait) return;
  s_wait = FDB_JOB_NONE;
  linkWaitCardHide();
  if (code != 200 || !current) {
    logSDf("DbPick: load %d failed, code %d, current %d", (int)job, code, (int)current);
    // Back from the message leads to the makers.
    if (job == FDB_JOB_PAIRS) s_step = DBP_MATERIAL;
    showLoadFailure(job, code);
    return;
  }
  if (job == FDB_JOB_INDEX) showMakers();
  else if (job == FDB_JOB_PAIRS) showMaterials();
  else showLoadedList();
}

// ------------------------------------------------------------
//  The loop's part
// ------------------------------------------------------------

static void goBack() {
  switch (s_step) {
    case DBP_ENTRIES:
      if (s_family_step) showFamilyStep();
      else if (s_line_step) showLines();
      else showMaterials();
      break;
    case DBP_FAMILY:
      if (s_line_step) showLines();
      else showMaterials();
      break;
    case DBP_LINE:     showMaterials(); break;
    case DBP_MATERIAL: showMakers();    break;
    default:
      dbPickClose();
      // Back to the copy popup the picker was opened from.
      showCopyEntryPopup();
      break;
  }
}

static void pickEntry(int i) {
  const FdbEntry* e = fdbEntry(i);
  if (!e) return;
  TagCreateInput in;
  fdbEntryToInput(*e, fdbMaker(s_maker)->name, s_material, &in);
  logSDf("DbPick: %s %s \"%s\" %d g, id %s", in.vendor, in.material, e->name, e->weight_g, e->id);
  showTagCreatePopupFor(in);
}

static void runNav(DbpNav nav, int arg) {
  if (nav != NAV_OPEN && !s_scr) return;
  switch (nav) {
    case NAV_OPEN:     openPicker(); break;
    case NAV_CLOSE:    dbPickClose(); break;
    case NAV_BACK:     goBack(); break;
    case NAV_LETTER:   showLetter(arg); break;
    case NAV_MAKER:
      s_maker = arg;
      // The FilamentDB names a maker's materials only when asked.
      if (fdbMakerHasPairs(arg)) showMaterials();
      else startLoad(FDB_JOB_PAIRS);
      break;
    case NAV_MATERIAL: {
      const FdbPair* p = fdbPair(arg);
      if (!p) return;
      snprintf(s_material, sizeof(s_material), "%s", p->material);
      startLoad(FDB_JOB_ENTRIES);
      break;
    }
    case NAV_LINE:     s_line = arg < s_line_n ? arg : -1; showLineList(); break;
    case NAV_FAMILY:   s_family = arg < CF_COUNT ? arg : -1; showEntries(); break;
    case NAV_ENTRY: {
      const int n = sizesFrom(arg);
      if (n > 1) askSize(arg, n);
      else pickEntry(arg);
      break;
    }
    case NAV_SIZE:        closeSizeQuestion(); pickEntry(arg); break;
    case NAV_SIZE_CANCEL: closeSizeQuestion(); break;
    default: break;
  }
}

void dbPickTick() {
  collectLoad();
  if (s_wait != FDB_JOB_NONE) {
    linkWaitCardBytes(fdbBytes());
    if (linkWaitCardCancelTake()) {
      // The step on screen stays; with none yet, back to the copy popup.
      // The load runs out on its own and is dropped when it arrives.
      logSD("DbPick: load cancelled");
      if (s_step == DBP_CLOSED) park(NAV_BACK, 0);
      linkWaitCardHide();
      s_wait = FDB_JOB_NONE;
    }
  }
  if (s_want != FDB_JOB_NONE && s_scr && fdbState() == FDB_IDLE) startLoad(s_want);
  if (s_nav == NAV_NONE) return;
  const DbpNav nav = s_nav;
  const int arg = s_nav_arg;
  s_nav = NAV_NONE;
  runNav(nav, arg);
}
