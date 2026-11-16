#include "ui/spool_pick_pages.h"

#include <Arduino.h>
#include <stdio.h>

#include "lang.h"
#include "ui/theme.h"
#include "ui/ui_common.h"

// The page inside the large popup's 2 px border: the title on top, the tiles
// in a scrolling area under it, one row of buttons or a hint at the bottom.
#define SPP_INNER_W   (UI_POPUP_LARGE_W - 4)
#define SPP_EDGE      12
#define SPP_TITLE_Y   10
#define SPP_AREA_Y    44
#define SPP_AREA_W    (SPP_INNER_W - 2 * SPP_EDGE)
#define SPP_AREA_H    188
#define SPP_GAP       8
#define SPP_TILE_W    ((SPP_AREA_W - SPP_GAP) / 2)
#define SPP_TILE_H    52
#define SPP_NAME_Y    6
#define SPP_WEIGHT_Y  28
// The makers' letters: a strip under the title, the tiles under it.
#define SPP_HEAD_H    18     // a section's caption over its tiles
#define SPP_LETTER_W  32
#define SPP_LETTER_H  34
#define SPP_LETTER_GAP 2
#define SPP_MAKERS_Y  (SPP_AREA_Y + SPP_LETTER_H + SPP_GAP)
#define SPP_MAKERS_H  (SPP_AREA_Y + SPP_AREA_H - SPP_MAKERS_Y)
#define SPP_BOTTOM_Y  244
#define SPP_BOTTOM_H  44
#define SPP_BTN_W     ((SPP_AREA_W - 2 * SPP_GAP) / 3)
#define SPP_BACK_W    134
#define SPP_GRAMS_PER_KG 1000

static SpoolPickTap s_tap = nullptr;

static void onTap(lv_event_t* e) {
  if (s_tap) s_tap((int)(intptr_t)lv_event_get_user_data(e));
}

static lv_obj_t* label(lv_obj_t* parent, const char* text, const lv_font_t* font, uint32_t color) {
  lv_obj_t* l = lv_label_create(parent);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(color), 0);
  return l;
}

static void title(lv_obj_t* box, const char* text) {
  lv_obj_t* l = label(box, text, UI_FONT_HEADLINE, UI_COL_INK);
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
  lv_obj_set_style_max_width(l, SPP_AREA_W, 0);
  lv_obj_align(l, LV_ALIGN_TOP_MID, 0, SPP_TITLE_Y);
}

// The scrolling area the tiles go in.
static lv_obj_t* areaAt(lv_obj_t* box, int y, int h) {
  lv_obj_t* a = lv_obj_create(box);
  lv_obj_remove_style_all(a);
  lv_obj_set_size(a, SPP_AREA_W, h);
  lv_obj_set_pos(a, SPP_EDGE, y);
  lv_obj_set_scroll_dir(a, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(a, LV_SCROLLBAR_MODE_AUTO);
  return a;
}

static lv_obj_t* area(lv_obj_t* box) { return areaAt(box, SPP_AREA_Y, SPP_AREA_H); }

// What one tile shows, and what a tap on it answers.
struct PickTile {
  const char* name;
  const char* weight;
  bool        chosen;
  int         tap;
};

// One tile: the name over the weight. The chosen one is green.
static void tile(lv_obj_t* parent, int x, int y, const PickTile& t) {
  const bool chosen = t.chosen;
  lv_obj_t* b = lv_btn_create(parent);
  lv_obj_set_size(b, SPP_TILE_W, SPP_TILE_H);
  lv_obj_set_pos(b, x, y);
  lv_obj_set_style_bg_color(b, lv_color_hex(chosen ? UI_COL_OK_BG : UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(chosen ? UI_COL_OK_BG_PRESSED : UI_COL_ROW_PRESS_FILL),
                            LV_STATE_PRESSED);
  lv_obj_set_style_border_width(b, chosen ? 0 : 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_pad_all(b, 0, 0);
  lv_obj_add_event_cb(b, onTap, LV_EVENT_CLICKED, (void*)(intptr_t)t.tap);
  lv_obj_t* n = label(b, t.name, UI_FONT_BODY, chosen ? UI_COL_OK_TEXT : UI_COL_INK);
  lv_label_set_long_mode(n, LV_LABEL_LONG_DOT);
  lv_obj_set_width(n, SPP_TILE_W - 2 * SPP_GAP);
  lv_obj_set_style_text_align(n, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(n, LV_ALIGN_TOP_MID, 0, SPP_NAME_Y);
  lv_obj_t* w = label(b, t.weight, UI_FONT_SMALL, chosen ? UI_COL_OK_TEXT_2 : UI_COL_INK_SOFT);
  lv_label_set_long_mode(w, LV_LABEL_LONG_DOT);
  lv_obj_set_width(w, SPP_TILE_W - 2 * SPP_GAP);
  lv_obj_set_style_text_align(w, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(w, LV_ALIGN_TOP_MID, 0, SPP_WEIGHT_Y);
}

// Where the n-th tile of a section starting at `top` goes.
static int tileX(int n) { return (n % 2) * (SPP_TILE_W + SPP_GAP); }
static int tileY(int top, int n) { return top + (n / 2) * (SPP_TILE_H + SPP_GAP); }

static void bottomButton(lv_obj_t* box, int x, int w, int caption, int tap) {
  const bool back = tap == SPICK_TAP_BACK;
  lv_obj_t* b = padButton(box, x, SPP_BOTTOM_Y, w, SPP_BOTTOM_H, UI_COL_ROW, UI_COL_ROW_PRESS_FILL);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  padLabel(b, T(caption), back ? UI_COL_INK_2 : UI_COL_INK, UI_FONT_BODY);
  if (back) styleLeaveButton(b, LV_SYMBOL_LEFT);
  lv_obj_add_event_cb(b, onTap, LV_EVENT_CLICKED, (void*)(intptr_t)tap);
}

// A page that ends in a line of explanation and Back.
static void hintAndBack(lv_obj_t* box, int hint) {
  lv_obj_t* l = label(box, T(hint), UI_FONT_CAPTION, UI_COL_CAPTION);
  lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(l, SPP_AREA_W - SPP_BACK_W - SPP_GAP);
  lv_obj_set_pos(l, SPP_EDGE, SPP_BOTTOM_Y + 4);
  bottomButton(box, SPP_EDGE + SPP_AREA_W - SPP_BACK_W, SPP_BACK_W, STR_BACK, SPICK_TAP_BACK);
}

void spoolPickKindText(const SpoolChoice& c, char* out, size_t out_size) {
  static const int KIND_TEXT[] = { STR_SPOOL_KIND_ANY, STR_SPOOL_KIND_PLASTIC,
                                   STR_SPOOL_KIND_CARDBOARD, STR_SPOOL_KIND_METAL };
  const char* kind = T(c.kind <= SPOOL_KIND_METAL ? KIND_TEXT[c.kind] : STR_SPOOL_KIND_ANY);
  const unsigned net = c.net_g;
  if (net == 0)                        snprintf(out, out_size, "%s", kind);
  else if (net < SPP_GRAMS_PER_KG)     snprintf(out, out_size, "%s | %u g", kind, net);
  else if (net % SPP_GRAMS_PER_KG == 0) snprintf(out, out_size, "%s | %u kg", kind, net / SPP_GRAMS_PER_KG);
  else snprintf(out, out_size, "%s | %.1f kg", kind, net / (float)SPP_GRAMS_PER_KG);
}

// A choice's name on a tile: the maker, or that it was typed in.
static const char* choiceName(const SpoolChoice& c) {
  return c.name[0] ? c.name : T(STR_SPICK_TYPED_NAME);
}

static bool isCurrent(const SpoolPickList& list, const SpoolChoice& c) {
  return list.current && spoolChoiceActive(*list.current) && spoolChoiceSame(c, *list.current);
}

static bool inSections(const SpoolPickList& list) {
  for (int i = 0; list.mine && i < list.mine_n; i++)
    if (isCurrent(list, list.mine[i])) return true;
  for (int i = 0; list.server && i < list.server_n; i++)
    if (isCurrent(list, list.server[i])) return true;
  return false;
}

// Automatic and the last ones; returns how many tiles it placed.
static int firstSection(lv_obj_t* a, const SpoolPickList& list) {
  char weight[48];
  if (list.auto_tare_g > 0) snprintf(weight, sizeof(weight), "%d g | %s", list.auto_tare_g, T(list.auto_from));
  else if (list.auto_name)  snprintf(weight, sizeof(weight), "0 g");
  else                      copyT(weight, sizeof(weight), STR_SPICK_UNKNOWN);
  const bool automatic = !list.current || !spoolChoiceActive(*list.current);
  tile(a, tileX(0), tileY(0, 0), { T(list.auto_name ? list.auto_name : STR_SPICK_AUTO), weight, automatic, 0 });
  int n = 1;
  bool current_shown = automatic || inSections(list);
  for (int i = 0; list.recent && i < SPOOL_RECENT_MAX; i++) {
    const SpoolChoice& r = list.recent[i];
    if (!spoolChoiceActive(r)) continue;
    snprintf(weight, sizeof(weight), "%u g | %s", (unsigned)r.weight_g, T(STR_SPICK_RECENT));
    const bool chosen = isCurrent(list, r);
    current_shown = current_shown || chosen;
    tile(a, tileX(n), tileY(0, n), { choiceName(r), weight, chosen, SPICK_TAP_RECENT(i) });
    n++;
  }
  // A choice no tile holds still shows as chosen, so the page never claims
  // Automatic while something else is set.
  if (!current_shown) {
    snprintf(weight, sizeof(weight), "%u g", (unsigned)list.current->weight_g);
    tile(a, tileX(n), tileY(0, n), { choiceName(*list.current), weight, true, SPICK_TAP_KEEP });
    n++;
  }
  return n;
}

static void caption(lv_obj_t* a, const char* text, int y) {
  lv_obj_set_pos(label(a, text, UI_FONT_CAPTION, UI_COL_CAPTION), 2, y);
}

// A section of the first page: the user's own, or the backend's.
struct PickSection {
  int                caption;     // STR_ id
  const SpoolChoice* items;
  int                n;
  int                first_tap;
};

// One section under its caption. Returns where the next one starts.
static int section(lv_obj_t* a, const SpoolPickList& list, int top, const PickSection& sec) {
  const SpoolChoice* items = sec.items;
  const int n = sec.n;
  if (!items || n <= 0) return top;
  caption(a, T(sec.caption), top);
  top += SPP_HEAD_H;
  char weight[16];
  for (int i = 0; i < n; i++) {
    snprintf(weight, sizeof(weight), "%u g", (unsigned)items[i].weight_g);
    tile(a, tileX(i), tileY(top, i), { items[i].name, weight, isCurrent(list, items[i]), sec.first_tap + i });
  }
  return tileY(top, n + 1);
}

void spoolPickBuildList(lv_obj_t* box, const SpoolPickList& list, SpoolPickTap tap) {
  s_tap = tap;
  title(box, T(STR_SPICK_TITLE));
  lv_obj_t* a = area(box);
  const int n = firstSection(a, list);
  const int top = section(a, list, tileY(0, n + 1),
                          { STR_SPICK_MINE, list.mine, list.mine_n, SPICK_TAP_MINE(0) });
  section(a, list, top, { STR_SPICK_SERVER, list.server, list.server_n, SPICK_TAP_SERVER(0) });
  bottomButton(box, SPP_EDGE, SPP_BTN_W, STR_SPICK_MAKERS, SPICK_TAP_MAKERS);
  bottomButton(box, SPP_EDGE + SPP_BTN_W + SPP_GAP, SPP_BTN_W, STR_SPICK_TYPE_BTN, SPICK_TAP_TYPE);
  bottomButton(box, SPP_EDGE + 2 * (SPP_BTN_W + SPP_GAP), SPP_BTN_W, STR_BACK, SPICK_TAP_BACK);
}

// A maker's tile: its one spool's weight, or how many it has. The card's own
// maker has a green frame.
static void makerTile(lv_obj_t* a, int maker, int n, bool marked) {
  char weight[32];
  SpoolChoice c;
  const int count = spoolCatalogSpoolCount(maker);
  if (count == 1 && spoolCatalogChoice(maker, 0, &c)) snprintf(weight, sizeof(weight), "%u g", (unsigned)c.weight_g);
  else snprintf(weight, sizeof(weight), T(STR_SPICK_SPOOLS), count);
  tile(a, tileX(n), tileY(0, n), { spoolCatalogMakerName(maker), weight, false, maker });
  if (!marked) return;
  lv_obj_t* t = lv_obj_get_child(a, lv_obj_get_child_cnt(a) - 1);
  lv_obj_set_style_border_width(t, 2, 0);
  lv_obj_set_style_border_color(t, lv_color_hex(UI_COL_ACCENT), 0);
}

// 0 for a name that starts with a digit or a sign ("3D Fuel"), then A-Z as
// 1-26, the way the database picker sorts its makers (db_pick_screen.cpp).
static int letterOfName(const char* name) {
  const char c = name ? name[0] : '\0';
  if (c >= 'a' && c <= 'z') return 1 + c - 'a';
  if (c >= 'A' && c <= 'Z') return 1 + c - 'A';
  return 0;
}

int spoolPickLetterOf(int maker) {
  if (maker >= 0) return letterOfName(spoolCatalogMakerName(maker));
  return spoolCatalogMakerCount() > 0 ? letterOfName(spoolCatalogMakerName(0)) : 0;
}

static void letterStrip(lv_obj_t* box, int letter) {
  bool used[SPICK_LETTERS] = {};
  for (int m = 0; m < spoolCatalogMakerCount(); m++) used[letterOfName(spoolCatalogMakerName(m))] = true;
  lv_obj_t* strip = lv_obj_create(box);
  lv_obj_remove_style_all(strip);
  lv_obj_set_size(strip, SPP_AREA_W, SPP_LETTER_H);
  lv_obj_set_pos(strip, SPP_EDGE, SPP_AREA_Y);
  lv_obj_set_style_pad_column(strip, SPP_LETTER_GAP, 0);
  lv_obj_set_flex_flow(strip, LV_FLEX_FLOW_ROW);
  lv_obj_set_scroll_dir(strip, LV_DIR_HOR);
  lv_obj_set_scrollbar_mode(strip, LV_SCROLLBAR_MODE_OFF);
  lv_obj_t* chosen = nullptr;
  for (int i = 0; i < SPICK_LETTERS; i++) {
    if (!used[i]) continue;
    const char text[2] = { i == 0 ? '#' : (char)('A' + i - 1), '\0' };
    lv_obj_t* b = padButton(strip, 0, 0, SPP_LETTER_W, SPP_LETTER_H, UI_COL_ROW, UI_COL_ROW_PRESS_FILL);
    padLabel(b, text, i == letter ? UI_COL_ACCENT : UI_COL_INK, UI_FONT_BODY);
    lv_obj_set_style_border_width(b, i == letter ? 2 : 0, 0);
    lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_add_event_cb(b, onTap, LV_EVENT_CLICKED, (void*)(intptr_t)SPICK_TAP_LETTER(i));
    if (i == letter) chosen = b;
  }
  // The chosen letter in view: Z is off to the right at first.
  if (chosen) lv_obj_scroll_to_view(chosen, LV_ANIM_OFF);
}

void spoolPickBuildMakers(lv_obj_t* box, int letter, int mark, SpoolPickTap tap) {
  s_tap = tap;
  title(box, T(STR_SPICK_MAKERS));
  letterStrip(box, letter);
  lv_obj_t* a = areaAt(box, SPP_MAKERS_Y, SPP_MAKERS_H);
  int n = 0;
  for (int m = 0; m < spoolCatalogMakerCount(); m++) {
    if (letterOfName(spoolCatalogMakerName(m)) != letter) continue;
    makerTile(a, m, n++, m == mark);
  }
  hintAndBack(box, STR_SPICK_MAKERS_HINT);
}

void spoolPickBuildMaker(lv_obj_t* box, int maker, const SpoolChoice* current, SpoolPickTap tap) {
  s_tap = tap;
  title(box, spoolCatalogMakerName(maker));
  lv_obj_t* a = area(box);
  char kind[48], weight[16];
  SpoolChoice c;
  for (int k = 0; spoolCatalogChoice(maker, k, &c); k++) {
    spoolPickKindText(c, kind, sizeof(kind));
    snprintf(weight, sizeof(weight), "%u g", (unsigned)c.weight_g);
    const bool chosen = current && spoolChoiceActive(*current) && spoolChoiceSame(c, *current);
    tile(a, tileX(k), tileY(0, k), { kind, weight, chosen, k });
  }
  hintAndBack(box, STR_SPICK_MAKER_HINT);
}
