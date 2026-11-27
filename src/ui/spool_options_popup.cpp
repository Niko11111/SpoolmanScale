#include "ui/spool_options_popup.h"

#include <Arduino.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// backend_api.h brings ArduinoJson, whose templates have a parameter T:
// before lang.h, which defines T().
#include "services/backend_api.h"
#include "app/app_state.h"
#include "app/backend_switch.h"
#include "app_config.h"
#include "hardware/psram_new.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "services/spool_mine.h"
#include "ui/num_pad.h"
#include "ui/price_pad.h"
#include "ui/spool_pick_pages.h"
#include "ui/theme.h"
#include "ui/ui_common.h"

// The Options page inside the large popup's 2 px border: the title and the
// close X, up to three rows under them and Done. Price and empty spool are
// tall rows, the full weight or the density a short one below them.
#define SO_INNER_W     (UI_POPUP_LARGE_W - 4)
#define SO_EDGE        12
#define SO_ROW_W       (SO_INNER_W - 2 * SO_EDGE)
#define SO_TITLE_Y     14
#define SO_PRICE_Y     52
#define SO_SPOOL_Y     116
#define SO_SHORT_Y     180
#define SO_ROW_H       56
#define SO_SHORT_H     UI_TOUCH_MIN
#define SO_DONE_Y      232
#define SO_DONE_H      56
// Both short rows at once (a card without a density that offers the full
// weight): four rows, each as short as a finger allows, the spool's with its
// line under it a little taller.
#define SO_TIGHT_PRICE_Y    48
#define SO_TIGHT_SPOOL_Y    96
#define SO_TIGHT_SPOOL_H    48
#define SO_TIGHT_FULL_Y     148
#define SO_TIGHT_DENSITY_Y  196
#define SO_TIGHT_DONE_Y     244
#define SO_TIGHT_DONE_H     48
#define SO_ROW_PAD     14
// A row's name and the line under it, from the top of a tall row.
#define SO_NAME_Y      8
#define SO_SUB_Y       30
#define SO_VALUE_W     200
// A weight typed in: "600" at most, as the tare pad takes it.
#define SO_TYPED_MAX_CHARS  4
// A full weight typed in: the filament on a full spool, a 5 kg spool at most.
#define SO_FULL_MIN_G       100
#define SO_FULL_MAX_G       5000
#define SO_FULL_MAX_CHARS   4
// NVS keys of the last choices, one line each (spoolChoiceEncode()).
static const char* const RECENT_KEYS[SPOOL_RECENT_MAX] = { "spool_recent0", "spool_recent1" };

enum SoPage : uint8_t { SO_NONE = 0, SO_OPTIONS, SO_LIST, SO_MAKERS, SO_MAKER, SO_PRICE, SO_TYPED,
                        SO_FULL };
enum SoTap : uint8_t { SO_TAP_PRICE = 1, SO_TAP_SPOOL, SO_TAP_DENSITY, SO_TAP_FULL, SO_TAP_DONE, SO_TAP_CLOSE };

static SpoolOptionsSpec s_spec = {};
static char        s_maker_name[SPOOL_CHOICE_NAME_MAX] = "";
static lv_obj_t*   s_scr  = nullptr;      // the scrim of the page that stands
static SoPage      s_page = SO_NONE;      // what stands
static SoPage      s_want = SO_NONE;      // what the next pass builds
static int         s_maker = -1;          // the maker whose spools are shown
static int         s_letter = 0;          // the letter whose makers are shown
static bool        s_rebuild = false;     // the page that stands, built again
static bool        s_then_density = false;
// Opened on the list itself (showSpoolPickList()): it ends where the Options
// page would come next.
static bool        s_list_only = false;
static bool        s_dismissed = false;   // left by the close X, not by Done or a pick
// The three lists a page offers, 1.1 kB in PSRAM from the first opening on:
// internal RAM need not hold them while no popup stands.
// recent: the last choices. mine: the user's own, read again for every list,
// the web page may have changed them. server: the backend's, the card's
// maker first, kept for SO_SERVER_KEEP_MS per backend: asking blocks the
// loop, and an unreachable server would freeze the screen for the request's
// timeout on every opening.
struct SoLists {
  SpoolChoice recent[SPOOL_RECENT_MAX];
  SpoolChoice mine[SPOOL_MINE_MAX];
  SpoolChoice server[SPOOL_SERVER_MAX];
};
static SoLists*    s_lists = nullptr;
static bool        s_recent_loaded = false;
static bool        s_recent_dirty  = false;
static int         s_mine_n = 0;
#define SO_SERVER_KEEP_MS  (5UL * 60UL * 1000UL)
static int         s_server_n = 0;
static bool        s_server_asked = false;
static uint32_t    s_server_ms = 0;
static uint32_t    s_server_gen = 0;
static char        s_server_maker[SPOOL_CHOICE_NAME_MAX] = "";

bool spoolOptionsOpen() { return s_page != SO_NONE || s_want != SO_NONE; }

void showSpoolOptions(const SpoolOptionsSpec& spec) {
  s_spec = spec;
  snprintf(s_maker_name, sizeof(s_maker_name), "%s", spec.maker ? spec.maker : "");
  s_spec.maker = s_maker_name;
  s_then_density = false;
  s_list_only = false;
  s_dismissed = false;
  s_want = SO_OPTIONS;
}

void showSpoolPickList(const SpoolOptionsSpec& spec) {
  showSpoolOptions(spec);
  s_list_only = true;
  s_want = SO_LIST;
}

// Where a list goes when it is done: the Options page, or out.
static SoPage afterList() { return s_list_only ? SO_NONE : SO_OPTIONS; }

// --- the last choices ---------------------------------------------

static void loadRecent() {
  if (s_recent_loaded) return;
  s_recent_loaded = true;
  for (int i = 0; i < SPOOL_RECENT_MAX; i++) {
    if (!spoolChoiceDecode(prefsGetString(RECENT_KEYS[i]).c_str(), &s_lists->recent[i])) spoolChoiceClear(&s_lists->recent[i]);
  }
}

static void saveRecent() {
  char line[SPOOL_CHOICE_TEXT_MAX];
  for (int i = 0; i < SPOOL_RECENT_MAX; i++) {
    if (spoolChoiceActive(s_lists->recent[i]) && spoolChoiceEncode(s_lists->recent[i], line, sizeof(line)))
      prefsPutString(RECENT_KEYS[i], line);
    else
      prefsRemoveKey(RECENT_KEYS[i]);
  }
}

// A spool picked on one of the pages: the card's from now on, and the first
// of the last ones. Saved from the loop, not from the tap.
static void choose(const SpoolChoice& chosen) {
  // A copy: `chosen` may be one of the last ones, which the push reorders.
  const SpoolChoice c = chosen;
  *s_spec.choice = c;
  // A catalog id belongs to the server it came from; a recent one may be
  // offered after a backend switch, so it keeps the weight and name only.
  SpoolChoice recent = c;
  recent.catalog_id = 0;
  spoolRecentPush(s_lists->recent, recent);
  s_recent_dirty = true;
  logSDf("SpoolOptions: empty spool %u g (%s)", (unsigned)c.weight_g, c.name[0] ? c.name : "typed");
  s_want = afterList();
}

// --- the Options page ---------------------------------------------

static void onOptionsTap(lv_event_t* e) {
  if (s_want != s_page) return;   // a page is already on its way
  switch ((int)(intptr_t)lv_event_get_user_data(e)) {
    case SO_TAP_PRICE:   logSD("BTN: Options -> Price");         s_want = SO_PRICE; break;
    case SO_TAP_SPOOL:   logSD("BTN: Options -> Empty spool");   s_want = SO_LIST;  break;
    case SO_TAP_DENSITY: logSD("BTN: Options -> Density");       s_then_density = true; s_want = SO_NONE; break;
    case SO_TAP_FULL:    logSD("BTN: Options -> Full weight");   s_want = SO_FULL;  break;
    // What was changed is kept either way: every row writes as it is set.
    case SO_TAP_CLOSE:   logSD("BTN: Options -> Close");         s_dismissed = true; s_want = SO_NONE; break;
    default:             logSD("BTN: Options -> Done");          s_want = SO_NONE;  break;
  }
}

static lv_obj_t* text(lv_obj_t* parent, const char* s, const lv_font_t* font, uint32_t color) {
  lv_obj_t* l = lv_label_create(parent);
  lv_label_set_text(l, s);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(color), 0);
  return l;
}

// One row of the Options page.
struct OptRow {
  int         y;
  int         h;
  int         name;       // STR_ id
  int         sub;        // STR_ id of the line under it, -1 for none
  const char* value;
  uint32_t    value_col;
  int         tap;        // SoTap
};

// A row: its name on the left (with a line under it, or none), its value on
// the right, and the chevron of a step that opens.
static void row(lv_obj_t* box, const OptRow& r) {
  const int y = r.y, h = r.h, name = r.name, sub = r.sub, tap = r.tap;
  const char* value = r.value;
  const uint32_t value_col = r.value_col;
  lv_obj_t* b = padButton(box, SO_EDGE, y, SO_ROW_W, h, UI_COL_ROW, UI_COL_ROW_PRESS_FILL);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  lv_obj_set_style_pad_all(b, 0, 0);
  lv_obj_add_event_cb(b, onOptionsTap, LV_EVENT_CLICKED, (void*)(intptr_t)tap);
  lv_obj_t* n = text(b, T(name), UI_FONT_BODY, UI_COL_INK);
  if (sub >= 0) {
    // A row shorter than the tall one keeps both lines in its middle.
    const int lift = (SO_ROW_H - h) / 2;
    lv_obj_align(n, LV_ALIGN_TOP_LEFT, SO_ROW_PAD, SO_NAME_Y - lift);
    lv_obj_align(text(b, T(sub), UI_FONT_CAPTION, UI_COL_INK_SOFT), LV_ALIGN_TOP_LEFT, SO_ROW_PAD,
                 SO_SUB_Y - lift);
  } else {
    lv_obj_align(n, LV_ALIGN_LEFT_MID, SO_ROW_PAD, 0);
  }
  lv_obj_align(text(b, LV_SYMBOL_RIGHT, UI_FONT_SMALL, UI_COL_INK_SOFT), LV_ALIGN_RIGHT_MID, -SO_ROW_PAD, 0);
  lv_obj_t* v = text(b, value, UI_FONT_SMALL, value_col);
  lv_label_set_long_mode(v, LV_LABEL_LONG_DOT);
  lv_obj_set_style_max_width(v, SO_VALUE_W, 0);
  lv_obj_align(v, LV_ALIGN_RIGHT_MID, -SO_ROW_PAD - 22, 0);
}

static void spoolValue(char* out, size_t out_size) {
  const SpoolChoice& c = *s_spec.choice;
  if (spoolChoiceActive(c) && c.name[0]) snprintf(out, out_size, "%s | %u g", c.name, (unsigned)c.weight_g);
  else if (spoolChoiceActive(c))         snprintf(out, out_size, "%u g", (unsigned)c.weight_g);
  else if (s_spec.auto_tare_g > 0)       snprintf(out, out_size, "%s | %d g", T(STR_SPICK_AUTO), s_spec.auto_tare_g);
  else                                   copyT(out, out_size, STR_SPICK_AUTO);
}

// Where the rows of the Options page go: three, or four when both short ones
// are on offer.
struct OptLayout { int price_y, price_h, spool_y, spool_h, full_y, density_y, done_y, done_h; };

static OptLayout optLayout(bool full, bool density) {
  if (full && density)
    return { SO_TIGHT_PRICE_Y, SO_SHORT_H, SO_TIGHT_SPOOL_Y, SO_TIGHT_SPOOL_H, SO_TIGHT_FULL_Y,
             SO_TIGHT_DENSITY_Y, SO_TIGHT_DONE_Y, SO_TIGHT_DONE_H };
  return { SO_PRICE_Y, SO_ROW_H, SO_SPOOL_Y, SO_ROW_H, SO_SHORT_Y, SO_SHORT_Y, SO_DONE_Y, SO_DONE_H };
}

// The full weight: typed in, assumed (amber, as the density's warning), or
// named by the tag or the filament.
static void fullValue(char* out, size_t out_size, uint32_t* color) {
  if (*s_spec.full_g > 0) {
    snprintf(out, out_size, "%d g", *s_spec.full_g);
    *color = UI_COL_ACCENT;
  } else if (s_spec.full_assumed) {
    snprintf(out, out_size, T(STR_OPT_FULL_ASSUMED), s_spec.full_auto_g);
    *color = UI_COL_WARN;
  } else {
    snprintf(out, out_size, "%d g", s_spec.full_auto_g);
    *color = UI_COL_INK_2;
  }
}

static void buildOptions(lv_obj_t* box) {
  lv_obj_align(text(box, T(STR_WP_OPTIONS), UI_FONT_HEADLINE, UI_COL_INK), LV_ALIGN_TOP_MID, 0, SO_TITLE_Y);
  uiPopupCloseX(box, onOptionsTap, (void*)(intptr_t)SO_TAP_CLOSE);
  const OptLayout at = optLayout(s_spec.full_g != nullptr, s_spec.density);
  char value[64];
  if (*s_spec.price > 0.0f) snprintf(value, sizeof(value), "%.2f", *s_spec.price);
  else                      copyT(value, sizeof(value), STR_OPT_PRICE_NONE);
  row(box, { at.price_y, at.price_h, STR_TAGNEW_PRICE_BTN, -1, value, UI_COL_INK_2, SO_TAP_PRICE });
  // Every backend keeps the empty spool on the spool: BamBuddy with Spoolman
  // behind it stores core_weight as spool_weight since v1.2.5.7 (its #3011).
  spoolValue(value, sizeof(value));
  row(box, { at.spool_y, at.spool_h, STR_OPT_SPOOL, STR_OPT_SPOOL_SUB, value,
             spoolChoiceActive(*s_spec.choice) ? UI_COL_ACCENT : UI_COL_INK_2, SO_TAP_SPOOL });
  if (s_spec.full_g) {
    uint32_t color = UI_COL_INK_2;
    fullValue(value, sizeof(value), &color);
    row(box, { at.full_y, SO_SHORT_H, STR_OPT_FULL, -1, value, color, SO_TAP_FULL });
  }
  if (s_spec.density)
    row(box, { at.density_y, SO_SHORT_H, STR_OPT_DENSITY, -1, T(STR_DENSITY_CHANGE), UI_COL_WARN, SO_TAP_DENSITY });
  lv_obj_t* done = padButton(box, SO_EDGE, at.done_y, SO_ROW_W, at.done_h, UI_COL_ROW, UI_COL_ROW_PRESS_FILL);
  lv_obj_set_style_radius(done, UI_RADIUS_BTN, 0);
  padLabel(done, T(STR_OPT_DONE), UI_COL_INK, UI_FONT_TITLE);
  uiBtnRole(done, BTN_CONFIRM);
  lv_obj_add_event_cb(done, onOptionsTap, LV_EVENT_CLICKED, (void*)(intptr_t)SO_TAP_DONE);
}

// --- the empty spool lists ------------------------------------------

static void onListTap(int tap) {
  if (tap == SPICK_TAP_BACK)   { s_want = afterList(); return; }
  if (tap == SPICK_TAP_KEEP)   { s_want = afterList(); return; }
  if (tap == SPICK_TAP_MAKERS) {
    // The card's maker's letter first, so its spools are one tap away.
    s_letter = spoolPickLetterOf(spoolCatalogFindMaker(s_spec.maker));
    s_want = SO_MAKERS;
    return;
  }
  if (tap == SPICK_TAP_TYPE)   { s_want = SO_TYPED;   return; }
  if (tap == 0) {
    logSD("SpoolOptions: empty spool automatic");
    spoolChoiceClear(s_spec.choice);
    s_want = afterList();
    return;
  }
  if (tap >= SPICK_TAP_RECENT(0) && tap < SPICK_TAP_RECENT(SPOOL_RECENT_MAX))
    choose(s_lists->recent[tap - SPICK_TAP_RECENT(0)]);
  else if (tap >= SPICK_TAP_MINE(0) && tap < SPICK_TAP_MINE(s_mine_n))
    choose(s_lists->mine[tap - SPICK_TAP_MINE(0)]);
  else if (tap >= SPICK_TAP_SERVER(0) && tap < SPICK_TAP_SERVER(s_server_n))
    choose(s_lists->server[tap - SPICK_TAP_SERVER(0)]);
}

static void onMakersTap(int tap) {
  if (tap == SPICK_TAP_BACK) { s_want = SO_LIST; return; }
  if (tap <= SPICK_TAP_LETTER(0)) {
    s_letter = SPICK_LETTER_OF_TAP(tap);
    s_rebuild = true;
    return;
  }
  if (tap < 0) return;
  // A maker with one spool needs no page of its own: the tap takes it.
  SpoolChoice c;
  if (spoolCatalogSpoolCount(tap) == 1 && spoolCatalogChoice(tap, 0, &c)) { choose(c); return; }
  s_maker = tap;
  s_want = SO_MAKER;
}

static void onMakerTap(int tap) {
  if (tap == SPICK_TAP_BACK) { s_want = SO_MAKERS; return; }
  SpoolChoice c;
  if (spoolCatalogChoice(s_maker, tap, &c)) choose(c);
}

static void onPickTap(int tap) {
  if (s_want != s_page || s_rebuild) return;   // a page is already on its way
  if (tap == SPICK_TAP_CLOSE) {
    // Out of every page at once, Options included, as Done would leave it.
    logSD("BTN: SpoolPick -> Close");
    s_dismissed = true;
    s_want = SO_NONE;
    return;
  }
  if (s_page == SO_LIST)        onListTap(tap);
  else if (s_page == SO_MAKERS) onMakersTap(tap);
  else if (s_page == SO_MAKER)  onMakerTap(tap);
}

// --- the pads ---------------------------------------------------------

static void onPriceDone(bool ok, float price) {
  if (ok) *s_spec.price = price;
  s_want = SO_OPTIONS;
}

// What a typed weight leaves on the pad, while it is one the tare pad takes.
static void onTypedInput(const char* typed) {
  const int v = atoi(typed);
  char hint[96];
  if (v >= NEW_SPOOL_TARE_MIN_G && v <= NEW_SPOOL_TARE_MAX_G && scale_weight_g > v) {
    snprintf(hint, sizeof(hint), T(STR_TARE_ENTER_REST), scale_weight_g, (float)v, scale_weight_g - v);
    numPadSetHintGood(hint);
    return;
  }
  snprintf(hint, sizeof(hint), T(STR_TARE_ENTER_RANGE), NEW_SPOOL_TARE_MIN_G, NEW_SPOOL_TARE_MAX_G);
  numPadSetHint(hint, false);
}

static bool onTypedDone(const char* typed) {
  const int v = atoi(typed);
  if (v < NEW_SPOOL_TARE_MIN_G || v > NEW_SPOOL_TARE_MAX_G) {
    char hint[96];
    snprintf(hint, sizeof(hint), T(STR_TARE_ENTER_RANGE), NEW_SPOOL_TARE_MIN_G, NEW_SPOOL_TARE_MAX_G);
    numPadSetHint(hint, true);
    return false;
  }
  SpoolChoice c;
  spoolChoiceClear(&c);
  c.weight_g = (uint16_t)v;
  c.source = SCS_TYPED;
  choose(c);
  return true;
}

static void showTypedPad() {
  char hint[96], initial[8] = "";
  snprintf(hint, sizeof(hint), T(STR_TARE_ENTER_RANGE), NEW_SPOOL_TARE_MIN_G, NEW_SPOOL_TARE_MAX_G);
  if (s_spec.choice->source == SCS_TYPED) snprintf(initial, sizeof(initial), "%u", (unsigned)s_spec.choice->weight_g);
  NumPadSpec spec = {};
  spec.title      = T(STR_TARE_ENTER_TITLE);
  spec.hint       = hint;
  spec.unit       = "g";
  spec.primary    = T(STR_BTN_OK);
  spec.initial    = initial;
  spec.max_chars  = SO_TYPED_MAX_CHARS;
  spec.help_title = -1;
  spec.on_done    = onTypedDone;
  spec.on_leave   = []() { s_want = SO_LIST; };
  spec.on_input   = onTypedInput;
  spec.popup      = true;
  spec.replaced_from_loop = true;
  showNumPad(spec);
  if (initial[0]) onTypedInput(initial);
}

// The full weight: what was on the spool when it was new.
static void fullRangeHint(char* out, size_t out_size) {
  snprintf(out, out_size, T(STR_OPT_FULL_RANGE), SO_FULL_MIN_G, SO_FULL_MAX_G);
}

static bool onFullDone(const char* typed) {
  const int v = atoi(typed);
  if (v < SO_FULL_MIN_G || v > SO_FULL_MAX_G) {
    char hint[96];
    fullRangeHint(hint, sizeof(hint));
    numPadSetHint(hint, true);
    return false;
  }
  *s_spec.full_g = v;
  s_want = SO_OPTIONS;
  return true;
}

// Opens on the weight the card files, so OK alone confirms an assumed one.
static void showFullPad() {
  char hint[96], initial[8];
  fullRangeHint(hint, sizeof(hint));
  // A named weight the pad would refuse (a 50 g sample) opens it empty.
  const int now = *s_spec.full_g > 0 ? *s_spec.full_g : s_spec.full_auto_g;
  if (now >= SO_FULL_MIN_G && now <= SO_FULL_MAX_G) snprintf(initial, sizeof(initial), "%d", now);
  else initial[0] = '\0';
  NumPadSpec spec = {};
  spec.title      = T(STR_OPT_FULL);
  spec.hint       = hint;
  spec.unit       = "g";
  spec.primary    = T(STR_BTN_OK);
  spec.initial    = initial;
  spec.max_chars  = SO_FULL_MAX_CHARS;
  spec.help_title = -1;
  spec.on_done    = onFullDone;
  spec.on_leave   = []() { s_want = SO_OPTIONS; };
  spec.popup      = true;
  spec.replaced_from_loop = true;
  showNumPad(spec);
}

// --- one page at a time ------------------------------------------------

// The backend's empty spools, once per opening: from the loop, the list
// waits for them. Without WiFi or with a failed answer the section stays away.
static void askServer() {
  const bool fresh = s_server_asked && s_server_gen == backendGeneration() &&
                     millis() - s_server_ms < SO_SERVER_KEEP_MS &&
                     strcmp(s_server_maker, s_spec.maker) == 0;
  if (fresh) return;
  s_server_asked = true;
  s_server_ms = millis();
  s_server_gen = backendGeneration();
  snprintf(s_server_maker, sizeof(s_server_maker), "%s", s_spec.maker);
  s_server_n = 0;
  if (!wifi_ok || !sm_reachable) return;
  // Everything the server answered, 2.1 kB, for the length of this call.
  SpoolChoice* all = static_cast<SpoolChoice*>(psramMalloc(SPOOL_SERVER_READ_MAX * sizeof(SpoolChoice)));
  if (!all) {
    // Not kept as an answer: the next opening asks again.
    s_server_asked = false;
    logSD("SpoolOptions: no memory for the server's empty spools, section left out");
    return;
  }
  int n = 0;
  const int code = backendServerSpools(all, SPOOL_SERVER_READ_MAX, &n);
  if (code == 200) s_server_n = spoolServerPick(all, n, s_spec.maker, s_lists->server, SPOOL_SERVER_MAX);
  free(all);
  logSDf("SpoolOptions: %d empty spool(s) from the server (HTTP %d, %d read)", s_server_n, code, n);
}

// From the loop, before the next page is built: deleted at once, so the two
// pages never hold the LVGL pool together (a letter's makers next to the
// page they replace came to 95 KB, the pool's limit is 96).
static void leavePage() {
  if (s_page == SO_PRICE) closePricePad();
  if (s_page == SO_TYPED || s_page == SO_FULL) { numPadDropParked(); numPadClose(); }
  if (s_scr) lv_obj_del(s_scr);
  s_scr = nullptr;
}

static void buildPage(SoPage page) {
  if (page == SO_PRICE) { showPricePad(*s_spec.price, onPriceDone); return; }
  if (page == SO_TYPED) { showTypedPad(); return; }
  if (page == SO_FULL)  { showFullPad(); return; }
  lv_obj_t* box = uiPopupBox(&s_scr, UI_POPUP_LARGE_W, UI_POPUP_LARGE_H);
  if (page == SO_OPTIONS) { buildOptions(box); return; }
  if (page == SO_MAKERS)  { spoolPickBuildMakers(box, s_letter, spoolCatalogFindMaker(s_spec.maker), onPickTap); return; }
  if (page == SO_MAKER)   { spoolPickBuildMaker(box, s_maker, s_spec.choice, onPickTap); return; }
  s_mine_n = spoolMineLoad(s_lists->mine);
  askServer();
  const SpoolPickList list = { s_spec.choice, s_lists->recent, s_spec.auto_tare_g, s_spec.auto_from,
                               s_spec.auto_name, s_lists->mine, s_mine_n, s_lists->server, s_server_n };
  spoolPickBuildList(box, list, onPickTap);
}

// Done, or the density row: the card comes back and takes it from there.
// The close X instead ends the caller too where it asked for that.
static void finish() {
  if (s_spec.card) lv_obj_clear_flag(s_spec.card, LV_OBJ_FLAG_HIDDEN);
  const bool density = s_then_density;
  const bool dismissed = s_dismissed;
  s_then_density = false;
  s_dismissed = false;
  if (dismissed && s_spec.on_dismiss) s_spec.on_dismiss();
  else if (s_spec.on_close)           s_spec.on_close(density);
}

// May come from a handler (the card closes from its own buttons' paths), so
// the page goes the asynchronous way.
void closeSpoolOptions() {
  if (s_page == SO_NONE && s_want == SO_NONE) return;
  if (s_page == SO_PRICE) closePricePad();
  if (s_page == SO_TYPED || s_page == SO_FULL) numPadClose();
  releaseScreen(&s_scr);
  s_page = s_want = SO_NONE;
  s_rebuild = false;
  s_list_only = false;
  s_then_density = false;
  s_dismissed = false;
}

void spoolOptionsTick() {
  pricePadTick();
  if (s_recent_dirty && s_lists) { s_recent_dirty = false; saveRecent(); }
  if (s_want == s_page && !s_rebuild) return;
  s_rebuild = false;
  if (!s_lists) s_lists = psramNew<SoLists>();
  if (!s_lists) {
    // Only before the first page, so nothing was hidden yet: closed as if
    // Back had been tapped at once, and the caller keeps its own choice.
    logSD("SpoolOptions: no memory for the spool lists, page not opened");
    s_want = SO_NONE;
    finish();
    return;
  }
  const SoPage was = s_page;
  const SoPage want = s_want;
  loadRecent();
  leavePage();
  s_page = want;
  if (want == SO_NONE) { finish(); return; }
  logSDf("SHOW: SpoolOptions page %d", (int)want);
  buildPage(want);
  // The card goes under the first page, in the same pass, so nothing else
  // shows through in between.
  if (was == SO_NONE && s_spec.card) lv_obj_add_flag(s_spec.card, LV_OBJ_FLAG_HIDDEN);
  logLvMem("spoolopts/page", (int)want);
}
