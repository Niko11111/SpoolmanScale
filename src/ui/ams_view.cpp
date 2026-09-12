#include "ams_view.h"

#include <Arduino.h>
#include <lvgl.h>
#include <string.h>

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "services/backend_api.h"
#include "services/prefs_store.h"
#include "ui/navigation.h"
#include "ui/ui_common.h"

// Last, and after everything that pulls in ArduinoJson: its template
// parameter T collides with the T() macro this header defines.
#include "lang.h"

// ---- geometry ------------------------------------------------
// Everything is derived from the 480x320 panel and the four bays of an AMS,
// so a change to one number keeps the grid intact.
#define AMSV_MARGIN       8
// The scrollbar is drawn inside the body, so anything aligned to its right
// edge has to stay clear of it or the last glyph disappears under the bar.
#define AMSV_MARGIN_R     16
#define AMSV_TILE_GAP     6
#define AMSV_TILE_W       ((480 - AMSV_MARGIN - AMSV_MARGIN_R - 3 * AMSV_TILE_GAP) / 4)
#define AMSV_TILE_H       58
#define AMSV_UNIT_HDR_H   17
#define AMSV_UNIT_H       (AMSV_UNIT_HDR_H + AMSV_TILE_H + 9)
#define AMSV_BODY_TOP     40
#define AMSV_HEADLINE_H   24
// What is left of the row once the reload chip and its margins are taken off.
#define AMSV_STATUS_W     (480 - AMSV_MARGIN - (AMSV_MARGIN + 56) - 88 - 8)

// Palette, the same one the rest of the interface uses.
#define AMSV_COL_BG       0x0a1828
#define AMSV_COL_LINE     0x1a3050
#define AMSV_COL_ACCENT   0x28d49a
#define AMSV_COL_MUTED    0x4a6fa0
#define AMSV_COL_EMPTY    0x101f33

// Above this a filament colour is bright enough to need dark text on it.
// Weighted the way the eye sees the channels, not a plain average: pure
// green would otherwise take white text and become unreadable.
#define AMSV_LUMA_SWITCH  140

static lv_obj_t*    s_scr       = nullptr;
static lv_obj_t*    s_body      = nullptr;   // scrolling container
static lv_obj_t*    s_status    = nullptr;   // the line shown while loading
static AmsViewMode  s_mode      = AMS_VIEW_BROWSE;
static AmsPickCb    s_cb        = nullptr;
static char         s_headline[48] = "";
static AmsSlotState s_state;

static bool s_build_pending = false;
static bool s_fetch_pending = false;
static bool s_close_pending = false;
// The printers, fetched once and kept: their names are what the status line
// shows, and asking again on every redraw would double the cost of a reload.
static AmsPrinterList s_printers;
static uint8_t s_printer_idx = 0;
static bool s_pick_pending  = false;
static int  s_pick_ams      = -1;
static int  s_pick_tray     = -1;
static int  s_printer_id    = 0;

// Packs a bay into user_data. A pointer sized integer holds both, and the
// pair is what the callback needs - an index into the grid would be wrong
// the moment a refresh reorders it.
#define AMSV_KEY(ams, tray)   ((void*)(intptr_t)(((ams) << 8) | (tray)))
#define AMSV_KEY_AMS(k)       ((int)(((intptr_t)(k) >> 8) & 0xFF))
#define AMSV_KEY_TRAY(k)      ((int)((intptr_t)(k) & 0xFF))

// The chosen printer survives a restart. Not through the settings registry:
// that stores bool and uint8_t, and a database id can exceed 255.
#define AMSV_NVS_PRINTER  "ams_printer"

void requestAmsView(AmsViewMode mode, AmsPickCb cb, const char* headline) {
  s_mode = mode;
  s_cb   = cb;
  s_headline[0] = '\0';
  if (headline) strncpy(s_headline, headline, sizeof(s_headline) - 1);
  // Re-read on every opening. One request more per visit, and in exchange a
  // backend switch, a renamed printer or a removed one can never leave a
  // stale name on the line - this screen is opened rarely enough that the
  // trade is not close.
  s_printers.count = 0;
  s_build_pending = true;
}

bool isAmsViewOpen() { return s_scr != nullptr; }

int  amsViewPrinterId() { return s_printer_id; }

// One place that lets go of the page. The fetch pumps LVGL, so the pointers
// have to be cleared together with the screen: a stale s_body outliving its
// parent is the kind of leftover that writes into freed memory later.
static void closeAmsView() {
  releaseScreen(&s_scr);
  s_body   = nullptr;
  s_status = nullptr;
}

void hideAmsViewOverlays() {
  if (s_scr) lv_obj_add_flag(s_scr, LV_OBJ_FLAG_HIDDEN);
}

void destroyAmsView() {
  closeAmsView();
  s_build_pending = false;
  s_fetch_pending = false;
  s_close_pending = false;
  s_pick_pending  = false;
}

static void setStatus(const char* text) {
  if (!s_status) return;
  char buf[64];
  strncpy(buf, text ? text : "", sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  lv_label_set_text(s_status, buf);
  lv_obj_clear_flag(s_status, LV_OBJ_FLAG_HIDDEN);
}

static void setStatusFmt(int str_id, int value) {
  if (!s_status) return;
  char fmt[48], buf[64];
  strncpy(fmt, T(str_id), sizeof(fmt) - 1);
  fmt[sizeof(fmt) - 1] = '\0';
  snprintf(buf, sizeof(buf), fmt, value);
  lv_label_set_text(s_status, buf);
  lv_obj_clear_flag(s_status, LV_OBJ_FLAG_HIDDEN);
}

static void tileClicked(lv_event_t* e) {
  if (s_mode != AMS_VIEW_PICK || !s_cb) return;
  void* key = lv_obj_get_user_data(lv_event_get_target(e));
  // Nothing but remembering. The callback sends the assignment, and an HTTP
  // request out of an LVGL callback is what this firmware never does: the
  // page it would run from is still on screen and would freeze mid tap.
  s_pick_ams   = AMSV_KEY_AMS(key);
  s_pick_tray  = AMSV_KEY_TRAY(key);
  s_pick_pending  = true;
  s_close_pending = true;
}

// One bay. Two objects: the tile carries the filament colour itself, and a
// single label carries material and fill level on two lines. Four objects a
// tile would be 21 kB of pool for a full AMS setup, which is more than the
// largest free block after a few minutes of navigating.
static lv_obj_t* buildTile(lv_obj_t* parent, const AmsSlotUnit& unit,
                           const AmsSlotTray& tray, int x, int y) {
  if (!lvPoolHasRoomForRow()) return nullptr;

  lv_obj_t* tile = lv_obj_create(parent);
  if (!tile) return nullptr;
  lv_obj_set_size(tile, AMSV_TILE_W, AMSV_TILE_H);
  lv_obj_set_pos(tile, x, y);
  lv_obj_clear_flag(tile, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_radius(tile, 6, 0);
  lv_obj_set_style_pad_all(tile, 0, 0);
  lv_obj_set_style_shadow_width(tile, 0, 0);

  const bool filled = tray.exists && tray.has_color;
  uint32_t bg = filled ? tray.color : AMSV_COL_EMPTY;
  lv_obj_set_style_bg_color(tile, lv_color_hex(bg), 0);

  // The loaded bay is the one thing on this page that says "this is printing
  // right now", so it gets the accent border rather than a colour change.
  const bool active = tray.active;
  lv_obj_set_style_border_width(tile, active ? 2 : 1, 0);
  lv_obj_set_style_border_color(tile,
    lv_color_hex(active ? AMSV_COL_ACCENT : AMSV_COL_LINE), 0);

  uint32_t text_col;
  if (!filled) {
    text_col = AMSV_COL_MUTED;
  } else {
    const uint32_t r = (tray.color >> 16) & 0xFF;
    const uint32_t g = (tray.color >> 8) & 0xFF;
    const uint32_t b = tray.color & 0xFF;
    const uint32_t luma = (299 * r + 587 * g + 114 * b) / 1000;
    text_col = (luma > AMSV_LUMA_SWITCH) ? 0x000000 : 0xFFFFFF;
  }

  char line[72];
  if (!tray.exists) {
    strncpy(line, T(STR_AMSV_EMPTY), sizeof(line) - 1);
    line[sizeof(line) - 1] = '\0';
  } else {
    char name[AMS_NAME_MAX];
    strncpy(name, tray.name[0] ? tray.name : T(STR_AMSV_EMPTY), sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';

    // Grams say more than a percentage when both are known, and the
    // percentage is all there is on a spool the server never weighed.
    char amount[24] = "";
    if (tray.remain_g > 0) {
      snprintf(amount, sizeof(amount), "%d g", (int)tray.remain_g);
    } else if (tray.remain >= 0) {
      snprintf(amount, sizeof(amount), "%d%%", (int)tray.remain);
    }

    // The bay that stands in for this one, appended to the amount rather than
    // given a line of its own: it is a footnote, and a third row of text on a
    // tile this size costs more than it tells.
    if (tray.backup_of[0]) {
      char b[16];
      snprintf(b, sizeof(b), "%s%s", amount[0] ? " - " : "", tray.backup_of);
      strncat(amount, b, sizeof(amount) - strlen(amount) - 1);
    }

    // The colour name only when the server knows one. The tile already
    // carries the colour itself, so this is the name for it, not a repeat.
    if (tray.color_name[0]) {
      snprintf(line, sizeof(line), "%s\n%s\n%s", name, tray.color_name, amount);
    } else if (amount[0]) {
      snprintf(line, sizeof(line), "%s\n%s", name, amount);
    } else {
      snprintf(line, sizeof(line), "%s", name);
    }
  }

  lv_obj_t* lbl = lv_label_create(tile);
  if (!lbl) return tile;
  lv_label_set_text(lbl, line);
  lv_obj_set_style_text_color(lbl, lv_color_hex(text_col), 0);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 0);

  lv_obj_set_user_data(tile, AMSV_KEY(unit.ams_id, tray.tray_id));
  if (s_mode == AMS_VIEW_PICK) {
    lv_obj_add_flag(tile, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(tile, tileClicked, LV_EVENT_CLICKED, nullptr);
  } else {
    lv_obj_clear_flag(tile, LV_OBJ_FLAG_CLICKABLE);
  }
  return tile;
}

// The line above a unit's bays: what it is called on the left, how it feels
// on the right.
static void buildUnitHeader(lv_obj_t* parent, const AmsSlotUnit& unit,
                            int index, int y) {
  char title[32];
  if (unit.label[0]) {
    strncpy(title, unit.label, sizeof(title) - 1);
    title[sizeof(title) - 1] = '\0';
  } else if (unit.is_ext) {
    strncpy(title, T(STR_AMSV_UNIT_EXT), sizeof(title) - 1);
    title[sizeof(title) - 1] = '\0';
  } else {
    char fmt[24];
    strncpy(fmt, T(unit.is_ht ? STR_AMSV_UNIT_HT : STR_AMSV_UNIT), sizeof(fmt) - 1);
    fmt[sizeof(fmt) - 1] = '\0';
    // An AMS HT numbers itself from 128 up, a regular AMS from 0.
    const int shown = unit.is_ht ? (unit.ams_id - 127) : (unit.ams_id + 1);
    snprintf(title, sizeof(title), fmt, shown > 0 ? shown : index + 1);
  }

  lv_obj_t* l = lv_label_create(parent);
  if (!l) return;
  lv_label_set_text(l, title);
  lv_obj_set_style_text_color(l, lv_color_hex(AMSV_COL_MUTED), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(l, AMSV_MARGIN, y);

  // Drying takes the right hand side while it runs: it is the one thing about
  // a unit that is happening rather than merely being the case, and it says
  // more than the humidity it replaces - which is high during a cycle anyway.
  if (unit.drying) {
    char dfmt[40], dbuf[48];
    const bool with_time = (unit.dry_minutes > 0);
    strncpy(dfmt, T(with_time ? STR_AMSV_DRYING : STR_AMSV_DRYING_T),
            sizeof(dfmt) - 1);
    dfmt[sizeof(dfmt) - 1] = '\0';
    if (with_time) {
      snprintf(dbuf, sizeof(dbuf), dfmt, (int)unit.dry_target_c,
               (int)unit.dry_minutes);
    } else {
      snprintf(dbuf, sizeof(dbuf), dfmt, (int)unit.dry_target_c);
    }
    lv_obj_t* d = lv_label_create(parent);
    if (!d) return;
    lv_label_set_text(d, dbuf);
    lv_obj_set_style_text_color(d, lv_color_hex(AMSV_COL_ACCENT), 0);
    lv_obj_set_style_text_font(d, &lv_font_montserrat_ext_12, 0);
    lv_obj_align(d, LV_ALIGN_TOP_RIGHT, -AMSV_MARGIN_R, y);
    return;
  }

  if (unit.humidity == AMS_HUMIDITY_NA && unit.temp_c10 == AMS_TEMP_NA) return;

  char right[32] = "";
  if (unit.humidity != AMS_HUMIDITY_NA) {
    char fmt[16];
    strncpy(fmt, T(unit.humidity_is_level ? STR_AMSV_HUM_LEVEL : STR_AMSV_HUM_PCT),
            sizeof(fmt) - 1);
    fmt[sizeof(fmt) - 1] = '\0';
    snprintf(right, sizeof(right), fmt, (int)unit.humidity);
  }
  if (unit.temp_c10 != AMS_TEMP_NA) {
    char tmp[16];
    snprintf(tmp, sizeof(tmp), "%s%d.%d C", right[0] ? "   " : "",
             unit.temp_c10 / 10, abs(unit.temp_c10 % 10));
    strncat(right, tmp, sizeof(right) - strlen(right) - 1);
  }

  lv_obj_t* r = lv_label_create(parent);
  if (!r) return;
  lv_label_set_text(r, right);
  lv_obj_set_style_text_color(r, lv_color_hex(AMSV_COL_MUTED), 0);
  lv_obj_set_style_text_font(r, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(r, LV_ALIGN_TOP_RIGHT, -AMSV_MARGIN_R, y);
}

// The grid. Kept as its own function because the plan keeps a two step
// fallback in reserve for the case the pool cannot hold a full setup: that
// would be a second function of this shape, over the same tiles.
static void layoutGrid(const AmsSlotState& st) {
  if (!s_body) return;
  logLvMem("amsview/pre", 0);
  int tiles = 0;
  int y = 0;

  for (uint8_t u = 0; u < st.unit_count; u++) {
    const AmsSlotUnit& unit = st.unit[u];
    buildUnitHeader(s_body, unit, u, y);

    int x = AMSV_MARGIN;
    for (uint8_t t = 0; t < unit.tray_count; t++) {
      lv_obj_t* tile = buildTile(s_body, unit, unit.tray[t], x,
                                 y + AMSV_UNIT_HDR_H);
      if (!tile) {
        // Out of pool. Says so instead of leaving a short grid that looks
        // like the printer reported fewer bays than it has.
        setStatus(T(STR_AMSV_ERR_FULL));
        logSDf("AMSVIEW: pool exhausted after %d tiles", tiles);
        logLvMem("amsview/post", tiles);
        return;
      }
      tiles++;
      x += AMSV_TILE_W + AMSV_TILE_GAP;
    }
    y += AMSV_UNIT_H;
  }
  logLvMem("amsview/post", tiles);
}

static void backCb(lv_event_t* e) {
  s_close_pending = true;
}

static void reloadCb(lv_event_t* e) {
  s_fetch_pending = true;
}

// Steps to the next printer. Only reachable when there is more than one, so
// there is no wrap-around to explain on a single printer setup.
static void nextPrinterCb(lv_event_t* e) {
  if (s_printers.count < 2 || s_fetch_pending) return;
  s_printer_idx = (uint8_t)((s_printer_idx + 1) % s_printers.count);
  s_printer_id  = s_printers.p[s_printer_idx].id;
  prefsPutInt(AMSV_NVS_PRINTER, s_printer_id);
  logSDf("AMSVIEW: switched to printer %d \"%s\"", s_printer_id,
         s_printers.p[s_printer_idx].name);
  s_fetch_pending = true;
}

static void buildScreen() {
  closeAmsView();
  s_scr = buildOverlayScreen();
  if (!s_scr) return;

  char title[32];
  strncpy(title, T(STR_AMSV_TITLE), sizeof(title) - 1);
  title[sizeof(title) - 1] = '\0';
  buildSubHeader(s_scr, title, backCb);

  int top = AMSV_BODY_TOP;

  // The spool being placed, so the comparison with a bay is on one screen.
  // Only in PICK: in BROWSE there is no spool in hand and the line would
  // take a row of tiles worth of space to say nothing.
  if (s_mode == AMS_VIEW_PICK && s_headline[0]) {
    lv_obj_t* h = lv_label_create(s_scr);
    if (h) {
      lv_label_set_text(h, s_headline);
      lv_obj_set_style_text_color(h, lv_color_hex(AMSV_COL_ACCENT), 0);
      lv_obj_set_style_text_font(h, &lv_font_montserrat_ext_12, 0);
      lv_obj_set_pos(h, AMSV_MARGIN, top + 4);
    }
    top += AMSV_HEADLINE_H;
  }

  // Status and reload share one row. Stacked they cost 48 of the 280 pixels
  // below the header, which is most of a row of bays.
  lv_obj_t* rl = lv_btn_create(s_scr);
  if (rl) {
    char rlab[20];
    strncpy(rlab, T(STR_AMSV_RELOAD), sizeof(rlab) - 1);
    rlab[sizeof(rlab) - 1] = '\0';
    lv_obj_set_size(rl, 88, 24);
    // Clear of the close button above it: the header's X reaches down to 40
    // and is 48 wide, and a chip tucked under its corner reads as belonging
    // to it.
    lv_obj_align(rl, LV_ALIGN_TOP_RIGHT, -(AMSV_MARGIN + 56), top);
    lv_obj_set_style_bg_color(rl, lv_color_hex(AMSV_COL_LINE), 0);
    lv_obj_set_style_radius(rl, 6, 0);
    lv_obj_set_style_shadow_width(rl, 0, 0);
    lv_obj_add_event_cb(rl, reloadCb, LV_EVENT_CLICKED, nullptr);
    lv_obj_t* rt = lv_label_create(rl);
    if (rt) {
      lv_label_set_text(rt, rlab);
      lv_obj_set_style_text_color(rt, lv_color_hex(AMSV_COL_ACCENT), 0);
      lv_obj_set_style_text_font(rt, &lv_font_montserrat_ext_12, 0);
      lv_obj_align(rt, LV_ALIGN_CENTER, 0, 0);
    }
  }

  s_status = lv_label_create(s_scr);
  if (s_status) {
    lv_label_set_text(s_status, "");
    lv_obj_set_style_text_color(s_status, lv_color_hex(AMSV_COL_MUTED), 0);
    lv_obj_set_style_text_font(s_status, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_pos(s_status, AMSV_MARGIN, top + 6);
    // Bounded and clipped with an ellipsis: the line carries a printer name
    // the user chose, and a long one would otherwise run straight under the
    // reload chip.
    lv_obj_set_width(s_status, AMSV_STATUS_W);
    lv_label_set_long_mode(s_status, LV_LABEL_LONG_DOT);
    // Attached once, here, and not where the text is written: a redraw runs
    // that path again, and a second callback on the same object would step
    // two printers per tap.
    lv_obj_set_ext_click_area(s_status, 12);
    lv_obj_add_event_cb(s_status, nextPrinterCb, LV_EVENT_CLICKED, nullptr);
  }
  top += 28;

  s_body = lv_obj_create(s_scr);
  if (s_body) {
    lv_obj_set_pos(s_body, 0, top);
    lv_obj_set_size(s_body, 480, 320 - top);
    lv_obj_set_style_bg_color(s_body, lv_color_hex(AMSV_COL_BG), 0);
    lv_obj_set_style_bg_opa(s_body, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(s_body, 0, 0);
    lv_obj_set_style_pad_all(s_body, 0, 0);
    lv_obj_set_style_radius(s_body, 0, 0);
    lv_obj_set_scroll_dir(s_body, LV_DIR_VER);
  }
}

// Fills the page. Blocks for the length of the request, so the screen is
// drawn first and pumped, and the screen is checked again afterwards: the
// user can have tapped back during those milliseconds.
static void fetchAndDraw() {
  if (!s_scr) return;
  setStatus(T(STR_AMSV_LOADING));

  for (int i = 0; i < 5; i++) {
    lv_timer_handler();
    delay(5);
  }
  if (!s_scr) return;

  if (!wifi_ok) {
    setStatus(T(STR_AMSV_ERR_NET));
    return;
  }

  if (s_printers.count == 0) {
    int code = backendListPrinters(s_printers, 8000);
    if (!s_scr) return;
    if (code != 200) {
      setStatusFmt(STR_AMSV_ERR_HTTP, code);
      return;
    }
    if (s_printers.count == 0) {
      setStatus(T(STR_AMSV_NO_PRINTER));
      return;
    }

    // The one chosen last time, if it is still there. A printer that has been
    // removed silently falls back to the first rather than showing an error
    // about a machine the user has already forgotten about.
    const int stored = prefsGetInt(AMSV_NVS_PRINTER, 0);
    s_printer_idx = 0;
    for (uint8_t i = 0; i < s_printers.count; i++) {
      if (s_printers.p[i].id == stored) { s_printer_idx = i; break; }
    }
    s_printer_id = s_printers.p[s_printer_idx].id;
  }

  int code = backendGetAmsState(s_printer_id, s_state, 8000);
  if (!s_scr) return;
  if (code != 200) {
    setStatusFmt(STR_AMSV_ERR_HTTP, code);
    return;
  }

  // Redraw from scratch: a reload after a spool moved has to lose the old
  // tiles, and clean() is the only way that also frees them.
  if (s_body) lv_obj_clean(s_body);

  if (s_state.unit_count == 0) {
    setStatus(T(STR_AMSV_NO_AMS));
    return;
  }

  // The status line carries the printer and what it is doing. It is the only
  // place the printer is named, and with several of them configured that is
  // the difference between a board and somebody else's board.
  {
    char line[64];
    char pos[16] = "";
    // Only when there is something to step through. On one printer the
    // "1/1" would be noise and the line would look like a control that does
    // nothing.
    if (s_printers.count > 1) {
      char fmt[12];
      strncpy(fmt, T(STR_AMSV_PRN_OF), sizeof(fmt) - 1);
      fmt[sizeof(fmt) - 1] = '\0';
      char n[12];
      snprintf(n, sizeof(n), fmt, (int)s_printer_idx + 1, (int)s_printers.count);
      snprintf(pos, sizeof(pos), "%s  ", n);
    }
    char body[64];
    if (!s_state.connected) {
      // An offline printer still has a last known state worth showing, so
      // this is a note next to the grid rather than a refusal to draw it.
      snprintf(body, sizeof(body), "%s - %s", s_state.printer,
               T(STR_AMSV_OFFLINE));
    } else if (s_state.job_percent >= 0) {
      char fmt[24];
      strncpy(fmt, T(STR_AMSV_JOB), sizeof(fmt) - 1);
      fmt[sizeof(fmt) - 1] = '\0';
      char job[24];
      snprintf(job, sizeof(job), fmt, (int)s_state.job_percent);
      snprintf(body, sizeof(body), "%s - %s", s_state.printer, job);
    } else if (s_state.state[0]) {
      snprintf(body, sizeof(body), "%s - %s", s_state.printer, s_state.state);
    } else {
      snprintf(body, sizeof(body), "%s", s_state.printer);
    }
    snprintf(line, sizeof(line), "%s%s", pos, body);
    setStatus(line);

    // Tapping the line steps to the next printer. The line names the printer
    // anyway, so it is where a user looks for one - cheaper than a page of
    // its own and it costs no room on a screen that has none. The accent
    // colour is what says it can be tapped at all.
    if (s_status) {
      const bool switchable = (s_printers.count > 1);
      if (switchable) lv_obj_add_flag(s_status, LV_OBJ_FLAG_CLICKABLE);
      else            lv_obj_clear_flag(s_status, LV_OBJ_FLAG_CLICKABLE);
      lv_obj_set_style_text_color(
        s_status, lv_color_hex(switchable ? AMSV_COL_ACCENT : AMSV_COL_MUTED), 0);
    }
  }

  layoutGrid(s_state);
}

void handleAmsViewDeferredActions() {
  if (show_ams_view_pending) {
    show_ams_view_pending = false;
    requestAmsView(AMS_VIEW_BROWSE);
  }

  // Closing comes first, so a pick that asked to close does not run its
  // request with the page still up. releaseScreen() frees asynchronously and
  // appLoop() has already been through lv_timer_handler(), so by the next
  // pass the page is really gone and a blocking request freezes nothing.
  if (s_close_pending) {
    s_close_pending = false;
    s_fetch_pending = false;
    closeAmsView();
    showMainScreen();
    return;
  }

  // Last, and a pass after the close: this is the one that talks to the
  // server.
  if (s_pick_pending) {
    s_pick_pending = false;
    if (s_cb && s_pick_ams >= 0 && s_pick_tray >= 0) {
      s_cb(s_pick_ams, s_pick_tray);
    }
    s_pick_ams  = -1;
    s_pick_tray = -1;
    return;
  }

  if (s_build_pending) {
    s_build_pending = false;
    s_printer_id = 0;
    // Built first, then everything else hidden, then shown: the same order
    // every other overlay uses, and the reason buildOverlayScreen() hands
    // back a hidden object in the first place.
    buildScreen();
    hideAllOverlays();
    if (s_scr) lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_HIDDEN);
    s_fetch_pending = true;
    return;      // one pass to draw, the next one to fetch
  }

  if (s_fetch_pending) {
    s_fetch_pending = false;
    fetchAndDraw();
  }
}
