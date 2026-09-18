#include "ams_view.h"

#include <Arduino.h>
#include <lvgl.h>
#include <string.h>

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "services/ams_weights.h"
#include "services/backend_api.h"
#include "services/prefs_store.h"
#include "ui/ams_detail_popup.h"
#include "ui/loading_overlay.h"
#include "ui/navigation.h"
#include "ui/theme.h"
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
// The status row: the printer's name, as a chip when there is more than one
// printer to step through, and what the printer is doing beside it. The row
// has the whole width since the reload chip moved up into the header - it
// used to share this row, which squeezed the printer into 12 px of text that
// was hard to read and, with two printers, did not look like the switch it is.
#define AMSV_STATUS_ROW_H 36
#define AMSV_CHIP_H       28
#define AMSV_CHIP_PAD_X   12
// The label inside the chip gets this much more than its text, so the
// simulator's check does not count a chip sized to its text as tight.
#define AMSV_CHIP_TXT_SLACK 10
#define AMSV_CHIP_GAP     10
// Room the status keeps beside the widest printer chip, so a long name cuts
// with dots inside the chip rather than pushing the status off the row.
#define AMSV_STATUS_MIN_W 120
#define AMSV_RELOAD_W     88
// The header's buttons are 44 px tall and 2 px down (addBackButton and
// addCloseButton in ui_common.cpp), so their middle is at 24; the reload chip
// sits on that line, centred between the title and the close button.
#define AMSV_HDR_MID      24
#define AMSV_HDR_BTN_W    44
#define AMSV_HDR_BTN_IN   4
// Finger room around the printer chip beyond its 28 px. Four, not more:
// the chip sits under the back button's corner, and a wider halo would take
// that button's lowest taps.
#define AMSV_STATUS_EXT_CLICK 4
// Air between the printer chip and the back button above it. The row and
// the grid move down by this much, but only with two or more printers -
// only then is there a chip, and a single printer page should not lose
// height to a control it does not have.
#define AMSV_CHIP_AIR     8
// What the row offers a line of text: from the left margin to the scrollbar's
// margin on the right.
#define AMSV_STATUS_W     (480 - AMSV_MARGIN - AMSV_MARGIN_R)
// How the page is pumped before a blocking fetch, so the loading line is
// drawn and a tap on back is seen: passes and the pause between them.
#define AMSV_PUMP_PASSES  5
#define AMSV_PUMP_MS      5
// The PICK headline: the spool name and the question around it. Sized to
// what amsPickShow() builds, so nothing is cut on the way in.
#define AMSV_HEADLINE_MAX 80
// The footer of a PICK or WINDOW page: one strip for the buttons, kept low
// so it costs less than a row of bays, with the hit area widened instead.
#define AMSV_FOOT_H       40
#define AMSV_FOOT_BTN_W   150
#define AMSV_FOOT_BTN_H   30
#define AMSV_FOOT_BTN_EXT 6
#define AMSV_FOOT_GAP     12

// Palette, from the one table in theme.h. The local names stay so the
// drawing code below reads as before; what they mean is decided there.
#define AMSV_COL_BG       UI_COL_SURFACE_2
#define AMSV_COL_LINE     UI_COL_ROW_PRESSED
#define AMSV_COL_ACCENT   UI_COL_ACCENT
#define AMSV_COL_MUTED    UI_COL_CAPTION
// A running cycle: amber, because the unit is warm. Green read as a state
// that is fine rather than as something happening.
#define AMSV_COL_WARM     UI_COL_WARN
#define AMSV_COL_EMPTY    UI_COL_EMPTY

// Above this a filament colour is bright enough to need dark text on it.
// Weighted the way the eye sees the channels, not a plain average: pure
// green would otherwise take white text and become unreadable.
#define AMSV_LUMA_SWITCH  140

static lv_obj_t*    s_scr       = nullptr;
static lv_obj_t*    s_body      = nullptr;   // scrolling container
static lv_obj_t*    s_status    = nullptr;   // the line shown while loading
// The printer's name as a chip, built once and shown only with two or more
// printers; the status label moves right to make room for it.
static lv_obj_t*    s_printer_btn = nullptr;
static lv_obj_t*    s_printer_lbl = nullptr;
// Where the status row and the body were built, so applyRowDrop() can move
// them by AMSV_CHIP_AIR once the printers are known and there are two.
static int          s_row_top  = 0;
static int          s_body_top = 0;
static int          s_body_h   = 0;
static AmsViewMode  s_mode      = AMS_VIEW_BROWSE;
static AmsPickCb    s_cb        = nullptr;
static char         s_headline[AMSV_HEADLINE_MAX] = "";
static AmsSlotState s_state;

static bool s_build_pending = false;
static bool s_fetch_pending = false;
// Weights came in while the detail card stood over the grid. Drawn as soon
// as the card is gone; without this they would wait for the next fetch.
static bool s_weights_redraw = false;
static bool s_close_pending = false;
// The printers, fetched once and kept: their names are what the status line
// shows, and asking again on every redraw would double the cost of a reload.
static AmsPrinterList s_printers;
static uint8_t s_printer_idx = 0;
static bool s_pick_pending  = false;
static int  s_pick_ams      = -1;
static int  s_pick_tray     = -1;
static int  s_printer_id    = 0;
// A bay was tapped for its detail card. Carried like every other answer:
// parked here, acted on from the loop, because the fetch behind it blocks.
static bool s_detail_pending = false;
static int  s_detail_ams     = -1;
static int  s_detail_tray    = -1;
// PICK only. While it is on, a tap opens the card instead of answering the
// question, so the bays can be read before one of them is chosen.
static bool s_info_mode      = false;
static lv_obj_t* s_info_btn  = nullptr;
static lv_obj_t* s_headline_lbl = nullptr;
// Where the page goes back to. Opened from the scale menu it returns there;
// from the header chip, the zone-4 button or the picker it lands on the main
// screen, which is where those were pressed.
static bool s_return_to_scale_menu = false;

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
  if (headline) snprintf(s_headline, sizeof(s_headline), "%s", headline);
  // Re-read on every opening. One request more per visit, and in exchange a
  // backend switch, a renamed printer or a removed one can never leave a
  // stale name on the line - this screen is opened rarely enough that the
  // trade is not close.
  s_printers.count = 0;
  // A fresh question. An answer parked by an earlier page must not be handed
  // to this one's callback.
  s_pick_pending = false;
  s_pick_ams     = -1;
  s_pick_tray    = -1;
  // And a fresh switch. Only the close through showMainScreen() reaches
  // destroyAmsView(); coming back from the scale menu does not, so without
  // this an info mode left on once would still be on the next time a
  // question was asked - and the tap that was meant to choose a bay would
  // open a card instead.
  s_info_mode      = false;
  s_detail_pending = false;
  s_detail_ams     = -1;
  s_detail_tray    = -1;
  s_return_to_scale_menu = false;
  s_build_pending = true;
}

void requestAmsViewFromScaleMenu() {
  requestAmsView(AMS_VIEW_BROWSE);
  s_return_to_scale_menu = true;
}

bool isAmsViewOpen() { return s_scr != nullptr; }

int  amsViewPrinterId() { return s_printer_id; }

// One place that lets go of the page. The fetch pumps LVGL, so the pointers
// have to be cleared together with the screen: a stale s_body outliving its
// parent is the kind of leftover that writes into freed memory later.
static void closeAmsView() {
  // The card sits on lv_scr_act(), not inside the page, so freeing the page
  // would leave it standing over whatever comes next.
  closeAmsDetailPopup();
  releaseScreen(&s_scr);
  s_body     = nullptr;
  s_status   = nullptr;
  s_info_btn = nullptr;
  s_headline_lbl = nullptr;
  s_printer_btn  = nullptr;
  s_printer_lbl  = nullptr;
}

void hideAmsViewOverlays() {
  closeAmsDetailPopup();
  if (s_scr) lv_obj_add_flag(s_scr, LV_OBJ_FLAG_HIDDEN);
}

// Hands the callback "no answer" when a PICK page goes away without a tap,
// so the note behind the question is dropped rather than asked again on the
// next removal. Not while an answer is already parked: that one is the
// answer, and it runs one pass later.
static bool modeAsks() {
  return s_mode == AMS_VIEW_PICK || s_mode == AMS_VIEW_WINDOW;
}

static void signalDismissIfUnanswered() {
  if (!modeAsks() || !s_cb || s_pick_pending) return;
  s_pick_ams     = -1;
  s_pick_tray    = -1;
  s_pick_pending = true;
}

void destroyAmsView() {
  if (s_scr) signalDismissIfUnanswered();
  closeAmsView();
  s_build_pending = false;
  s_fetch_pending = false;
  s_close_pending = false;
  s_return_to_scale_menu = false;
  // Unlike s_pick_pending below, this one goes: it opens a card over a page
  // that is being torn down, and there is nothing left to open it against.
  s_detail_pending = false;
  s_info_mode = false;
  // s_pick_pending stays. Every pick closes the page first, and that close
  // goes through showMainScreen() and lands here - clearing the flag would
  // swallow the user's answer one pass before it runs, which is exactly what
  // beta.28 did: no bay was ever assigned.
}

// The row as one line of text: the printer chip hidden, the label from the
// margin across the width. What every message wants - loading, an error, a
// note - and what a single printer setup shows all the time. The chip comes
// back with the next drawn state.
// Keyed on the printer count rather than on the chip's visibility, so a
// reload - which lays the row plain while it loads - does not bounce the
// grid up and down by eight pixels every time.
static int rowDrop() { return (s_printers.count > 1) ? AMSV_CHIP_AIR : 0; }

static void applyRowDrop() {
  const int drop   = rowDrop();
  const int chip_y = s_row_top + (AMSV_STATUS_ROW_H - AMSV_CHIP_H) / 2 + drop;
  const lv_coord_t lh = lv_font_get_line_height(UI_FONT_BODY);
  if (s_printer_btn) lv_obj_set_y(s_printer_btn, chip_y);
  if (s_status)      lv_obj_set_y(s_status, chip_y + (AMSV_CHIP_H - lh) / 2);
  if (s_body) {
    lv_obj_set_y(s_body, s_body_top + drop);
    lv_obj_set_height(s_body, s_body_h - drop);
  }
}

static void statusRowPlain() {
  applyRowDrop();
  if (s_printer_btn) lv_obj_add_flag(s_printer_btn, LV_OBJ_FLAG_HIDDEN);
  if (s_status) {
    lv_obj_set_x(s_status, AMSV_MARGIN);
    lv_obj_set_width(s_status, AMSV_STATUS_W);
  }
}

static void setStatus(const char* text) {
  if (!s_status) return;
  statusRowPlain();
  char buf[64];
  strncpy(buf, text ? text : "", sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  lv_label_set_text(s_status, buf);
  lv_obj_clear_flag(s_status, LV_OBJ_FLAG_HIDDEN);
}

static void setStatusFmt(int str_id, int value) {
  if (!s_status) return;
  statusRowPlain();
  char fmt[48], buf[64];
  copyT(fmt, sizeof(fmt), str_id);
  snprintf(buf, sizeof(buf), fmt, value);
  lv_label_set_text(s_status, buf);
  lv_obj_clear_flag(s_status, LV_OBJ_FLAG_HIDDEN);
}

// The bay behind a packed key, or nullptr. Looked up by the pair rather than
// by a grid index for the same reason the callback carries the pair: a
// refresh can reorder the grid between the tap and the answer.
static const AmsSlotTray* findTray(int ams_id, int tray_id,
                                   const AmsSlotUnit** out_unit) {
  for (uint8_t u = 0; u < s_state.unit_count; u++) {
    const AmsSlotUnit& unit = s_state.unit[u];
    if (unit.ams_id != (uint8_t)ams_id) continue;
    for (uint8_t t = 0; t < unit.tray_count; t++) {
      if (unit.tray[t].tray_id != (uint8_t)tray_id) continue;
      if (out_unit) *out_unit = &unit;
      return &unit.tray[t];
    }
  }
  return nullptr;
}

static bool trayExists(int ams_id, int tray_id) {
  const AmsSlotTray* t = findTray(ams_id, tray_id, nullptr);
  return t && t->exists;
}

static bool unitIsExt(int ams_id) {
  for (uint8_t u = 0; u < s_state.unit_count; u++) {
    if (s_state.unit[u].ams_id == (uint8_t)ams_id) return s_state.unit[u].is_ext;
  }
  return false;
}

// Whether a tap means "show me this spool" rather than "put it here".
// Everywhere except a question, and inside a question while the info switch
// is on. The future FilaMan picker will be AMS_VIEW_PICK as well, so it
// inherits this without a line of its own.
static bool modeShowsDetail() {
  return s_mode != AMS_VIEW_PICK || s_info_mode;
}

static void tileClicked(lv_event_t* e) {
  lv_obj_t* tile = lv_event_get_target(e);
  void* key = lv_obj_get_user_data(tile);
  const int ams  = AMSV_KEY_AMS(key);
  const int tray = AMSV_KEY_TRAY(key);

  if (modeShowsDetail()) {
    // Only a bay with something in it has anything to tell. An empty one is
    // not clickable outside PICK at all, and inside PICK the info switch
    // makes it inert rather than answering the question by accident.
    if (!trayExists(ams, tray)) return;
    s_detail_ams     = ams;
    s_detail_tray    = tray;
    s_detail_pending = true;
    // No close: the card lies over the page, and there is nothing to come
    // back to because it answers nothing.
    return;
  }

  if (!s_cb) return;
  // The external holder is not a bay a spool can be pinned to - the server
  // refuses it. It used to be built unclickable, which left a tap on it
  // silent; now it says why.
  if (unitIsExt(ams)) {
    setStatus(T(STR_AMSV_EXT_NO_PICK));
    return;
  }
  // Nothing but remembering. The callback sends the assignment, and an HTTP
  // request out of an LVGL callback is what this firmware never does: the
  // page it would run from is still on screen and would freeze mid tap.
  s_pick_ams   = ams;
  s_pick_tray  = tray;
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

  // A filled bay is always three lines, in the same order, with a dash where
  // a value is missing. Built the other way round - a line only when there is
  // something to put on it - the same bay read as two lines on one tile and
  // three on the next, and because the label is centred the text sat at a
  // different height in each. Nothing was wrong with any single tile; the row
  // of them looked broken.
  char line[72];
  if (!tray.exists) {
    // An empty bay stays one line. There is nothing to line up with, and the
    // difference between "nothing in here" and "something with no data"
    // should stay visible at a glance.
    copyT(line, sizeof(line), STR_AMSV_EMPTY);
  } else {
    char name[AMS_NAME_MAX];
    strncpy(name, tray.name[0] ? tray.name : T(STR_AMSV_EMPTY), sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';

    // color_name arrives cleaned - the parser drops a hex code and strips an
    // article number before it stores anything, because the field is too
    // short to hold "Charcoal (11101)" and clean it afterwards.

    // Grams say more than a percentage when both are known, and the
    // percentage is all there is on a spool the server never weighed.
    char amount[24] = "";
    if (tray.remain_g > 0) {
      snprintf(amount, sizeof(amount), "%d g", (int)tray.remain_g);
    } else if (tray.remain >= 0) {
      snprintf(amount, sizeof(amount), "%d%%", (int)tray.remain);
    }

    // The bay that stands in for this one, appended to the amount rather than
    // given a line of its own: it is a footnote, and a fourth row of text on a
    // tile this size costs more than it tells.
    if (tray.backup_of[0]) {
      char b[16];
      snprintf(b, sizeof(b), "%s%s", amount[0] ? " - " : "", tray.backup_of);
      strncat(amount, b, sizeof(amount) - strlen(amount) - 1);
    }

    snprintf(line, sizeof(line), "%s\n%s\n%s",
             name,
             tray.color_name[0] ? tray.color_name : "-",
             amount[0]          ? amount          : "-");
  }

  lv_obj_t* lbl = lv_label_create(tile);
  if (!lbl) return tile;
  lv_label_set_text(lbl, line);
  lv_obj_set_style_text_color(lbl, lv_color_hex(text_col), 0);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 0);

  lv_obj_set_user_data(tile, AMSV_KEY(unit.ams_id, tray.tray_id));
  // In a question every bay answers, including the external holder, which
  // tileClicked() then turns down with a reason - the tap used to land in
  // silence. Elsewhere only a filled bay is worth a tap, because all it can
  // do is show what is in it.
  const bool pickable = (s_mode == AMS_VIEW_PICK) || tray.exists;
  if (pickable) {
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
    copyT(title, sizeof(title), STR_AMSV_UNIT_EXT);
  } else {
    char fmt[24];
    copyT(fmt, sizeof(fmt), unit.is_ht ? STR_AMSV_UNIT_HT : STR_AMSV_UNIT);
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

  // The right hand side: how the unit feels, and while a cycle runs what it
  // is doing as well. Drying leads and the climate follows it rather than
  // being replaced - a heated unit is exactly when its own temperature is
  // worth reading.
  char right[40] = "";
  if (unit.humidity != AMS_HUMIDITY_NA) {
    char fmt[16];
    copyT(fmt, sizeof(fmt), unit.humidity_is_level ? STR_AMSV_HUM_LEVEL : STR_AMSV_HUM_PCT);
    snprintf(right, sizeof(right), fmt, (int)unit.humidity);
  }
  if (unit.temp_c10 != AMS_TEMP_NA) {
    char tmp[16];
    snprintf(tmp, sizeof(tmp), "%s%d.%d °C", right[0] ? "   " : "",
             unit.temp_c10 / 10, abs(unit.temp_c10 % 10));
    strncat(right, tmp, sizeof(right) - strlen(right) - 1);
  }

  char line[96] = "";
  if (unit.drying) {
    // Only the figures the printer really reported. An AMS HT sends the
    // minutes left and no target temperature at all, and printing it anyway
    // put the sentinel on the screen as "Trocknet -1 °C, 674 min".
    char dfmt[40], dbuf[48];
    const bool with_time = (unit.dry_minutes > 0);
    const bool with_temp = (unit.dry_target_c > 0);
    if (with_temp && with_time) {
      copyT(dfmt, sizeof(dfmt), STR_AMSV_DRYING_TIME);
      snprintf(dbuf, sizeof(dbuf), dfmt, (int)unit.dry_target_c,
               (int)unit.dry_minutes);
    } else if (with_temp) {
      copyT(dfmt, sizeof(dfmt), STR_AMSV_DRYING_TEMP);
      snprintf(dbuf, sizeof(dbuf), dfmt, (int)unit.dry_target_c);
    } else if (with_time) {
      copyT(dfmt, sizeof(dfmt), STR_AMSV_DRYING_MIN);
      snprintf(dbuf, sizeof(dbuf), dfmt, (int)unit.dry_minutes);
    } else {
      copyT(dbuf, sizeof(dbuf), STR_AMSV_DRYING);
    }
    snprintf(line, sizeof(line), "%s%s%s", dbuf, right[0] ? "   " : "", right);
  } else {
    snprintf(line, sizeof(line), "%s", right);
  }

  if (!line[0]) return;

  lv_obj_t* r = lv_label_create(parent);
  if (!r) return;
  lv_label_set_text(r, line);
  lv_obj_set_style_text_color(r,
    lv_color_hex(unit.drying ? AMSV_COL_WARM : AMSV_COL_MUTED), 0);
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

// The footer's Cancel: the same "not now" the X in the header gives, as a
// word at the bottom where the finger already is.
static void footCancelCb(lv_event_t* e) {
  s_close_pending = true;
}

// WINDOW: open FilaMan's assignment window. (0, 0) is the answer the
// callback reads as "open"; the request itself runs one pass later, with
// the page gone.
static void footOpenCb(lv_event_t* e) {
  s_pick_ams      = 0;
  s_pick_tray     = 0;
  s_pick_pending  = true;
  s_close_pending = true;
}

static lv_obj_t* footButton(int x, int str_id, bool primary, lv_event_cb_t cb) {
  lv_obj_t* b = lv_btn_create(s_scr);
  if (!b) return nullptr;
  lv_obj_set_size(b, AMSV_FOOT_BTN_W, AMSV_FOOT_BTN_H);
  lv_obj_set_pos(b, x, 320 - AMSV_FOOT_H + (AMSV_FOOT_H - AMSV_FOOT_BTN_H) / 2);
  lv_obj_set_style_bg_color(b, lv_color_hex(primary ? UI_COL_OK_BG : UI_COL_SURFACE_2), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(primary ? UI_COL_OK_BG_PRESSED : UI_COL_LINE), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(b, 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(primary ? UI_COL_OK_BG_PRESSED : UI_COL_LINE), 0);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  // Under the 44 px touch minimum by design, so the strip stays small; the
  // hit area is widened instead.
  lv_obj_set_ext_click_area(b, AMSV_FOOT_BTN_EXT);
  lv_obj_add_event_cb(b, cb, LV_EVENT_CLICKED, nullptr);
  lv_obj_t* l = lv_label_create(b);
  if (l) {
    char t[24];
    copyT(t, sizeof(t), str_id);
    lv_label_set_text(l, t);
    lv_obj_set_style_text_color(l, lv_color_hex(primary ? UI_COL_OK_TEXT : UI_COL_INK_2), 0);
    lv_obj_set_style_text_font(l, UI_FONT_SMALL, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0);
  }
  return b;
}

// Puts the info switch and the headline into whichever state s_info_mode is
// in. Both change together and neither needs a redraw of the grid: the tiles
// stay clickable either way, only what a tap means changes.
static void applyInfoMode() {
  if (s_info_btn) {
    const bool on = s_info_mode;
    lv_obj_set_style_border_width(s_info_btn, on ? 2 : 1, 0);
    lv_obj_set_style_border_color(s_info_btn,
      lv_color_hex(on ? UI_COL_ACCENT : UI_COL_LINE), 0);
    lv_obj_set_style_bg_color(s_info_btn,
      lv_color_hex(on ? UI_COL_ACCENT_DIM : UI_COL_SURFACE_2), 0);
    lv_obj_t* l = lv_obj_get_child(s_info_btn, 0);
    if (l) {
      lv_obj_set_style_text_color(l,
        lv_color_hex(on ? UI_COL_ACCENT : UI_COL_INK_2), 0);
    }
  }
  if (s_headline_lbl) {
    // The headline is the one line that says what a tap will do, so it is the
    // line that has to change when that changes.
    char buf[AMSV_HEADLINE_MAX];
    if (s_info_mode) copyT(buf, sizeof(buf), STR_AMSV_INFO_HINT);
    else             snprintf(buf, sizeof(buf), "%s", s_headline);
    lv_label_set_text(s_headline_lbl, buf);
    lv_obj_set_style_text_color(s_headline_lbl,
      lv_color_hex(s_info_mode ? UI_COL_INK_SOFT : AMSV_COL_ACCENT), 0);
  }
}

static void footInfoCb(lv_event_t* e) {
  s_info_mode = !s_info_mode;
  // Safe inside the callback: nothing is created or freed here, only styles
  // and one label's text.
  applyInfoMode();
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
  copyT(title, sizeof(title), STR_AMSV_TITLE);
  buildSubHeader(s_scr, title, backCb);

  // The reload chip, in the header between the title and the close button,
  // centred in the gap. The title's width is measured rather than assumed: it
  // differs per language, and a chip that is symmetric in one and off by
  // twenty pixels in the other would read as a mistake in the second.
  {
    lv_obj_t* rl = lv_btn_create(s_scr);
    if (rl) {
      char rlab[20];
      copyT(rlab, sizeof(rlab), STR_AMSV_RELOAD);
      const lv_coord_t tw = lv_txt_get_width(title, (uint32_t)strlen(title),
                                             UI_FONT_TITLE, 0, LV_TEXT_FLAG_NONE);
      const int title_right = 240 + tw / 2;
      const int close_left  = 480 - AMSV_HDR_BTN_IN - AMSV_HDR_BTN_W;
      const int x = (title_right + close_left) / 2 - AMSV_RELOAD_W / 2;
      lv_obj_set_size(rl, AMSV_RELOAD_W, AMSV_CHIP_H);
      lv_obj_set_pos(rl, x, AMSV_HDR_MID - AMSV_CHIP_H / 2);
      lv_obj_set_style_bg_color(rl, lv_color_hex(AMSV_COL_LINE), 0);
      lv_obj_set_style_radius(rl, 6, 0);
      lv_obj_set_style_shadow_width(rl, 0, 0);
      lv_obj_add_event_cb(rl, reloadCb, LV_EVENT_CLICKED, nullptr);
      lv_obj_t* rt = lv_label_create(rl);
      if (rt) {
        lv_label_set_text(rt, rlab);
        lv_obj_set_style_text_color(rt, lv_color_hex(AMSV_COL_ACCENT), 0);
        lv_obj_set_style_text_font(rt, UI_FONT_SMALL, 0);
        lv_obj_align(rt, LV_ALIGN_CENTER, 0, 0);
      }
    }
  }

  int top = AMSV_BODY_TOP;

  // The spool being placed, so the comparison with a bay is on one screen.
  // Only in PICK: in BROWSE there is no spool in hand and the line would
  // take a row of tiles worth of space to say nothing.
  if (modeAsks() && s_headline[0]) {
    lv_obj_t* h = lv_label_create(s_scr);
    if (h) {
      lv_label_set_text(h, s_headline);
      lv_obj_set_style_text_color(h, lv_color_hex(AMSV_COL_ACCENT), 0);
      lv_obj_set_style_text_font(h, &lv_font_montserrat_ext_12, 0);
      lv_obj_set_pos(h, AMSV_MARGIN, top + 4);
      // Kept so the info switch can rewrite it. Cleared in closeAmsView()
      // along with the rest, because the page is rebuilt on every opening.
      s_headline_lbl = h;
    }
    top += AMSV_HEADLINE_H;
  }

  // The status row: the printer chip first, hidden until the printers are
  // known and there are two of them, and the status label after it - or from
  // the margin, when the chip is away. Sized to its text when it is shown.
  s_row_top = top;
  const int chip_y = top + (AMSV_STATUS_ROW_H - AMSV_CHIP_H) / 2;
  const lv_coord_t lh = lv_font_get_line_height(UI_FONT_BODY);
  s_printer_btn = lv_btn_create(s_scr);
  if (s_printer_btn) {
    lv_obj_set_size(s_printer_btn, AMSV_RELOAD_W, AMSV_CHIP_H);
    lv_obj_set_pos(s_printer_btn, AMSV_MARGIN, chip_y);
    lv_obj_set_style_bg_color(s_printer_btn, lv_color_hex(AMSV_COL_LINE), 0);
    lv_obj_set_style_radius(s_printer_btn, 6, 0);
    lv_obj_set_style_shadow_width(s_printer_btn, 0, 0);
    lv_obj_set_style_pad_all(s_printer_btn, 0, 0);
    lv_obj_set_ext_click_area(s_printer_btn, AMSV_STATUS_EXT_CLICK);
    lv_obj_add_flag(s_printer_btn, LV_OBJ_FLAG_HIDDEN);
    // Attached once, here, and not where the text is written: a redraw runs
    // that path again, and a second callback on the same object would step
    // two printers per tap.
    lv_obj_add_event_cb(s_printer_btn, nextPrinterCb, LV_EVENT_CLICKED, nullptr);
    s_printer_lbl = lv_label_create(s_printer_btn);
    if (s_printer_lbl) {
      lv_label_set_text(s_printer_lbl, "");
      lv_obj_set_style_text_color(s_printer_lbl, lv_color_hex(AMSV_COL_ACCENT), 0);
      lv_obj_set_style_text_font(s_printer_lbl, UI_FONT_BODY, 0);
      lv_obj_set_style_text_align(s_printer_lbl, LV_TEXT_ALIGN_CENTER, 0);
      lv_label_set_long_mode(s_printer_lbl, LV_LABEL_LONG_DOT);
      lv_obj_align(s_printer_lbl, LV_ALIGN_CENTER, 0, 0);
    }
  }

  s_status = lv_label_create(s_scr);
  if (s_status) {
    lv_label_set_text(s_status, "");
    lv_obj_set_style_text_color(s_status, lv_color_hex(UI_COL_INK_2), 0);
    lv_obj_set_style_text_font(s_status, UI_FONT_BODY, 0);
    // One line with a real height, so a long printer name is cut with dots
    // rather than wrapped into the grid below.
    lv_obj_set_size(s_status, AMSV_STATUS_W, lh);
    lv_label_set_long_mode(s_status, LV_LABEL_LONG_DOT);
    lv_obj_set_pos(s_status, AMSV_MARGIN, chip_y + (AMSV_CHIP_H - lh) / 2);
  }
  top += AMSV_STATUS_ROW_H;

  // A question leaves room for its footer; a look at the bays does not.
  const int foot = modeAsks() ? AMSV_FOOT_H : 0;

  s_body_top = top;
  s_body_h   = 320 - top - foot;
  s_body = lv_obj_create(s_scr);
  if (s_body) {
    lv_obj_set_pos(s_body, 0, top);
    lv_obj_set_size(s_body, 480, 320 - top - foot);
    lv_obj_set_style_bg_color(s_body, lv_color_hex(AMSV_COL_BG), 0);
    lv_obj_set_style_bg_opa(s_body, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(s_body, 0, 0);
    lv_obj_set_style_pad_all(s_body, 0, 0);
    lv_obj_set_style_radius(s_body, 0, 0);
    lv_obj_set_scroll_dir(s_body, LV_DIR_VER);
  }

  // The footer. PICK: a way out in words, the X alone was easy to miss, and
  // the info switch beside it - the one place a tap already means something,
  // so the only place the two have to be told apart.
  // WINDOW: the one action this mode exists for, and the way out beside it.
  if (s_mode == AMS_VIEW_PICK) {
    s_info_btn = footButton(240 - AMSV_FOOT_GAP / 2 - AMSV_FOOT_BTN_W,
                            STR_AMSV_INFO, false, footInfoCb);
    footButton(240 + AMSV_FOOT_GAP / 2, STR_CANCEL, false, footCancelCb);
    applyInfoMode();
  } else if (s_mode == AMS_VIEW_WINDOW) {
    footButton(240 - AMSV_FOOT_GAP / 2 - AMSV_FOOT_BTN_W, STR_AMSV_BTN_WINDOW, true, footOpenCb);
    footButton(240 + AMSV_FOOT_GAP / 2, STR_CANCEL, false, footCancelCb);
  }
}

// What the printer's state word means, across the spellings the drivers
// use. Bambu's gcode_state is RUNNING, PAUSE, FINISH, FAILED, IDLE, PREPARE
// and SLICING; a driver that normalises writes the participle instead.
// Matched without case, and anything else is PRINTER_OTHER, which the
// status line prints as it came.
enum PrinterActivity {
  PRINTER_OTHER, PRINTER_PRINTING, PRINTER_PAUSED, PRINTER_FINISHED,
  PRINTER_FAILED, PRINTER_IDLE, PRINTER_PREPARING
};

static PrinterActivity printerActivity(const char* st) {
  if (!st || !st[0]) return PRINTER_OTHER;
  static const struct { const char* word; PrinterActivity act; } WORDS[] = {
    { "RUNNING",   PRINTER_PRINTING  }, { "PRINTING",  PRINTER_PRINTING  },
    { "PAUSE",     PRINTER_PAUSED    }, { "PAUSED",    PRINTER_PAUSED    },
    { "FINISH",    PRINTER_FINISHED  }, { "FINISHED",  PRINTER_FINISHED  },
    { "COMPLETED", PRINTER_FINISHED  },
    { "FAILED",    PRINTER_FAILED    }, { "FAILURE",   PRINTER_FAILED    },
    { "ERROR",     PRINTER_FAILED    },
    { "IDLE",      PRINTER_IDLE      }, { "READY",     PRINTER_IDLE      },
    { "PREPARE",   PRINTER_PREPARING }, { "PREPARING", PRINTER_PREPARING },
    { "SLICING",   PRINTER_PREPARING },
  };
  for (const auto& w : WORDS) {
    if (strcasecmp(st, w.word) == 0) return w.act;
  }
  return PRINTER_OTHER;
}

// Fills the page. Blocks for the length of the request, so the screen is
// drawn first and pumped, and the screen is checked again afterwards: the
// user can have tapped back during those milliseconds.
static void fetchAndDraw() {
  if (!s_scr) return;
  setStatus(T(STR_AMSV_LOADING));

  for (int i = 0; i < AMSV_PUMP_PASSES; i++) {
    lv_timer_handler();
    delay(AMSV_PUMP_MS);
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
    // What the printer is doing, without its name: offline, a job, a state,
    // or nothing at all.
    char what[48] = "";
    const PrinterActivity act = printerActivity(s_state.state);
    if (!s_state.connected) {
      // An offline printer still has a last known state worth showing, so
      // this is a note next to the grid rather than a refusal to draw it.
      // A backend that never said either way gets its own wording: blaming
      // the printer for a driver that has not reported sends the user to
      // the wrong machine.
      copyT(what, sizeof(what), s_state.conn_known ? STR_AMSV_OFFLINE : STR_AMSV_UNKNOWN);
    } else if (s_state.job_percent >= 0 &&
               (act == PRINTER_PRINTING || act == PRINTER_PAUSED)) {
      // The percentage only while it means something. Bambu reports the
      // finished job and its 100 % until the next print starts, and FilaMan
      // passes that through, so a printer that finished two days ago read
      // "printing 100%" the whole time.
      char fmt[24];
      copyT(fmt, sizeof(fmt), act == PRINTER_PAUSED ? STR_AMSV_JOB_PAUSED : STR_AMSV_JOB);
      snprintf(what, sizeof(what), fmt, (int)s_state.job_percent);
    } else if (act == PRINTER_FINISHED) {
      copyT(what, sizeof(what), STR_AMSV_STATE_FINISH);
    } else if (act == PRINTER_FAILED) {
      copyT(what, sizeof(what), STR_AMSV_STATE_FAILED);
    } else if (act == PRINTER_IDLE) {
      copyT(what, sizeof(what), STR_AMSV_STATE_IDLE);
    } else if (act == PRINTER_PREPARING) {
      copyT(what, sizeof(what), STR_AMSV_STATE_PREPARE);
    } else if (s_state.state[0]) {
      // A state this list does not know is shown as the server wrote it,
      // rather than hidden.
      snprintf(what, sizeof(what), "%s", s_state.state);
    }

    // With two or more printers the name is the switch, and looks like one:
    // the same chip as "reload", holding "2/3  P1S" so it also says where in
    // the list the next tap goes. The status stands beside it in plain text.
    // On one printer there is nothing to step through, so the line is text
    // only - a chip that does nothing would be a promise the page cannot keep.
    const bool switchable = (s_printers.count > 1);
    if (switchable && s_printer_btn && s_printer_lbl && s_status) {
      applyRowDrop();
      char fmt[12], n[12], name[48];
      copyT(fmt, sizeof(fmt), STR_AMSV_PRN_OF);
      snprintf(n, sizeof(n), fmt, (int)s_printer_idx + 1, (int)s_printers.count);
      snprintf(name, sizeof(name), "%s  %s", n, s_state.printer);
      lv_label_set_text(s_printer_lbl, name);
      // Sized to the name. A name of the user's choosing can be long; the chip
      // stops where the status would have no room left, and the label inside
      // cuts with dots.
      lv_coord_t w = lv_txt_get_width(name, (uint32_t)strlen(name), UI_FONT_BODY,
                                      0, LV_TEXT_FLAG_NONE) + 2 * AMSV_CHIP_PAD_X;
      const lv_coord_t w_max = AMSV_STATUS_W - AMSV_CHIP_GAP - AMSV_STATUS_MIN_W;
      if (w > w_max) w = w_max;
      lv_obj_set_width(s_printer_btn, w);
      lv_obj_set_size(s_printer_lbl, w - 2 * AMSV_CHIP_PAD_X + AMSV_CHIP_TXT_SLACK,
                      lv_font_get_line_height(UI_FONT_BODY));
      lv_obj_clear_flag(s_printer_btn, LV_OBJ_FLAG_HIDDEN);

      const int x = AMSV_MARGIN + w + AMSV_CHIP_GAP;
      lv_obj_set_x(s_status, x);
      lv_obj_set_width(s_status, 480 - AMSV_MARGIN_R - x);
      lv_label_set_text(s_status, what);
      lv_obj_clear_flag(s_status, LV_OBJ_FLAG_HIDDEN);
    } else {
      char line[80];
      if (what[0]) snprintf(line, sizeof(line), "%s - %s", s_state.printer, what);
      else         snprintf(line, sizeof(line), "%s", s_state.printer);
      setStatus(line);
    }
  }

  layoutGrid(s_state);

  // The grams the grid could not show. BamBuddy's answer carries the
  // printer's percentage, the weighed figure sits in the inventory, and
  // fetching it here would hold the first frame for a request per bay. So it
  // is asked for in the background and laid over the tiles when it arrives.
  amsWeightsStart(s_printer_id, s_state);
}

// Takes what the weight fetch found into the state the grid draws from, and
// says whether anything changed.
static bool applyWeights(const AmsWeightsResult& r) {
  if (r.printer_id != s_printer_id) return false;   // the user switched printers
  bool changed = false;
  for (uint8_t i = 0; i < r.count; i++) {
    if (r.item[i].grams < 0) continue;
    for (uint8_t u = 0; u < s_state.unit_count; u++) {
      AmsSlotUnit& unit = s_state.unit[u];
      if (unit.ams_id != r.item[i].ams_id) continue;
      for (uint8_t t = 0; t < unit.tray_count; t++) {
        AmsSlotTray& tray = unit.tray[t];
        if (tray.tray_id != r.item[i].tray_id || !tray.exists) continue;
        if (tray.remain_g == r.item[i].grams) continue;
        tray.remain_g = r.item[i].grams;
        changed = true;
      }
    }
  }
  return changed;
}

// The unit's name, the way the unit header writes it: a name the user gave
// the unit where there is one, otherwise "AMS 2" or "AMS HT 1" built from the
// number.
static void unitName(const AmsSlotUnit& unit, char* out, size_t n) {
  if (unit.label[0]) {
    snprintf(out, n, "%s", unit.label);
  } else if (unit.is_ext) {
    copyT(out, n, STR_AMSV_UNIT_EXT);
  } else {
    char fmt[24];
    copyT(fmt, sizeof(fmt), unit.is_ht ? STR_AMSV_UNIT_HT : STR_AMSV_UNIT);
    const int shown = unit.is_ht ? (unit.ams_id - 127) : (unit.ams_id + 1);
    snprintf(out, n, fmt, shown > 0 ? shown : 1);
  }
}

// The bay's own name: the unit's, and the bay counted from one.
static void bayName(const AmsSlotUnit& unit, const AmsSlotTray& tray,
                    char* out, size_t n) {
  char unit_name[SD_UNIT_NAME_MAX];
  unitName(unit, unit_name, sizeof(unit_name));

  char fmt[24];
  copyT(fmt, sizeof(fmt), STR_AMSD_BAY);
  snprintf(out, n, fmt, unit_name, (int)tray.tray_id + 1);
}

// Everything the AMS answer already knows about a bay, before anything is
// asked of the database. What the database then has lays over this; what it
// has not stays as the printer reported it.
static void detailFromTray(const AmsSlotUnit& unit, const AmsSlotTray& tray,
                           AmsSpoolDetail& out) {
  out = AmsSpoolDetail{};
  out.remaining_g = SD_WEIGHT_NA;
  out.total_g     = SD_WEIGHT_NA;

  bayName(unit, tray, out.bay, sizeof(out.bay));
  out.color      = tray.color;
  out.has_color  = tray.has_color;
  out.spool_id   = tray.spool_id;
  out.remain_pct = tray.remain;
  out.nozzle_min = tray.nozzle_min;
  out.nozzle_max = tray.nozzle_max;
  snprintf(out.material, sizeof(out.material), "%s", tray.name);
  snprintf(out.printer_type, sizeof(out.printer_type), "%s", tray.type);
  snprintf(out.backup_of, sizeof(out.backup_of), "%s", tray.backup_of);
  snprintf(out.color_name, sizeof(out.color_name), "%s", tray.color_name);

  // The grams the printer reports are a fill level, not a weighing, so they
  // stand in only until the database says otherwise.
  if (tray.remain_g > 0) out.remaining_g = (float)tray.remain_g;
}

// Reads one bay and shows it. Blocking, so it runs from the loop and never
// from the tap that asked for it.
static void openDetail(int ams_id, int tray_id) {
  const AmsSlotUnit* unit = nullptr;
  const AmsSlotTray* tray = findTray(ams_id, tray_id, &unit);
  if (!tray || !unit) {
    logSDf("AMSVIEW: detail for bay %d/%d, no such bay", ams_id, tray_id);
    return;
  }

  static AmsSpoolDetail det;   // BSS: 200 bytes the loop task's stack is spared
  detailFromTray(*unit, *tray, det);
  static AmsUnitSpools us;     // BSS as well
  us = AmsUnitSpools{};

  loadingOverlayShow(T(STR_AMSD_LOADING));

  // FilaMan names the spool per bay in the same answer the grid was drawn
  // from, so there is nothing to look up. BamBuddy does not, and its
  // assignment list is the only place the pair is resolved.
  int spool_id = det.spool_id;
  if (amsUnitOffersDriedAll(*unit) && backendCanPatchLastDried()) {
    // An AMS 2 Pro: the card may offer to record a drying for the whole
    // unit, so it needs every bay's spool rather than this one's. The
    // assignment list holds them all, and asking it once for the unit takes
    // the place of asking it for the bay - one request either way.
    int by_tray[AMS_MAX_TRAYS] = {0};
    bool need = (spool_id <= 0);
    for (uint8_t t = 0; t < unit->tray_count; t++) {
      if (unit->tray[t].exists && unit->tray[t].spool_id <= 0) need = true;
    }
    if (need && s_printer_id > 0) {
      backendFindUnitSpools(s_printer_id, ams_id, by_tray, AMS_MAX_TRAYS);
    }
    for (uint8_t t = 0; t < unit->tray_count; t++) {
      const AmsSlotTray& bay = unit->tray[t];
      int id = bay.spool_id;
      if (id <= 0 && bay.tray_id < AMS_MAX_TRAYS) id = by_tray[bay.tray_id];
      if (bay.tray_id == (uint8_t)tray_id && spool_id <= 0 && id > 0) {
        spool_id = id;
        det.spool_id = id;
      }
      // Only bays with filament in them: an assignment can outlive the spool
      // that was taken out, and that spool was not in the dryer.
      if (!bay.exists || id <= 0) continue;
      bool seen = false;
      for (uint8_t k = 0; k < us.count; k++) {
        if (us.spool_id[k] == id) seen = true;
      }
      if (!seen && us.count < AMS_MAX_TRAYS) us.spool_id[us.count++] = id;
    }
    unitName(*unit, us.name, sizeof(us.name));
    us.printer_id = s_printer_id;
    us.ams_id     = (uint8_t)ams_id;
  } else if (spool_id <= 0 && s_printer_id > 0) {
    int found = backendFindBaySpool(s_printer_id, ams_id, tray_id);
    if (found > 0) {
      spool_id = found;
      det.spool_id = found;
    }
  }

  if (spool_id > 0) backendGetSpoolDetail(spool_id, det);

  // The printer's word against the database's. The grid above is drawn from
  // the printer and the card from the spool the backend has assigned to the
  // bay, and nothing on the BamBuddy side keeps the two in step once Spoolman
  // owns the assignments: a user swapped PLA for PETG and the card went on
  // showing the PLA spool under a tile that said PETG.
  det.type_conflict = det.found &&
                      sdMaterialContradicts(det.printer_type, det.material);
  if (det.type_conflict) {
    logSDf("AMSVIEW: bay %d/%d reports %s, spool %d on file is %s - assignment stale?",
           ams_id, tray_id, det.printer_type, det.spool_id, det.material);
    // A spool that is most likely not in the bay was not in the dryer either.
    // Out of the unit's list, the card stops offering "all spools in this
    // unit" and asks about this one spool alone - under the warning it shows.
    uint8_t kept = 0;
    for (uint8_t k = 0; k < us.count; k++) {
      if (us.spool_id[k] != det.spool_id) us.spool_id[kept++] = us.spool_id[k];
    }
    us.count = kept;
  }

  loadingOverlayHide();

  // The page can have gone while the request ran - a tap on back is seen by
  // the loading overlay's own refresh.
  if (!s_scr) return;
  // Always set, so a unit from an earlier card cannot survive into this one.
  amsDetailSetUnit(us.count > 0 ? &us : nullptr);
  showAmsDetailPopup(det);
}

void handleAmsViewDeferredActions() {
  if (show_ams_view_pending) {
    show_ams_view_pending = false;
    requestAmsView(AMS_VIEW_BROWSE);
  }
  if (show_ams_view_scale_pending) {
    show_ams_view_scale_pending = false;
    requestAmsViewFromScaleMenu();
  }

  // Closing comes first, so a pick that asked to close does not run its
  // request with the page still up. releaseScreen() frees asynchronously and
  // appLoop() has already been through lv_timer_handler(), so by the next
  // pass the page is really gone and a blocking request freezes nothing.
  if (s_close_pending) {
    s_close_pending = false;
    s_fetch_pending = false;
    // Back without a tap on a PICK page is an answer too: "not now".
    signalDismissIfUnanswered();
    closeAmsView();
    if (s_return_to_scale_menu && scr_scale_sub) {
      // The menu is still there, hidden by the build: showing it again puts
      // the user back on the row they came from, scroll position included.
      s_return_to_scale_menu = false;
      lv_obj_clear_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN);
    } else {
      showMainScreen();   // calls destroyAmsView(), which leaves the pick alone
    }
    return;
  }

  // Last, and a pass after the close: this is the one that talks to the
  // server. The callback sees (-1, -1) when the page was closed without an
  // answer, and it is the callback that knows what that means for its note.
  if (s_pick_pending) {
    s_pick_pending = false;
    const int ams = s_pick_ams, tray = s_pick_tray;
    s_pick_ams  = -1;
    s_pick_tray = -1;
    if (s_cb) s_cb(ams, tray);
    return;
  }

  // The detail card. Also a request, and also run with the page standing -
  // unlike a pick, because the card lies over that page and goes away again
  // on its own. The loading overlay covers the seconds in between and eats
  // the taps that would otherwise queue up behind it.
  if (s_detail_pending) {
    s_detail_pending = false;
    // Latched before the blocking call, like the pick above: a tap that lands
    // while the fetch runs must not find the pair already cleared.
    const int ams  = s_detail_ams;
    const int tray = s_detail_tray;
    s_detail_ams  = -1;
    s_detail_tray = -1;
    openDetail(ams, tray);
    return;
  }

  if (s_build_pending) {
    s_build_pending = false;
    s_weights_redraw = false;
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
    return;
  }

  // The weights that came in behind the first frame. Redrawn only with the
  // page really in front: rebuilding the tiles under an open detail card
  // would hold two sets of them in the pool at once for nothing.
  if (amsWeightsState() == AWS_DONE) {
    if (s_scr && applyWeights(amsWeightsResult())) s_weights_redraw = true;
    amsWeightsTake();
  }
  if (s_weights_redraw && !isAmsDetailPopupOpen()) {
    s_weights_redraw = false;
    if (s_scr) layoutGrid(s_state);
  }
}
