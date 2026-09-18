#include "ams_detail_popup.h"

#include <Arduino.h>
#include <lvgl.h>
#include <string.h>

#include "app/app_state.h"
#include "date_display.h"
#include "dried_action.h"
#include "hardware/sd_logger.h"
#include "loading_overlay.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/dried_batch.h"
#include "services/filaman_api.h"
#include "services/time_service.h"
#include "services/user_options.h"
#include "services/wifi_manager.h"
#include "status_picker.h"
#include "theme.h"
#include "ui_common.h"

// Last, and after everything that pulls in ArduinoJson: its template
// parameter T collides with the T() macro this header defines.
#include "lang.h"

// ---- geometry ------------------------------------------------
// The card is the More Info card's grid, because it answers the same kind of
// question and a second set of measurements for that would only be a second
// thing to keep in step. What is new is the weight block in the middle: this
// card exists because a bay can show no weight at all, so the weight is the
// one figure that gets a row of its own.
#define AMSD_BOX_W        464
#define AMSD_BOX_H        300
#define AMSD_BOX_X        8
#define AMSD_BOX_Y        10
#define AMSD_HDR_H        52
#define AMSD_PAD          10
#define AMSD_CLOSE        44

// Two columns, as in more_info_screen.cpp.
#define AMSD_CA           10
#define AMSD_CB           236
#define AMSD_CW           218
// Caption to value, for a font 16 value on a font 12 caption: 18 px between
// the baselines.
#define AMSD_VF           16

#define AMSD_SWATCH       42
#define AMSD_ID_X         60
#define AMSD_ID_W         46
#define AMSD_MAT_X        114
#define AMSD_MAT_W        114

// Rows, top to bottom.
#define AMSD_IDENT_CAP_Y  60
#define AMSD_IDENT_VAL_Y  76
#define AMSD_DIV1_Y       104
#define AMSD_WEIGHT_CAP_Y 110
#define AMSD_WEIGHT_VAL_Y 124
#define AMSD_BAR_Y        148
#define AMSD_BAR_W        (AMSD_BOX_W - 2 * AMSD_PAD)
#define AMSD_BAR_H        6
// The footnote under the bar: the backup bay, and whatever the backend could
// not tell. Full width and one line high, both on purpose - it used to sit in
// the 142 px corner beside a short bar, where a German sentence wrapped and
// the second line was drawn straight through the divider below. LONG_DOT only
// cuts when the label has a height to be too tall for, so the height is set
// rather than left to the content.
#define AMSD_NOTE_Y       156
#define AMSD_NOTE_H       16
#define AMSD_DIV2_Y       174
#define AMSD_R1           180
#define AMSD_R2           220
#define AMSD_R3           260

// Below this share the bar turns amber. Not a backend threshold - FilaMan
// keeps one per spool and the card does not fetch it - just the point at
// which a spool is worth a second look before a long print.
#define AMSD_LOW_PCT      15

static lv_obj_t* s_pop  = nullptr;
// The two things the card can ask of the spool behind the bay, each its own
// small overlay above it.
static lv_obj_t* s_ask  = nullptr;   // record today's drying?
// The status picker is not ours: status_picker.cpp owns the one both this
// card and the More Info screen show.

// What the card is currently showing. Kept so a write can update one field
// and redraw from it, rather than fetching the whole spool again to learn
// what the server has just been told.
static AmsSpoolDetail s_det;

// The unit the bay belongs to, when that unit is an AMS 2 Pro and the card
// may offer to record the drying for all of it. count 0 otherwise.
static AmsUnitSpools s_unit;

static bool s_dried_pending     = false;
static bool s_dried_all_pending = false;
static bool s_status_pending    = false;
static int  s_status_pick       = 0;
// Set when a write failed, so the redraw can say so instead of looking as if
// nothing had happened.
static bool s_write_failed   = false;
// The last batch on this card's unit has come back: how many of how many.
static bool    s_batch_note  = false;
static uint8_t s_batch_ok    = 0;
static uint8_t s_batch_total = 0;
// A batch result wants the card redrawn, as soon as nothing stands above it.
static bool s_redraw_pending = false;

bool isAmsDetailPopupOpen() { return s_pop != nullptr; }

void closeAmsDetailPopup() {
  releaseScreen(&s_ask);
  closeStatusPicker();
  releaseScreen(&s_pop);
}

// Whether the spool behind this bay can be handled from here at all. A bay
// with nothing on file has nothing to write to, and without a network the
// write would only fail in a way the user has to undo.
static bool canEdit(const AmsSpoolDetail& d) {
  return d.spool_id > 0 && d.found && wifiManagerIsConnected();
}

// The status is FilaMan's: the other two have a boolean, and a picker for a
// boolean is a worse button than the one the weight popup already has.
static bool canEditStatus(const AmsSpoolDetail& d) {
  return canEdit(d) && backendIsFilaMan() && d.status_id > 0;
}

// ---- the two things the card can ask of the spool ------------
// Both follow the house rule: the callback records what to do and returns,
// the loop performs it. A PATCH from inside a callback would freeze the panel
// with the card still up, and in FilaMan mode the drying date is two
// sequential requests.

static void askCloseCb(lv_event_t* e) { releaseScreen(&s_ask); }

static void askYesCb(lv_event_t* e) {
  releaseScreen(&s_ask);
  s_dried_pending = true;
}

static void askAllCb(lv_event_t* e) {
  releaseScreen(&s_ask);
  s_dried_all_pending = true;
}

static bool unitHolds(int spool_id) {
  if (spool_id <= 0) return false;
  for (uint8_t i = 0; i < s_unit.count; i++) {
    if (s_unit.spool_id[i] == spool_id) return true;
  }
  return false;
}

// Below this "all" and "this one" are the same answer, and the question keeps
// its two buttons.
#define AMSD_DRIED_ALL_MIN 2

// Whether the question offers the whole unit. The bay's own spool has to be
// one of them: "all" that leaves out the spool the user tapped would not be
// all, and a bay whose spool is not in the unit's list is one the printer
// reports empty.
static bool offerDriedAll() {
  return s_unit.count >= AMSD_DRIED_ALL_MIN && !driedBatchBusy() &&
         unitHolds(s_det.spool_id);
}

// The same question the main screen asks after a weighing, in the same shape:
// the drop icon, the sentence at font 20, two 170x56 buttons. Only one thing
// is added, and it is the one thing that differs - which spool is meant. On
// the main screen the spool is the one lying on the pad and needs no naming;
// here a bay was tapped, and a tap one bay over would write the date onto the
// wrong spool without ever looking wrong.
#define AMSD_ASK_W        400
#define AMSD_ASK_H        250
#define AMSD_ASK_BTN_H    56
#define AMSD_ASK_SWATCH   22
// What the identification line is cut to. The row is 376 px, of which the
// swatch and its gap take 30; at font 16 the remaining 346 hold about 39
// characters - measured, not guessed: the simulator's dump reports 220 px for
// a 25 character line. Anything longer is cut with an ellipsis rather than
// silently, because the row clips its children and a hard cut lands
// mid-glyph with nothing to show that it happened.
#define AMSD_ASK_ID_CHARS 39
#define AMSD_ASK_ID_KEEP  36

// The same question with a third answer, for an AMS 2 Pro: the whole unit.
// Stacked rather than three abreast, because "Nur diese Spule" and "Alle 3
// Spulen in AMS 1" do not fit a third of 400 px at font 20. The two answers
// of the plain question keep their size and their row; the unit's goes above
// them at full width, and the box grows by what that row needs. Everything
// above the buttons moves up a little to make room without crowding them.
#define AMSD_ASK_H_ALL      290
#define AMSD_ASK_Q_Y_ALL    58
// One line of font 20 fits the German sentence (337 of 360 px), but a longer
// translation may wrap; the slot holds two and the text is centred in it.
#define AMSD_ASK_Q_SLOT_H   46
#define AMSD_ASK_ROW_Y      122
#define AMSD_ASK_ROW_Y_ALL  116
#define AMSD_ASK_ICON_Y     14
#define AMSD_ASK_Q_Y        62
#define AMSD_ASK_BTN_W      170
#define AMSD_ASK_BTN_X_L    12
#define AMSD_ASK_BTN_X_R    218
#define AMSD_ASK_BTN_GAP_B  18
#define AMSD_ASK_ALL_Y      154
#define AMSD_ASK_ALL_H      48
#define AMSD_ASK_ALL_W      376
#define AMSD_ASK_ALL_TEXT_W (AMSD_ASK_ALL_W - 24)

static void oneLine(lv_obj_t* l, int w, const lv_font_t* font);

static void showDriedAsk() {
  releaseScreen(&s_ask);
  if (!lvPoolHasRoomForRow()) return;
  // Decided once, so the whole box is drawn for one question or the other.
  const bool all = offerDriedAll();
  const int  box_h = all ? AMSD_ASK_H_ALL : AMSD_ASK_H;

  s_ask = lv_obj_create(lv_scr_act());
  if (!s_ask) return;
  lv_obj_set_size(s_ask, 480, 320);
  lv_obj_set_pos(s_ask, 0, 0);
  lv_obj_set_style_bg_color(s_ask, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(s_ask, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(s_ask, 0, 0);
  lv_obj_set_style_radius(s_ask, 0, 0);
  lv_obj_set_style_pad_all(s_ask, 0, 0);
  lv_obj_clear_flag(s_ask, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_flag(s_ask, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t* box = lv_obj_create(s_ask);
  if (!box) { releaseScreen(&s_ask); return; }
  lv_obj_set_size(box, AMSD_ASK_W, box_h);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // The drop, in the colour the weight popup gives the same question. 24 is
  // the largest size the firmware already links; a bigger one would pull in a
  // font for a single glyph.
  lv_obj_t* icon = lv_label_create(box);
  if (icon) {
    lv_label_set_text(icon, LV_SYMBOL_TINT);
    lv_obj_set_style_text_color(icon, lv_color_hex(0x5ad1ff), 0);
    lv_obj_set_style_text_font(icon, UI_FONT_ICON, 0);
    lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, AMSD_ASK_ICON_Y);
  }

  lv_obj_t* q = lv_label_create(box);
  if (q) {
    char buf[96];
    // "for this spool" only where the question is about one spool: with the
    // unit on offer, which spool is meant is what the answer says.
    copyT(buf, sizeof(buf), all ? STR_AMSD_DRIED_Q_ALL : STR_AMSD_DRIED_Q);
    lv_label_set_text(q, buf);
    lv_obj_set_style_text_color(q, lv_color_hex(UI_COL_INK), 0);
    lv_obj_set_style_text_font(q, UI_FONT_HEADLINE, 0);
    lv_obj_set_style_text_align(q, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(q, AMSD_ASK_W - 40);
    if (all) {
      lv_obj_update_layout(q);
      const lv_coord_t h = lv_obj_get_height(q);
      const int y = AMSD_ASK_Q_Y_ALL + (h < AMSD_ASK_Q_SLOT_H ? (AMSD_ASK_Q_SLOT_H - h) / 2 : 0);
      lv_obj_align(q, LV_ALIGN_TOP_MID, 0, y);
    } else {
      lv_obj_align(q, LV_ALIGN_TOP_MID, 0, AMSD_ASK_Q_Y);
    }
  }

  // Swatch and name as one centred pair, laid out by flex so neither has to
  // know how wide the other came out.
  lv_obj_t* row = lv_obj_create(box);
  if (row) {
    lv_obj_set_size(row, AMSD_ASK_W - 24, 26);
    lv_obj_align(row, LV_ALIGN_TOP_MID, 0, all ? AMSD_ASK_ROW_Y_ALL : AMSD_ASK_ROW_Y);
    lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(row, 0, 0);
    lv_obj_set_style_pad_all(row, 0, 0);
    lv_obj_set_style_pad_column(row, 8, 0);
    lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);

    lv_obj_t* sw = lv_obj_create(row);
    if (sw) {
      lv_obj_set_size(sw, AMSD_ASK_SWATCH, AMSD_ASK_SWATCH);
      lv_obj_set_style_radius(sw, 4, 0);
      lv_obj_set_style_border_color(sw, lv_color_hex(UI_COL_RULE), 0);
      lv_obj_set_style_border_width(sw, 1, 0);
      lv_obj_set_style_pad_all(sw, 0, 0);
      lv_obj_clear_flag(sw, LV_OBJ_FLAG_SCROLLABLE);
      if (s_det.color.valid) swatchPaint(sw, s_det.color);
      else lv_obj_set_style_bg_color(sw, lv_color_hex(UI_COL_EMPTY), 0);
    }

    // "Spule 294 - PLA Cyan (12601)": the id to look it up by, the material
    // and the trade name. The id carries no "#", the way every id on this
    // device is written.
    char line[96], cut[96];
    char spool[16];
    copyT(spool, sizeof(spool), STR_REMOTE_LINK_COL_SPOOL);
    // The material is dropped when the name already opens with it: FilaMan's
    // designation often repeats the type, and "ABS-GF ABS-GF" says nothing
    // twice. "PLA" before "Matte - Charcoal (11101)" does say something, and
    // stays.
    const size_t mat_len = strlen(s_det.material);
    const bool name_repeats_material =
      mat_len > 0 && strncasecmp(s_det.name, s_det.material, mat_len) == 0;
    if (s_det.material[0] && s_det.name[0] && !name_repeats_material) {
      snprintf(line, sizeof(line), "%s %d - %s %s", spool, s_det.spool_id,
               s_det.material, s_det.name);
    } else {
      snprintf(line, sizeof(line), "%s %d - %s", spool, s_det.spool_id,
               s_det.name[0] ? s_det.name : s_det.material);
    }
    if (strlen(line) > AMSD_ASK_ID_CHARS) {
      utf8Cut(line, AMSD_ASK_ID_KEEP, cut, sizeof(cut));
      strncat(cut, "...", sizeof(cut) - strlen(cut) - 1);
    } else {
      snprintf(cut, sizeof(cut), "%s", line);
    }

    lv_obj_t* who = lv_label_create(row);
    if (who) {
      lv_label_set_text(who, cut);
      lv_obj_set_style_text_color(who, lv_color_hex(UI_COL_INK_2), 0);
      lv_obj_set_style_text_font(who, UI_FONT_BODY, 0);
    }
  }

  // The unit, above the two answers the plain question has. In the outline
  // an active choice wears on the AMS page, so it reads as an answer of its
  // own beside the solid "this spool only" rather than as a second copy of it.
  if (all) {
    lv_obj_t* btn = lv_btn_create(box);
    if (btn) {
      lv_obj_set_size(btn, AMSD_ASK_ALL_W, AMSD_ASK_ALL_H);
      lv_obj_set_pos(btn, AMSD_ASK_BTN_X_L, AMSD_ASK_ALL_Y);
      lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_ACCENT_DIM), 0);
      lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_OK_BG_PRESSED), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(btn, lv_color_hex(UI_COL_ACCENT), 0);
      lv_obj_set_style_border_width(btn, 1, 0);
      lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
      lv_obj_set_style_shadow_width(btn, 0, 0);
      lv_obj_add_event_cb(btn, askAllCb, LV_EVENT_CLICKED, nullptr);
      lv_obj_t* l = lv_label_create(btn);
      if (l) {
        char fmt[48], t[64];
        copyT(fmt, sizeof(fmt), STR_AMSD_DRIED_ALL);
        snprintf(t, sizeof(t), fmt, (int)s_unit.count, s_unit.name);
        lv_label_set_text(l, t);
        lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_ACCENT), 0);
        lv_obj_set_style_text_font(l, UI_FONT_TITLE, 0);
        lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
        oneLine(l, AMSD_ASK_ALL_TEXT_W, UI_FONT_TITLE);
        lv_obj_center(l);
      }
    }
  }

  struct { int str_id; bool primary; lv_event_cb_t cb; } b[2] = {
    { all ? STR_AMSD_DRIED_ONE : STR_BTN_CONFIRMED, true,  askYesCb   },
    { STR_CANCEL,                                   false, askCloseCb },
  };
  for (int i = 0; i < 2; i++) {
    lv_obj_t* btn = lv_btn_create(box);
    if (!btn) continue;
    lv_obj_set_size(btn, AMSD_ASK_BTN_W, AMSD_ASK_BTN_H);
    lv_obj_set_pos(btn, i == 0 ? AMSD_ASK_BTN_X_L : AMSD_ASK_BTN_X_R,
                   box_h - AMSD_ASK_BTN_H - AMSD_ASK_BTN_GAP_B);
    lv_obj_set_style_bg_color(btn,
      lv_color_hex(b[i].primary ? UI_COL_OK_BG : UI_COL_BAD_BG), 0);
    lv_obj_set_style_bg_color(btn,
      lv_color_hex(b[i].primary ? UI_COL_OK_BG_PRESSED : UI_COL_BAD_BG_PRESSED),
      LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
    lv_obj_set_style_shadow_width(btn, 0, 0);
    lv_obj_add_event_cb(btn, b[i].cb, LV_EVENT_CLICKED, nullptr);
    lv_obj_t* l = lv_label_create(btn);
    if (l) {
      char t[24];
      copyT(t, sizeof(t), b[i].str_id);
      lv_label_set_text(l, t);
      lv_obj_set_style_text_color(l,
        lv_color_hex(b[i].primary ? UI_COL_OK_TEXT : UI_COL_BAD_TEXT), 0);
      lv_obj_set_style_text_font(l, UI_FONT_TITLE, 0);
      lv_obj_center(l);
    }
  }
}

static void driedCellCb(lv_event_t* e) {
  if (!canEdit(s_det) || driedBatchBusy()) return;
  showDriedAsk();
}

// The answer comes back from status_picker.cpp a pass after its overlay is
// gone, so the write below is parked like every other one.
static void onStatusPicked(int status_id) {
  if (status_id <= 0 || status_id == s_det.status_id) return;
  s_status_pick    = status_id;
  s_status_pending = true;
}

static void statusChipCb(lv_event_t* e) {
  if (!canEditStatus(s_det)) return;
  showStatusPicker(s_det.status_id, onStatusPicked);
}

static void closeCb(lv_event_t* e) {
  // Parked, not deleted here: this runs inside the card's own callback and
  // releaseScreen() frees asynchronously, which is what makes that safe.
  closeAmsDetailPopup();
}

// One caption over one value. Returns the value label so a caller that wants
// a colour of its own, or the dried-date treatment, can take it.
// A cell whose value can be changed says so by being a frame. The frame is
// the one the More Info card already uses for its location button - same
// fill, same border, same radius - because that is what a changeable field
// looks like on this device, and a second look for it is a second thing to
// recognise. Its literals come over with it for the same reason.
//
// Drawn before the labels, so the press tint sits behind the text rather than
// over it: a label is not clickable, and the tap finds the frame beneath.
#define AMSD_FIELD_PAD_X  6
#define AMSD_FIELD_PAD_Y  6
#define AMSD_FIELD_H      44

// One line, no more. A label with a width but no height grows downwards when
// the text does not fit, and LV_LABEL_LONG_DOT never engages because there is
// no height to be too tall for - the second line was then drawn through the
// divider, or over the caption of the row below. A real height, one line of
// the font in use, is what turns the overflow into dots. Same fault, same fix
// as the note under the bar (AMSD_NOTE_H).
static void oneLine(lv_obj_t* l, int w, const lv_font_t* font) {
  lv_obj_set_size(l, w, lv_font_get_line_height(font));
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
}

static lv_obj_t* cell(lv_obj_t* box, int x, int y, int cap_id,
                      const char* value, uint32_t value_col,
                      const lv_font_t* font = UI_FONT_BODY,
                      lv_event_cb_t cb = nullptr) {
  if (cb) {
    lv_obj_t* frame = lv_btn_create(box);
    if (frame) {
      lv_obj_set_size(frame, AMSD_CW + 2 * AMSD_FIELD_PAD_X, AMSD_FIELD_H);
      lv_obj_set_pos(frame, x - AMSD_FIELD_PAD_X, y - AMSD_FIELD_PAD_Y);
      lv_obj_set_style_bg_color(frame, lv_color_hex(0x0d2040), 0);
      lv_obj_set_style_bg_color(frame, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(frame, lv_color_hex(0x1a3060), 0);
      lv_obj_set_style_border_width(frame, 1, 0);
      lv_obj_set_style_radius(frame, 8, 0);
      lv_obj_set_style_shadow_width(frame, 0, 0);
      lv_obj_set_style_pad_all(frame, 0, 0);
      lv_obj_add_event_cb(frame, cb, LV_EVENT_CLICKED, nullptr);
    }
  }

  lv_obj_t* c = lv_label_create(box);
  if (c) {
    char buf[32];
    copyT(buf, sizeof(buf), cap_id);
    lv_label_set_text(c, buf);
    lv_obj_set_style_text_color(c, lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_set_style_text_font(c, UI_FONT_CAPTION, 0);
    lv_obj_set_pos(c, x, y);
  }

  const bool has = (value && value[0]);

  lv_obj_t* v = lv_label_create(box);
  if (!v) return nullptr;
  lv_label_set_text(v, has ? value : "-");
  // A dash is not a value and should not read like one. In the colour of a
  // real value a row of them looks like data the card got wrong, rather than
  // like nothing being there.
  lv_obj_set_style_text_color(v, lv_color_hex(has ? value_col : UI_COL_CAPTION), 0);
  lv_obj_set_style_text_font(v, font, 0);
  oneLine(v, AMSD_CW, font);
  lv_obj_set_pos(v, x, y + AMSD_VF);
  return v;
}

// "245 °C" for a single setpoint, "190 - 300 °C" for a real range, "-" when
// the backend keeps none. A profile that names one temperature reports it as
// both ends, and printing that as "245 - 245" would read like a fault.
static void nozzleText(const AmsSpoolDetail& d, char* out, size_t n) {
  const bool lo = (d.nozzle_min > 0);
  const bool hi = (d.nozzle_max > 0);
  if (!lo && !hi) {
    snprintf(out, n, "-");
  } else if (lo && hi && d.nozzle_min != d.nozzle_max) {
    snprintf(out, n, "%d - %d °C", (int)d.nozzle_min, (int)d.nozzle_max);
  } else {
    snprintf(out, n, "%d °C", (int)(lo ? d.nozzle_min : d.nozzle_max));
  }
}

// The header: the bay on the title line, the status where FilaMan has one,
// and the way out on the right.
static void buildHeader(lv_obj_t* box, const AmsSpoolDetail& d) {
  lv_obj_t* hdr = lv_obj_create(box);
  if (!hdr) return;
  lv_obj_set_size(hdr, AMSD_BOX_W, AMSD_HDR_H);
  lv_obj_set_pos(hdr, 0, 0);
  lv_obj_set_style_bg_color(hdr, lv_color_hex(UI_COL_GROUND), 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_set_style_pad_all(hdr, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t* title = lv_label_create(hdr);
  if (title) {
    lv_label_set_text(title, d.bay);
    lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_set_style_text_font(title, UI_FONT_BODY, 0);
    // Centred in the room the header actually has: between the chip and the
    // close button when there is a chip, and mirrored around the close button
    // when there is not. With a width and one line, because a unit name of
    // the user's choosing can be longer than that room, and a label with
    // neither ran under the chip.
    const int left  = (d.status_id > 0) ? AMSD_PAD + STATUS_CHIP_W + AMSD_PAD
                                        : AMSD_PAD + AMSD_CLOSE + AMSD_PAD;
    const int right = AMSD_BOX_W - AMSD_PAD - AMSD_CLOSE - AMSD_PAD;
    oneLine(title, right - left, UI_FONT_BODY);
    lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, left, 0);
  }

  // The status is FilaMan's alone. Spoolman has archived:bool and BamBuddy an
  // archive route, and a picker for a boolean would be a worse button than the
  // one the weight popup already has.
  //
  // Where it can be changed the chip is a button, and a taller one: the header
  // has the room, and a status that can be set from the printer view is what
  // saves taking the spool out to set it.
  if (d.status_id > 0) {
    // The same chip the More Info card carries, from the same builder. It was
    // a second, smaller one of its own until that turned out to be two looks
    // for one thing. A button only where it can be changed.
    buildStatusChip(hdr, AMSD_PAD, 4, d.status_id,
                    canEditStatus(d) ? statusChipCb : nullptr);
  }

  lv_obj_t* x = lv_btn_create(hdr);
  if (!x) return;
  lv_obj_set_size(x, AMSD_CLOSE, AMSD_CLOSE);
  lv_obj_align(x, LV_ALIGN_RIGHT_MID, -AMSD_PAD, 0);
  lv_obj_set_style_bg_color(x, lv_color_hex(UI_COL_BAD_BG), 0);
  lv_obj_set_style_bg_color(x, lv_color_hex(UI_COL_BAD_BG_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(x, 1, 0);
  lv_obj_set_style_border_color(x, lv_color_hex(UI_COL_BAD_BG_PRESSED), 0);
  lv_obj_set_style_radius(x, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(x, 0, 0);
  lv_obj_add_event_cb(x, closeCb, LV_EVENT_CLICKED, nullptr);
  lv_obj_t* xl = lv_label_create(x);
  if (xl) {
    lv_label_set_text(xl, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(xl, lv_color_hex(UI_COL_BAD_TEXT), 0);
    lv_obj_set_style_text_font(xl, UI_FONT_TITLE, 0);
    lv_obj_center(xl);
  }
}

static void buildDivider(lv_obj_t* box, int y) {
  lv_obj_t* d = lv_obj_create(box);
  if (!d) return;
  lv_obj_set_size(d, AMSD_BOX_W - 2 * AMSD_PAD, 1);
  lv_obj_set_pos(d, AMSD_PAD, y);
  lv_obj_set_style_bg_color(d, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_border_width(d, 0, 0);
  lv_obj_set_style_radius(d, 0, 0);
  lv_obj_set_style_pad_all(d, 0, 0);
}

// Swatch, id, material, trade name - what identifies the spool, on one line.
static void buildIdentity(lv_obj_t* box, const AmsSpoolDetail& d) {
  lv_obj_t* sw = lv_obj_create(box);
  if (sw) {
    lv_obj_set_size(sw, AMSD_SWATCH, AMSD_SWATCH);
    lv_obj_set_pos(sw, AMSD_PAD, AMSD_IDENT_CAP_Y - 4);
    lv_obj_set_style_radius(sw, UI_RADIUS_INPUT, 0);
    lv_obj_set_style_border_color(sw, lv_color_hex(UI_COL_RULE), 0);
    lv_obj_set_style_border_width(sw, 1, 0);
    lv_obj_set_style_pad_all(sw, 0, 0);
    lv_obj_clear_flag(sw, LV_OBJ_FLAG_SCROLLABLE);
    if (d.color.valid) swatchPaint(sw, d.color);
    else lv_obj_set_style_bg_color(sw, lv_color_hex(UI_COL_EMPTY), 0);
  }

  // The id caption doubles as the place the tag binding is reported: a spool
  // this scale can find by holding a card against it is worth saying, and it
  // costs no row of its own.
  lv_obj_t* cap = lv_label_create(box);
  if (cap) {
    char buf[24];
    if (d.tag_linked) {
      char tag[12];
      copyT(tag, sizeof(tag), STR_REMOTE_LINK_COL_TAG);
      snprintf(buf, sizeof(buf), "ID  %s", tag);
    } else {
      snprintf(buf, sizeof(buf), "ID");
    }
    lv_label_set_text(cap, buf);
    lv_obj_set_style_text_color(cap,
      lv_color_hex(d.tag_linked ? UI_COL_ACCENT : UI_COL_CAPTION), 0);
    lv_obj_set_style_text_font(cap, UI_FONT_CAPTION, 0);
    lv_obj_set_pos(cap, AMSD_ID_X, AMSD_IDENT_CAP_Y);
  }

  lv_obj_t* id = lv_label_create(box);
  if (id) {
    char buf[12];
    if (d.spool_id > 0) snprintf(buf, sizeof(buf), "%d", d.spool_id);
    else                snprintf(buf, sizeof(buf), "-");
    lv_label_set_text(id, buf);
    lv_obj_set_style_text_color(id,
      lv_color_hex(d.spool_id > 0 ? UI_COL_ACCENT : UI_COL_WARN), 0);
    lv_obj_set_style_text_font(id, UI_FONT_BODY, 0);
    oneLine(id, AMSD_ID_W, UI_FONT_BODY);
    lv_obj_set_pos(id, AMSD_ID_X, AMSD_IDENT_VAL_Y);
  }

  lv_obj_t* mc = lv_label_create(box);
  if (mc) {
    char buf[24];
    copyT(buf, sizeof(buf), STR_REMOTE_LINK_ROW_MATERIAL);
    lv_label_set_text(mc, buf);
    lv_obj_set_style_text_color(mc, lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_set_style_text_font(mc, UI_FONT_CAPTION, 0);
    lv_obj_set_pos(mc, AMSD_MAT_X, AMSD_IDENT_CAP_Y);
  }
  lv_obj_t* mv = lv_label_create(box);
  if (mv) {
    lv_label_set_text(mv, d.material[0] ? d.material : "-");
    // In the warning colour when the printer reports another material: this
    // is the field the note under the bar is about, and the eye should land
    // on it without reading the note first.
    lv_obj_set_style_text_color(mv,
      lv_color_hex(d.type_conflict ? UI_COL_WARN : UI_COL_INK), 0);
    lv_obj_set_style_text_font(mv, UI_FONT_BODY, 0);
    oneLine(mv, AMSD_MAT_W, UI_FONT_BODY);
    lv_obj_set_pos(mv, AMSD_MAT_X, AMSD_IDENT_VAL_Y);
  }

  // The trade name, and where there is none, whatever the printer called the
  // filament. "Filament" reads the same in both languages, like the caption
  // on the More Info card.
  lv_obj_t* fc = lv_label_create(box);
  if (fc) {
    lv_label_set_text(fc, "Filament");
    lv_obj_set_style_text_color(fc, lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_set_style_text_font(fc, UI_FONT_CAPTION, 0);
    lv_obj_set_pos(fc, AMSD_CB, AMSD_IDENT_CAP_Y);
  }
  lv_obj_t* fv = lv_label_create(box);
  if (fv) {
    lv_label_set_text(fv, d.name[0] ? d.name : "-");
    lv_obj_set_style_text_color(fv, lv_color_hex(UI_COL_VALUE_BLUE), 0);
    lv_obj_set_style_text_font(fv, UI_FONT_BODY, 0);
    oneLine(fv, AMSD_CW, UI_FONT_BODY);
    lv_obj_set_pos(fv, AMSD_CB, AMSD_IDENT_VAL_Y);
  }
}

// The reason this card exists. A bay can carry filament whose weight nobody
// ever recorded, and the tile can only fall silent about it - here it says so
// in words, in the place the figure would have been.
// reserve_right is the width the status on the right of the note line takes,
// 0 when there is none: the note gives that much up rather than run under it.
static void buildWeight(lv_obj_t* box, const AmsSpoolDetail& d, int reserve_right) {
  lv_obj_t* cap = lv_label_create(box);
  if (cap) {
    char buf[24];
    copyT(buf, sizeof(buf), STR_AMSD_REMAINING);
    lv_label_set_text(cap, buf);
    lv_obj_set_style_text_color(cap, lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_set_style_text_font(cap, UI_FONT_CAPTION, 0);
    lv_obj_set_pos(cap, AMSD_CA, AMSD_WEIGHT_CAP_Y);
  }

  const bool known = (d.remaining_g >= 0.0f);

  lv_obj_t* val = lv_label_create(box);
  if (val) {
    char buf[40];
    if (!known) {
      snprintf(buf, sizeof(buf), "-");
    } else if (d.total_g > 0.0f) {
      char a[12], b[12], fmt[24];
      snprintf(a, sizeof(a), "%.0f g", d.remaining_g);
      snprintf(b, sizeof(b), "%.0f g", d.total_g);
      copyT(fmt, sizeof(fmt), STR_AMSD_OF);
      snprintf(buf, sizeof(buf), fmt, a, b);
    } else {
      snprintf(buf, sizeof(buf), "%.0f g", d.remaining_g);
    }
    lv_label_set_text(val, buf);
    lv_obj_set_style_text_color(val,
      lv_color_hex(known ? UI_COL_INK : UI_COL_WARN), 0);
    lv_obj_set_style_text_font(val, UI_FONT_TITLE, 0);
    lv_obj_set_pos(val, AMSD_CA, AMSD_WEIGHT_VAL_Y);
  }

  // Share of a full spool: from the two weights when both are there, else the
  // percentage the printer reports - which exists on bays the database has no
  // gram figure for, because a Bambu spool says how full it is without anyone
  // having weighed it.
  int share = -1;
  if (known && d.total_g > 0.0f) {
    share = (int)((d.remaining_g / d.total_g) * 100.0f + 0.5f);
    if (share < 0) share = 0;
    if (share > 100) share = 100;
  } else if (d.remain_pct >= 0) {
    share = d.remain_pct;
  }

  // The figure on the right is the share the bar draws, from the same source.
  // It used to be the printer's percentage whenever there was one, next to a
  // bar drawn from the database's grams: two sources, two numbers, and
  // nothing on the card to say which was which.
  if (share >= 0) {
    lv_obj_t* pct = lv_label_create(box);
    if (pct) {
      char buf[12];
      snprintf(buf, sizeof(buf), "%d %%", share);
      lv_label_set_text(pct, buf);
      lv_obj_set_style_text_color(pct,
        lv_color_hex(share < AMSD_LOW_PCT ? UI_COL_WARN : UI_COL_ACCENT), 0);
      lv_obj_set_style_text_font(pct, UI_FONT_TITLE, 0);
      lv_obj_align(pct, LV_ALIGN_TOP_RIGHT, -AMSD_PAD, AMSD_WEIGHT_VAL_Y);
    }

    lv_obj_t* bar = lv_bar_create(box);
    if (bar) {
      lv_obj_set_size(bar, AMSD_BAR_W, AMSD_BAR_H);
      lv_obj_set_pos(bar, AMSD_CA, AMSD_BAR_Y);
      lv_obj_set_style_bg_color(bar, lv_color_hex(UI_COL_RULE), LV_PART_MAIN);
      lv_obj_set_style_bg_color(bar,
        lv_color_hex(share < AMSD_LOW_PCT ? UI_COL_WARN : UI_COL_ACCENT),
        LV_PART_INDICATOR);
      lv_obj_set_style_radius(bar, AMSD_BAR_H / 2, LV_PART_MAIN);
      lv_obj_set_style_radius(bar, AMSD_BAR_H / 2, LV_PART_INDICATOR);
      lv_bar_set_range(bar, 0, 100);
      lv_bar_set_value(bar, share, LV_ANIM_OFF);
    }
  }

  // One line for everything the figures above could not say: why there is no
  // weight, why there is no spool, that the printer reports another material,
  // and which bay carries the same filament. Joined rather than given a place
  // each, because only one of the first three is shown and the last is a
  // footnote either way.
  //
  // This is also what a card full of dashes needs. Six empty fields with no
  // sentence anywhere read as a fault in the scale; the sentence says the
  // fault is not here.
  //
  // The printer disagreeing with the database goes before a missing weight:
  // the dash above already says the weight is missing, and a card that may be
  // showing the wrong spool altogether is the bigger thing to know. It names
  // the fact and leaves the conclusion to the user - a PCTG spool a printer
  // was told to treat as PETG trips this too, and is no fault at all.
  char note[112] = "";
  if (!d.found) {
    copyT(note, sizeof(note), d.spool_id > 0 ? STR_AMSD_FAIL : STR_AMSD_NO_SPOOL);
  } else if (d.type_conflict) {
    char fmt[72], said[88];
    copyT(fmt, sizeof(fmt), STR_AMSD_TYPE_CONFLICT);
    snprintf(said, sizeof(said), fmt, d.printer_type);
    snprintf(note, sizeof(note), LV_SYMBOL_WARNING " %s", said);
  } else if (!known) {
    copyT(note, sizeof(note), STR_AMSD_NO_WEIGHT);
  }
  if (d.backup_of[0]) {
    char fmt[24], b[40];
    copyT(fmt, sizeof(fmt), STR_AMSD_BACKUP);
    snprintf(b, sizeof(b), fmt, d.backup_of);
    if (note[0]) strncat(note, " - ", sizeof(note) - strlen(note) - 1);
    strncat(note, b, sizeof(note) - strlen(note) - 1);
  }
  if (note[0]) {
    lv_obj_t* n = lv_label_create(box);
    if (n) {
      lv_label_set_text(n, note);
      lv_obj_set_style_text_color(n,
        lv_color_hex(d.type_conflict ? UI_COL_WARN : UI_COL_INK_SOFT), 0);
      lv_obj_set_style_text_font(n, UI_FONT_CAPTION, 0);
      // Size before position, and a real height: with LV_SIZE_CONTENT the
      // label grows downwards instead of ellipsising, which is how the second
      // line ended up on top of the divider.
      lv_obj_set_size(n, AMSD_BAR_W - (reserve_right > 0 ? reserve_right + AMSD_PAD : 0),
                      AMSD_NOTE_H);
      lv_label_set_long_mode(n, LV_LABEL_LONG_DOT);
      lv_obj_set_pos(n, AMSD_CA, AMSD_NOTE_Y);
    }
  }
}

static void buildGrid(lv_obj_t* box, const AmsSpoolDetail& d) {
  cell(box, AMSD_CA, AMSD_R1, STR_LBL_VENDOR, d.vendor, UI_COL_INK_2);
  cell(box, AMSD_CB, AMSD_R1, STR_REMOTE_LINK_ROW_COLOR, d.color_name,
       UI_COL_INK_2);

  char nozzle[24];
  nozzleText(d, nozzle, sizeof(nozzle));
  cell(box, AMSD_CA, AMSD_R2, STR_LBL_TEMP, nozzle, UI_COL_INK_2);
  cell(box, AMSD_CB, AMSD_R2, STR_BTN_LOCATION, d.location, UI_COL_ACCENT);

  // Used on the left, dried on the right - the order the main screen puts
  // them in. The same two dates in the other order on the next screen is the
  // kind of difference nobody can name but everybody stumbles over.
  //
  // The caption follows the main screen too: with last_used_mode 1 the scale
  // writes its own weighing date into that field, and calling it "last used"
  // here while the home screen calls it "last weighed" would name one field
  // two ways.
  // Both dates carry "(vor N Tagen)" the way the main screen writes them -
  // "28.03.2026" alone does not say whether that is recent. It needs font 14
  // instead of 16: the longest form is 27 characters and the column is 218 px,
  // which font 16 misses by about twenty. Both cells of the row take the
  // smaller size, so the row stays one row rather than two sizes.
  // 48, not 24: "26.05.2026  (vor 2 Tagen)" is 25 characters and the first
  // cut left "(vor 2 Tage" on the screen. snprintf truncates in silence, and
  // the simulator's check cannot see it either - the label really does hold
  // that text, so nothing is clipped as far as the renderer is concerned.
  char used[48] = "";
  if (d.last_used[0]) {
    char de_used[16];
    isoToDe(d.last_used, de_used, sizeof(de_used));
    driedDisplayStr(de_used, used, sizeof(used));
  }
  cell(box, AMSD_CA, AMSD_R3,
       last_used_mode == 1 ? STR_LASTUSED_OPT_WEIGHED : STR_LBL_LAST_USED,
       used[0] ? used : nullptr, UI_COL_VALUE_BLUE, UI_FONT_SMALL);

  // The drying date, with the same traffic light and the same "(N days ago)"
  // the main screen puts on it. The material is this bay's, not the pad's.
  char de[16] = "", dried_txt[48] = "";
  if (driedBatchContains(d.spool_id)) {
    // Being written in the background. Neither the old date nor its traffic
    // light is the truth any more, and the new one is not in yet.
    snprintf(dried_txt, sizeof(dried_txt), "...");
  } else if (d.last_dried[0]) {
    isoToDe(d.last_dried, de, sizeof(de));
    driedDisplayStr(de, dried_txt, sizeof(dried_txt));
  }
  // The one field the card can set, and the reason it can: after a drying
  // cycle the spool is in the bay, and recording the date used to mean taking
  // it out and putting it on the pad.
  lv_obj_t* dried = cell(box, AMSD_CB, AMSD_R3, STR_LBL_LAST_DRIED,
                         dried_txt[0] ? dried_txt : nullptr, UI_COL_VALUE_BLUE,
                         UI_FONT_SMALL,
                         (canEdit(d) && !driedBatchBusy()) ? driedCellCb : nullptr);
  if (dried && de[0]) {
    const uint32_t col = driedAlertColor(de, d.material);
    lv_obj_set_style_text_color(dried, lv_color_hex(col), 0);
    // The warning triangle only when the reminder is actually warning. A
    // colour on its own is not something to rely on, and the home screen
    // shows both.
    if (driedAlertLevel(de, d.material) >= 1) {
      lv_obj_t* sym = lv_label_create(box);
      if (sym) {
        lv_label_set_text(sym, LV_SYMBOL_WARNING);
        lv_obj_set_style_text_color(sym, lv_color_hex(col), 0);
        lv_obj_set_style_text_font(sym, UI_FONT_CAPTION, 0);
        lv_obj_align(sym, LV_ALIGN_TOP_RIGHT, -AMSD_PAD, AMSD_R3 + AMSD_VF + 2);
      }
    }
  }
}

// The right half of the note line: what a write on this card did, or is
// doing. First match wins - a batch on this unit that is still running, the
// result of one that came back, a single write that did not take.
static bool cardStatus(char* out, size_t n, uint32_t* col) {
  out[0] = '\0';
  const DriedBatchResult& r = driedBatchResult();
  if (driedBatchBusy() && s_unit.count > 0 && r.printer_id == s_unit.printer_id &&
      r.ams_id == s_unit.ams_id) {
    char fmt[48];
    copyT(fmt, sizeof(fmt), STR_AMSD_BATCH_RUNNING);
    snprintf(out, n, fmt, (int)r.count);
    *col = UI_COL_INK_SOFT;
    return true;
  }
  if (s_batch_note) {
    char fmt[48];
    copyT(fmt, sizeof(fmt), STR_AMSD_BATCH_DONE);
    snprintf(out, n, fmt, (int)s_batch_ok, (int)s_batch_total);
    *col = (s_batch_ok == s_batch_total) ? UI_COL_ACCENT
         : (s_batch_ok > 0)              ? UI_COL_WARN
                                         : UI_COL_BAD_TEXT;
    return true;
  }
  if (s_write_failed) {
    copyT(out, n, STR_AMSD_WRITE_FAIL);
    *col = UI_COL_BAD_TEXT;
    return true;
  }
  return false;
}

void amsDetailSetUnit(const AmsUnitSpools* unit) {
  s_unit = unit ? *unit : AmsUnitSpools{};
}

void showAmsDetailPopup(const AmsSpoolDetail& d) {
  // Kept so a write can update one field and redraw from it. Guarded against
  // self-assignment, because the redraw after a write passes s_det back in.
  if (&d != &s_det) {
    s_det = d;
    // A fresh card starts clean. Only the redraw after a write passes s_det
    // back in, and only that one may carry the flag a failed write set - left
    // standing, it reappeared on every bay opened afterwards.
    s_write_failed = false;
    s_batch_note   = false;
  }

  // Open-replace rather than stack: a second tap on a bay while the card
  // stands should show that bay, not two cards.
  closeAmsDetailPopup();

  if (!lvPoolHasRoomForRow()) {
    logSD("AMSDETAIL: LVGL pool low, card not built");
    return;
  }
  logLvMem("amsdetail/pre", 0);

  s_pop = lv_obj_create(lv_scr_act());
  if (!s_pop) return;
  lv_obj_set_size(s_pop, 480, 320);
  lv_obj_set_pos(s_pop, 0, 0);
  lv_obj_set_style_bg_color(s_pop, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(s_pop, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(s_pop, 0, 0);
  lv_obj_set_style_radius(s_pop, 0, 0);
  lv_obj_set_style_pad_all(s_pop, 0, 0);
  lv_obj_clear_flag(s_pop, LV_OBJ_FLAG_SCROLLABLE);
  // Swallows the taps the AMS page would otherwise take through the scrim.
  lv_obj_add_flag(s_pop, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t* box = lv_obj_create(s_pop);
  if (!box) { closeAmsDetailPopup(); return; }
  lv_obj_set_size(box, AMSD_BOX_W, AMSD_BOX_H);
  lv_obj_set_pos(box, AMSD_BOX_X, AMSD_BOX_Y);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // Worked out before the weight block, whose note has to leave room for it.
  char status[64];
  uint32_t status_col = UI_COL_INK_SOFT;
  const bool has_status = cardStatus(status, sizeof(status), &status_col);
  const int status_w = has_status
    ? lv_txt_get_width(status, strlen(status), UI_FONT_CAPTION, 0, LV_TEXT_FLAG_NONE)
    : 0;

  buildHeader(box, s_det);
  buildDivider(box, AMSD_HDR_H);
  buildIdentity(box, s_det);
  buildDivider(box, AMSD_DIV1_Y);
  buildWeight(box, s_det, status_w);
  buildDivider(box, AMSD_DIV2_Y);
  buildGrid(box, s_det);

  // On the note line, right aligned. Only after a write, so the card never
  // looks as if nothing had happened.
  if (has_status) {
    lv_obj_t* w = lv_label_create(box);
    if (w) {
      lv_label_set_text(w, status);
      lv_obj_set_style_text_color(w, lv_color_hex(status_col), 0);
      lv_obj_set_style_text_font(w, UI_FONT_CAPTION, 0);
      lv_obj_align(w, LV_ALIGN_TOP_RIGHT, -AMSD_PAD, AMSD_NOTE_Y);
    }
  }

  logLvMem("amsdetail/post", 1);
  logSDf("AMSDETAIL: %s, spool %d, found=%d", s_det.bay, s_det.spool_id,
         (int)s_det.found);
}

void handleAmsDetailDeferredActions() {
  if (!s_dried_pending && !s_dried_all_pending && !s_status_pending) return;
  // The card has to be up: every write redraws it, and a card taken down
  // while the question stood means the user moved on.
  if (!s_pop) {
    s_dried_pending = s_dried_all_pending = s_status_pending = false;
    return;
  }

  const int spool_id = s_det.spool_id;
  s_write_failed = false;

  // The whole unit, handed to a task of its own. Only started here: the card
  // is redrawn below showing it running, and amsDetailBatchTick() collects
  // the result when it comes back.
  if (s_dried_all_pending) {
    s_dried_all_pending = false;
    s_batch_note = false;
    char iso[32];
    if (!nowIsoUtc(iso, sizeof(iso))) {
      logSDf("AMSDETAIL: clock not set, dried date for %s not written", s_unit.name);
      s_write_failed = true;
    } else if (!driedBatchStart(s_unit.printer_id, s_unit.ams_id, s_unit.spool_id,
                                s_unit.count, iso)) {
      logSDf("AMSDETAIL: dried batch for %s not started", s_unit.name);
      s_write_failed = true;
    } else {
      logSDf("AMSDETAIL: dried %s for %u spools of %s started", iso,
             (unsigned)s_unit.count, s_unit.name);
    }
  }

  if (s_dried_pending) {
    s_dried_pending = false;
    char iso[32];
    if (!nowIsoUtc(iso, sizeof(iso))) {
      // No clock, no date: the fallback stamp would be booked as the day the
      // spool was dried. Shown as a failed save, which is what it is.
      logSDf("AMSDETAIL: clock not set, dried date for spool %d not written", spool_id);
      s_write_failed = true;
    } else {
      loadingOverlayShow(T(STR_AMSD_SAVING));
      const int code = backendPatchSpoolLastDried(cfg_spoolman_base, spool_id, iso);
      loadingOverlayHide();
      logSDf("AMSDETAIL: dried %s for spool %d, HTTP %d", iso, spool_id, code);
      if (code == 200) {
        isoDayLocal(iso, s_det.last_dried, sizeof(s_det.last_dried));
      } else {
        s_write_failed = true;
      }
    }
  }

  if (s_status_pending) {
    s_status_pending = false;
    const int want = s_status_pick;
    const char* key = filamanStatusKey(want);
    if (key) {
      loadingOverlayShow(T(STR_AMSD_SAVING));
      const int code = backendSetSpoolStatus(cfg_spoolman_base, spool_id, key);
      loadingOverlayHide();
      logSDf("AMSDETAIL: status spool %d -> %s, HTTP %d", spool_id, key, code);
      if (code == 200) {
        s_det.status_id = want;
        s_det.archived  = (want == FILAMAN_STATUS_ARCHIVED);
      } else {
        s_write_failed = true;
      }
    }
  }

  // Redrawn either way: on success it shows the new value, on failure it goes
  // back to showing the truth with a line saying the write did not take.
  //
  // The old card goes synchronously first. This runs on the loop task, not
  // inside a callback, so a plain delete is allowed here - and the deferred
  // delete releaseScreen() does would have left both cards in the pool for a
  // pass: the simulator measured the redraw at 64 to 78 percent used, and
  // 39 percent fragmentation once the first was finally freed.
  if (s_pop) {
    lv_obj_del(s_pop);
    s_pop = nullptr;
    showAmsDetailPopup(s_det);
  }
}

void amsDetailBatchTick() {
  if (driedBatchState() == DBS_DONE) {
    const DriedBatchResult& r = driedBatchResult();
    logSDf("AMSDETAIL: batch on unit %d of printer %d, %u of %u saved",
           (int)r.ams_id, r.printer_id, (unsigned)r.ok, (unsigned)r.count);
    driedActionApplyBatch(r);

    if (s_pop) {
      // Whatever card is up, its drying cell was locked while the batch ran
      // and has to come back.
      s_redraw_pending = true;
      for (uint8_t i = 0; i < r.count; i++) {
        if (r.spool_id[i] != s_det.spool_id || r.code[i] != 200) continue;
        isoDayLocal(r.iso, s_det.last_dried, sizeof(s_det.last_dried));
      }
      if (s_unit.count > 0 && s_unit.printer_id == r.printer_id &&
          s_unit.ams_id == r.ams_id) {
        s_batch_note  = true;
        s_batch_ok    = r.ok;
        s_batch_total = r.count;
      }
    }
    // Always collected in the same pass, card or not: an uncollected result
    // keeps the batch busy, and that locks every drying button there is.
    driedBatchTake();
  }

  if (!s_redraw_pending) return;
  if (!s_pop) { s_redraw_pending = false; return; }
  // Not under an open question or picker: the redraw would close them.
  if (s_ask || isStatusPickerOpen()) return;
  s_redraw_pending = false;
  // Synchronous delete, for the reason handleAmsDetailDeferredActions() gives.
  lv_obj_del(s_pop);
  s_pop = nullptr;
  showAmsDetailPopup(s_det);
}
