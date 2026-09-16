#include "ams_detail_popup.h"

#include <Arduino.h>
#include <lvgl.h>
#include <string.h>

#include "app/app_state.h"
#include "date_display.h"
#include "hardware/sd_logger.h"
#include "loading_overlay.h"
#include "services/backend.h"
#include "services/backend_api.h"
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

static bool s_dried_pending  = false;
static bool s_status_pending = false;
static int  s_status_pick    = 0;
// Set when a write failed, so the redraw can say so instead of looking as if
// nothing had happened.
static bool s_write_failed   = false;

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

static void showDriedAsk() {
  releaseScreen(&s_ask);
  if (!lvPoolHasRoomForRow()) return;

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
  lv_obj_set_size(box, AMSD_ASK_W, AMSD_ASK_H);
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
    lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, 14);
  }

  lv_obj_t* q = lv_label_create(box);
  if (q) {
    char buf[96];
    copyT(buf, sizeof(buf), STR_AMSD_DRIED_Q);
    lv_label_set_text(q, buf);
    lv_obj_set_style_text_color(q, lv_color_hex(UI_COL_INK), 0);
    lv_obj_set_style_text_font(q, UI_FONT_HEADLINE, 0);
    lv_obj_set_style_text_align(q, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(q, AMSD_ASK_W - 40);
    lv_obj_align(q, LV_ALIGN_TOP_MID, 0, 62);
  }

  // Swatch and name as one centred pair, laid out by flex so neither has to
  // know how wide the other came out.
  lv_obj_t* row = lv_obj_create(box);
  if (row) {
    lv_obj_set_size(row, AMSD_ASK_W - 24, 26);
    lv_obj_align(row, LV_ALIGN_TOP_MID, 0, 122);
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
      lv_obj_set_style_bg_color(sw,
        lv_color_hex(s_det.has_color ? s_det.color : UI_COL_EMPTY), 0);
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

  struct { int str_id; bool primary; lv_event_cb_t cb; } b[2] = {
    { STR_BTN_CONFIRMED, true,  askYesCb   },
    { STR_CANCEL,        false, askCloseCb },
  };
  for (int i = 0; i < 2; i++) {
    lv_obj_t* btn = lv_btn_create(box);
    if (!btn) continue;
    lv_obj_set_size(btn, 170, AMSD_ASK_BTN_H);
    lv_obj_set_pos(btn, i == 0 ? 12 : 218, AMSD_ASK_H - AMSD_ASK_BTN_H - 18);
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
  if (!canEdit(s_det)) return;
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
  lv_obj_set_pos(v, x, y + AMSD_VF);
  lv_obj_set_width(v, AMSD_CW);
  lv_label_set_long_mode(v, LV_LABEL_LONG_DOT);
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
    lv_obj_align(title, LV_ALIGN_CENTER, 0, 0);
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
    lv_obj_set_style_bg_color(sw,
      lv_color_hex(d.has_color ? d.color : UI_COL_EMPTY), 0);
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
    lv_obj_set_pos(id, AMSD_ID_X, AMSD_IDENT_VAL_Y);
    lv_obj_set_width(id, AMSD_ID_W);
    lv_label_set_long_mode(id, LV_LABEL_LONG_DOT);
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
    lv_obj_set_style_text_color(mv, lv_color_hex(UI_COL_INK), 0);
    lv_obj_set_style_text_font(mv, UI_FONT_BODY, 0);
    lv_obj_set_pos(mv, AMSD_MAT_X, AMSD_IDENT_VAL_Y);
    lv_obj_set_width(mv, AMSD_MAT_W);
    lv_label_set_long_mode(mv, LV_LABEL_LONG_DOT);
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
    lv_obj_set_pos(fv, AMSD_CB, AMSD_IDENT_VAL_Y);
    lv_obj_set_width(fv, AMSD_CW);
    lv_label_set_long_mode(fv, LV_LABEL_LONG_DOT);
  }
}

// The reason this card exists. A bay can carry filament whose weight nobody
// ever recorded, and the tile can only fall silent about it - here it says so
// in words, in the place the figure would have been.
static void buildWeight(lv_obj_t* box, const AmsSpoolDetail& d) {
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

  // The percentage the printer reports, which exists on bays the database has
  // no gram figure for - a Bambu spool says how full it is without anyone
  // having weighed it.
  if (d.remain_pct >= 0) {
    lv_obj_t* pct = lv_label_create(box);
    if (pct) {
      char buf[12];
      snprintf(buf, sizeof(buf), "%d %%", (int)d.remain_pct);
      lv_label_set_text(pct, buf);
      lv_obj_set_style_text_color(pct,
        lv_color_hex(d.remain_pct < AMSD_LOW_PCT ? UI_COL_WARN : UI_COL_ACCENT), 0);
      lv_obj_set_style_text_font(pct, UI_FONT_TITLE, 0);
      lv_obj_align(pct, LV_ALIGN_TOP_RIGHT, -AMSD_PAD, AMSD_WEIGHT_VAL_Y);
    }
  }

  // Share of a full spool: from the two weights when both are there, else the
  // printer's own percentage.
  int share = -1;
  if (known && d.total_g > 0.0f) {
    share = (int)((d.remaining_g / d.total_g) * 100.0f + 0.5f);
    if (share < 0) share = 0;
    if (share > 100) share = 100;
  } else if (d.remain_pct >= 0) {
    share = d.remain_pct;
  }

  if (share >= 0) {
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
  // weight, why there is no spool, and which bay carries the same filament.
  // Joined rather than given a place each, because at most one of the first
  // two can be true and the third is a footnote either way.
  //
  // This is also what a card full of dashes needs. Six empty fields with no
  // sentence anywhere read as a fault in the scale; the sentence says the
  // fault is not here.
  char note[96] = "";
  if (!d.found) {
    copyT(note, sizeof(note), d.spool_id > 0 ? STR_AMSD_FAIL : STR_AMSD_NO_SPOOL);
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
      lv_obj_set_style_text_color(n, lv_color_hex(UI_COL_INK_SOFT), 0);
      lv_obj_set_style_text_font(n, UI_FONT_CAPTION, 0);
      // Size before position, and a real height: with LV_SIZE_CONTENT the
      // label grows downwards instead of ellipsising, which is how the second
      // line ended up on top of the divider.
      lv_obj_set_size(n, AMSD_BAR_W, AMSD_NOTE_H);
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
  if (d.last_dried[0]) {
    isoToDe(d.last_dried, de, sizeof(de));
    driedDisplayStr(de, dried_txt, sizeof(dried_txt));
  }
  // The one field the card can set, and the reason it can: after a drying
  // cycle the spool is in the bay, and recording the date used to mean taking
  // it out and putting it on the pad.
  lv_obj_t* dried = cell(box, AMSD_CB, AMSD_R3, STR_LBL_LAST_DRIED,
                         dried_txt[0] ? dried_txt : nullptr, UI_COL_VALUE_BLUE,
                         UI_FONT_SMALL, canEdit(d) ? driedCellCb : nullptr);
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

void showAmsDetailPopup(const AmsSpoolDetail& d) {
  // Kept so a write can update one field and redraw from it. Guarded against
  // self-assignment, because the redraw after a write passes s_det back in.
  if (&d != &s_det) s_det = d;

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

  buildHeader(box, s_det);
  buildDivider(box, AMSD_HDR_H);
  buildIdentity(box, s_det);
  buildDivider(box, AMSD_DIV1_Y);
  buildWeight(box, s_det);
  buildDivider(box, AMSD_DIV2_Y);
  buildGrid(box, s_det);

  // Sits under the grid, in the strip the box leaves free. Only after a write
  // that did not take, so the card never looks as if nothing had happened.
  if (s_write_failed) {
    lv_obj_t* w = lv_label_create(box);
    if (w) {
      char buf[40];
      copyT(buf, sizeof(buf), STR_AMSD_WRITE_FAIL);
      lv_label_set_text(w, buf);
      lv_obj_set_style_text_color(w, lv_color_hex(UI_COL_BAD_TEXT), 0);
      lv_obj_set_style_text_font(w, UI_FONT_CAPTION, 0);
      lv_obj_align(w, LV_ALIGN_TOP_RIGHT, -AMSD_PAD, AMSD_NOTE_Y);
    }
  }

  logLvMem("amsdetail/post", 1);
  logSDf("AMSDETAIL: %s, spool %d, found=%d", s_det.bay, s_det.spool_id,
         (int)s_det.found);
}

void handleAmsDetailDeferredActions() {
  if (!s_dried_pending && !s_status_pending) return;
  // The card has to be up: both writes redraw it, and a card taken down while
  // the question stood means the user moved on.
  if (!s_pop) { s_dried_pending = s_status_pending = false; return; }

  const int spool_id = s_det.spool_id;
  s_write_failed = false;

  if (s_dried_pending) {
    s_dried_pending = false;
    char iso[32];
    nowIsoUtc(iso, sizeof(iso));
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
  if (s_pop) showAmsDetailPopup(s_det);
}
