#include "tag_view.h"

#include <Arduino.h>
#include <lvgl.h>
#include <string.h>

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "services/tag_write.h"
#include "services/user_options.h"
#include "tag_write_popup.h"
#include "theme.h"
#include "ui_common.h"

// Last: T() is a macro, and ArduinoJson uses T as a template parameter.
#include "lang.h"

// ---- geometry ------------------------------------------------
// The More Info card's box, header and two columns, as the AMS bay card has
// them too: this answers the same kind of question about the same spool, and
// one set of measurements is one thing to keep in step. What differs is the
// bottom row, which holds the two buttons instead of a third row of fields.
#define TV_BOX_W        464
#define TV_BOX_H        300
#define TV_BOX_X        8
#define TV_BOX_Y        10
#define TV_HDR_H        52
#define TV_PAD          10
#define TV_CLOSE        44

#define TV_CA           10
#define TV_CB           236
#define TV_CW           218
#define TV_FULL_W       (TV_BOX_W - 2 * TV_PAD)
// Caption to value: a font 16 value under a font 12 caption.
#define TV_VF           16

#define TV_SWATCH       42
#define TV_MAT_X        60
#define TV_MAT_W        166

#define TV_IDENT_CAP_Y  60
#define TV_IDENT_VAL_Y  76
#define TV_DIV1_Y       104
#define TV_R1           110
#define TV_R2           152
#define TV_R3           194
#define TV_DIV2_Y       238
#define TV_BTN_Y        246
#define TV_BTN_H        UI_TOUCH_MIN
#define TV_BTN_W        ((TV_BOX_W - 3 * TV_PAD) / 2)

// The format, on the left of the header where More Info keeps its status: it
// is how the tag is written, not what the spool is, so it sits apart from the
// swatch and the filament. As wide as the room left of the centred title.
#define TV_FMT_W        150
#define TV_FMT_CAP_Y    8

// What the capability container reports for the three NTAG21x sizes: the NDEF
// area, which is what tagCachedBytes() hands out, and which names the chip.
#define TV_NTAG213_BYTES  144
#define TV_NTAG215_BYTES  496
#define TV_NTAG216_BYTES  872

static lv_obj_t* s_view = nullptr;
static bool s_erase_pending = false;
static bool s_write_pending = false;

// What the card was built from. Taken on every pass and compared whole, and
// the card is built again when anything in it differs: a tag put down or
// lifted, the main poll filling in a Bambu tag over several passes, or the
// lookup naming the spool a moment after the tag was read.
struct Shown {
  char     uid[26];
  uint8_t  kind;
  uint16_t bytes;
  TagInfo  info;
  bool     reader_ok;
  bool     found;
  int      spool_id;
  char     spool_name[32];
};
static Shown s_shown;

static void snapshot(Shown* s) {
  memset(s, 0, sizeof(*s));
  snprintf(s->uid, sizeof(s->uid), "%s", tagCachedUid());
  s->kind  = tagCachedKindCode();
  s->bytes = tagCachedBytes();
  // memcpy rather than assignment: the whole struct is compared with memcmp,
  // padding included, and the cache clears its padding before it fills.
  memcpy(&s->info, tagCachedInfo(), sizeof(s->info));
  s->reader_ok = nfc_ok;
  s->found     = sm_found && sm_id > 0;
  s->spool_id  = s->found ? sm_id : 0;
  if (s->found) snprintf(s->spool_name, sizeof(s->spool_name), "%s", sm_filament_name);
}

bool isTagViewOpen() { return s_view != nullptr; }

void closeTagView() {
  s_erase_pending = false;
  s_write_pending = false;
  releaseScreen(&s_view);
}

// From the loop only, where the next build follows in the same pass and the
// pool must not hold two cards at once.
static void dropView() {
  if (s_view) { lv_obj_del(s_view); s_view = nullptr; }
}

static void closeCb(lv_event_t* e)  { closeTagView(); }
static void eraseCb(lv_event_t* e)  { s_erase_pending = true; }
static void writeCb(lv_event_t* e)  { s_write_pending = true; }

// ---- pieces --------------------------------------------------

// One line with dots at the end, as on the AMS bay card: a label with a width
// and no height grows downwards instead, into the row below.
static void oneLine(lv_obj_t* l, int w, const lv_font_t* font) {
  lv_obj_set_size(l, w, lv_font_get_line_height(font));
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
}

static void caption(lv_obj_t* box, int x, int y, const char* text) {
  lv_obj_t* c = lv_label_create(box);
  if (!c) return;
  lv_label_set_text(c, text);
  lv_obj_set_style_text_color(c, lv_color_hex(UI_COL_CAPTION), 0);
  lv_obj_set_style_text_font(c, UI_FONT_CAPTION, 0);
  lv_obj_set_pos(c, x, y);
}

static void cell(lv_obj_t* box, int x, int y, int w, const char* cap, const char* value,
                 const lv_font_t* font = UI_FONT_BODY) {
  caption(box, x, y, cap);
  lv_obj_t* v = lv_label_create(box);
  if (!v) return;
  const bool has = value && value[0];
  lv_label_set_text(v, has ? value : "-");
  lv_obj_set_style_text_color(v, lv_color_hex(has ? UI_COL_INK : UI_COL_CAPTION), 0);
  lv_obj_set_style_text_font(v, font, 0);
  oneLine(v, w, font);
  lv_obj_set_pos(v, x, y + TV_VF);
}

// A sentence in place of fields: no tag, a blank one, one nothing here reads.
static void note(lv_obj_t* box, int y, const char* text) {
  lv_obj_t* l = lv_label_create(box);
  if (!l) return;
  lv_label_set_text(l, text);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
  lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(l, TV_FULL_W);
  lv_obj_set_pos(l, TV_PAD, y);
}

static void divider(lv_obj_t* box, int y) {
  lv_obj_t* d = lv_obj_create(box);
  if (!d) return;
  lv_obj_set_size(d, TV_FULL_W, 1);
  lv_obj_set_pos(d, TV_PAD, y);
  lv_obj_set_style_bg_color(d, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_border_width(d, 0, 0);
  lv_obj_set_style_radius(d, 0, 0);
  lv_obj_set_style_pad_all(d, 0, 0);
}

// Protocol names read the same in every language; the three answers that are
// not a format are words.
static const char* formatText(const TagInfo& i) {
  if (!i.fmt[0])                     return "";
  if (!strcmp(i.fmt, "blank"))       return T(STR_TV_FMT_BLANK);
  if (!strcmp(i.fmt, "unknown"))     return T(STR_TV_FMT_UNKNOWN);
  if (!strcmp(i.fmt, "unsupported")) return T(STR_TV_FMT_NONE);
  if (!strcmp(i.fmt, "ACE"))         return "Anycubic ACE";
  if (!strcmp(i.fmt, "Bambu"))       return "Bambu Lab";
  return i.fmt;
}

static void chipText(char* out, size_t n, uint8_t kind, uint16_t bytes) {
  if (kind == TAG_KIND_MIFARE) { snprintf(out, n, "MIFARE Classic"); return; }
  const char* model = bytes == TV_NTAG213_BYTES ? "NTAG213"
                    : bytes == TV_NTAG215_BYTES ? "NTAG215"
                    : bytes == TV_NTAG216_BYTES ? "NTAG216" : "NTAG";
  if (!bytes) { snprintf(out, n, "%s", model); return; }
  char b[24];
  snprintf(b, sizeof(b), T(STR_W_TAG_KIND_BYTES), (unsigned)bytes);
  snprintf(out, n, "%s%s", model, b);
}

// "245 °C" for a single setpoint, "190 - 220 °C" for a range.
static void rangeText(char* out, size_t n, uint16_t lo, uint16_t hi) {
  out[0] = '\0';
  if (!lo && !hi) return;
  if (lo && hi && lo != hi) snprintf(out, n, "%u - %u °C", (unsigned)lo, (unsigned)hi);
  else                      snprintf(out, n, "%u °C", (unsigned)(hi ? hi : lo));
}

// A format the scale recognised, as opposed to one of the three answers that
// are not a format: blank, unknown, none.
static bool isRealFormat(const TagInfo& i) {
  return i.fmt[0] && strcmp(i.fmt, "blank") && strcmp(i.fmt, "unknown") &&
         strcmp(i.fmt, "unsupported");
}

// Caption over value like every field on the card, and no frame: on this
// device a frame with a fill is a button, and this cannot be pressed. Green
// when the scale knows the format, quiet for blank, unknown and none, so the
// header says at a glance whether the tag is one it understands.
static void formatInfo(lv_obj_t* hdr, const TagInfo& i) {
  caption(hdr, TV_PAD, TV_FMT_CAP_Y, T(STR_TW_OPT_FMT));
  lv_obj_t* val = lv_label_create(hdr);
  if (!val) return;
  lv_label_set_text(val, formatText(i));
  lv_obj_set_style_text_color(val, lv_color_hex(isRealFormat(i) ? UI_COL_ACCENT
                                                                : UI_COL_INK_SOFT), 0);
  lv_obj_set_style_text_font(val, UI_FONT_BODY, 0);
  oneLine(val, TV_FMT_W, UI_FONT_BODY);
  lv_obj_set_pos(val, TV_PAD, TV_FMT_CAP_Y + TV_VF);
}

static void buildHeader(lv_obj_t* box, const Shown& s) {
  lv_obj_t* hdr = lv_obj_create(box);
  if (!hdr) return;
  lv_obj_set_size(hdr, TV_BOX_W, TV_HDR_H);
  lv_obj_set_pos(hdr, 0, 0);
  lv_obj_set_style_bg_color(hdr, lv_color_hex(UI_COL_GROUND), 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_set_style_pad_all(hdr, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t* title = lv_label_create(hdr);
  if (title) {
    lv_label_set_text(title, T(STR_TV_TITLE));
    lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_set_style_text_font(title, UI_FONT_BODY, 0);
    lv_obj_align(title, LV_ALIGN_CENTER, 0, 0);
  }
  if (s.reader_ok && s.uid[0] && s.info.fmt[0]) formatInfo(hdr, s.info);

  lv_obj_t* x = lv_btn_create(hdr);
  if (!x) return;
  lv_obj_set_size(x, TV_CLOSE, TV_CLOSE);
  lv_obj_align(x, LV_ALIGN_RIGHT_MID, -TV_PAD, 0);
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

// Swatch, material and vendor, the main screen's order - what the tag says the
// spool is.
static void buildIdentity(lv_obj_t* box, const Shown& s) {
  const TagInfo& i = s.info;

  lv_obj_t* sw = lv_obj_create(box);
  if (sw) {
    lv_obj_set_size(sw, TV_SWATCH, TV_SWATCH);
    lv_obj_set_pos(sw, TV_PAD, TV_IDENT_CAP_Y - 4);
    lv_obj_set_style_radius(sw, UI_RADIUS_INPUT, 0);
    lv_obj_set_style_border_color(sw, lv_color_hex(UI_COL_RULE), 0);
    lv_obj_set_style_border_width(sw, 1, 0);
    lv_obj_set_style_pad_all(sw, 0, 0);
    lv_obj_clear_flag(sw, LV_OBJ_FLAG_SCROLLABLE);
    if (i.has_color) {
      const SpoolColor c = { ((uint32_t)i.r << 16) | ((uint32_t)i.g << 8) | i.b, 0xFF, true };
      swatchPaint(sw, c);
    } else {
      lv_obj_set_style_bg_color(sw, lv_color_hex(UI_COL_EMPTY), 0);
    }
  }

  cell(box, TV_MAT_X, TV_IDENT_CAP_Y, TV_MAT_W, T(STR_LBL_MATERIAL), i.material, UI_FONT_TITLE);
  cell(box, TV_CB, TV_IDENT_CAP_Y, TV_CW, T(STR_LBL_VENDOR), i.brand);
}

// UID and chip first, then whatever the record carries, in two columns and
// two more rows. A value too long for a column - Bambu's tray UUID - takes a
// row of its own.
static void buildGrid(lv_obj_t* box, const Shown& s) {
  const TagInfo& i = s.info;
  char chip[40];
  chipText(chip, sizeof(chip), s.kind, s.bytes);
  cell(box, TV_CA, TV_R1, TV_CW, T(STR_TV_UID), s.uid);
  cell(box, TV_CB, TV_R1, TV_CW, T(STR_TV_CHIP), chip);

  // Nothing to list: say what the tag is instead.
  const char* why = nullptr;
  if      (!i.fmt[0])                     why = nullptr;
  else if (!strcmp(i.fmt, "blank"))       why = T(STR_TV_BLANK_NOTE);
  else if (!strcmp(i.fmt, "unknown"))     why = T(STR_W_TAG_UNKNOWN);
  else if (!strcmp(i.fmt, "unsupported")) why = T(STR_W_TAG_NOREC);
  if (why) { note(box, TV_R2, why); return; }

  struct Item { int cap; char val[40]; bool wide; };
  Item items[8];
  int n = 0;
  auto add = [&](int cap, const char* v, bool wide) {
    if (!v || !v[0] || n >= (int)(sizeof(items) / sizeof(items[0]))) return;
    items[n].cap = cap;
    items[n].wide = wide;
    snprintf(items[n].val, sizeof(items[n].val), "%s", v);
    n++;
  };
  char buf[24];
  rangeText(buf, sizeof(buf), i.et_lo, i.et_hi);   add(STR_W_TAG_NOZZLE, buf, false);
  rangeText(buf, sizeof(buf), i.bed_lo, i.bed_hi); add(STR_W_TAG_BED, buf, false);
  buf[0] = '\0';
  if (i.weight_g) snprintf(buf, sizeof(buf), "%u g", (unsigned)i.weight_g);
  add(STR_W_TAG_WEIGHT, buf, false);
  add(STR_LBL_PRODUCTION_DATE, i.prod_date, false);
  add(STR_W_TAG_SKU, i.sku, false);
  add(STR_W_TAG_TRAY, i.tray_uuid, true);

  const int rows[] = { TV_R2, TV_R3 };
  int row = 0, col = 0;
  for (int k = 0; k < n && row < 2; k++) {
    if (items[k].wide) {
      if (col) { row++; col = 0; }
      if (row >= 2) break;
      cell(box, TV_CA, rows[row], TV_FULL_W, T(items[k].cap), items[k].val);
      row++;
      continue;
    }
    cell(box, col ? TV_CB : TV_CA, rows[row], TV_CW, T(items[k].cap), items[k].val);
    if (col) { row++; col = 0; } else col = 1;
  }
}

static lv_obj_t* button(lv_obj_t* box, int x, const char* text, bool danger,
                        bool enabled, lv_event_cb_t cb) {
  lv_obj_t* b = lv_btn_create(box);
  if (!b) return nullptr;
  lv_obj_set_size(b, TV_BTN_W, TV_BTN_H);
  lv_obj_set_pos(b, x, TV_BTN_Y);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  // Standing but inert rather than hidden: the button says why it cannot be
  // pressed, and a row that changed shape with the tag would move the other
  // one. Not LV_STATE_DISABLED, whose theme filter paints it light grey - the
  // brightest thing on the card for the one thing that does nothing.
  if (enabled) {
    lv_obj_set_style_bg_color(b, lv_color_hex(danger ? UI_COL_BAD_BG : UI_COL_OK_BG), 0);
    lv_obj_set_style_bg_color(b, lv_color_hex(danger ? UI_COL_BAD_BG_PRESSED : UI_COL_OK_BG_PRESSED),
                              LV_STATE_PRESSED);
    lv_obj_add_event_cb(b, cb, LV_EVENT_CLICKED, nullptr);
  } else {
    lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_SURFACE_2), 0);
    lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_LINE_SOFT), 0);
    lv_obj_set_style_border_width(b, 1, 0);
    lv_obj_clear_flag(b, LV_OBJ_FLAG_CLICKABLE);
  }

  lv_obj_t* l = lv_label_create(b);
  if (!l) return b;
  lv_label_set_text(l, text);
  lv_obj_set_style_text_color(l, lv_color_hex(!enabled ? UI_COL_CAPTION
                                              : danger ? UI_COL_BAD_TEXT : UI_COL_OK_TEXT), 0);
  lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  oneLine(l, TV_BTN_W - 2 * TV_PAD, UI_FONT_BODY);
  lv_obj_center(l);
  return b;
}

// Erase and write for an NTAG. A MIFARE tag can only be read, and the row
// says so instead; with no tag there is nothing to act on.
static void buildButtons(lv_obj_t* box, const Shown& s) {
  if (!s.reader_ok || !s.uid[0]) return;
  divider(box, TV_DIV2_Y);

  if (s.kind != TAG_KIND_NTAG) {
    lv_obj_t* l = lv_label_create(box);
    if (!l) return;
    lv_label_set_text(l, T(STR_TW_ERR_NOT_NTAG));
    lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
    lv_obj_align(l, LV_ALIGN_TOP_MID, 0, TV_BTN_Y + (TV_BTN_H - lv_font_get_line_height(UI_FONT_BODY)) / 2);
    return;
  }

  // Blank has nothing to lose. Not read yet has not said so either way, and
  // the erase asks before it does anything.
  const bool erasable = strcmp(s.info.fmt, "blank") != 0;
  char erase[32];
  snprintf(erase, sizeof(erase), LV_SYMBOL_TRASH " %s", T(STR_TW_BTN_ERASE));
  button(box, TV_PAD, erase, true, erasable, eraseCb);

  // The same floor the question after a link keeps: an NDEF record does not
  // fit an NTAG213, and offering it there only ends in "needs 176 bytes".
  const bool fits = !(TAG_FMT_IS_NDEF(g_tagwrite_fmt) && s.bytes &&
                      s.bytes < TAGWRITE_NDEF_MIN_BYTES);
  char write[40];
  if (!s.found)  copyT(write, sizeof(write), STR_TV_NOSPOOL);
  else if (!fits) copyT(write, sizeof(write), STR_TV_TOOSMALL);
  else            snprintf(write, sizeof(write), T(STR_TV_WRITE), s.spool_id);
  button(box, TV_PAD + TV_BTN_W + TV_PAD, write, false, s.found && fits, writeCb);
}

static void build() {
  if (!lvPoolHasRoomForRow()) {
    logSD("TAGVIEW: LVGL pool low, card not built");
    return;
  }
  logLvMem("tagview/pre", 0);

  s_view = lv_obj_create(lv_scr_act());
  if (!s_view) return;
  lv_obj_set_size(s_view, 480, 320);
  lv_obj_set_pos(s_view, 0, 0);
  lv_obj_set_style_bg_color(s_view, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(s_view, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(s_view, 0, 0);
  lv_obj_set_style_radius(s_view, 0, 0);
  lv_obj_set_style_pad_all(s_view, 0, 0);
  lv_obj_clear_flag(s_view, LV_OBJ_FLAG_SCROLLABLE);
  // Swallows the taps the main screen would otherwise take through the scrim.
  lv_obj_add_flag(s_view, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t* box = lv_obj_create(s_view);
  if (!box) { dropView(); return; }
  lv_obj_set_size(box, TV_BOX_W, TV_BOX_H);
  lv_obj_set_pos(box, TV_BOX_X, TV_BOX_Y);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  buildHeader(box, s_shown);
  divider(box, TV_HDR_H);

  if (!s_shown.reader_ok) {
    note(box, TV_IDENT_CAP_Y, T(STR_TV_READER_DOWN));
  } else if (!s_shown.uid[0]) {
    note(box, TV_IDENT_CAP_Y, T(STR_TV_PLACE));
  } else {
    buildIdentity(box, s_shown);
    divider(box, TV_DIV1_Y);
    buildGrid(box, s_shown);
    buildButtons(box, s_shown);
  }

  logLvMem("tagview/post", 1);
}

void handleTagViewDeferredActions() {
  if (show_tag_view_pending) {
    show_tag_view_pending = false;
    snapshot(&s_shown);
    dropView();
    build();
    logSDf("TAGVIEW: open, uid=%s fmt=%s spool=%d", s_shown.uid[0] ? s_shown.uid : "-",
           s_shown.info.fmt[0] ? s_shown.info.fmt : "-", s_shown.spool_id);
    return;
  }

  if (!s_view) {
    s_erase_pending = false;
    s_write_pending = false;
    return;
  }

  // Both questions stand where the card stood, and the card goes first: the
  // pool holds one of the two, the way the tag write question and its busy
  // card take turns.
  if (s_erase_pending) {
    s_erase_pending = false;
    dropView();
    logSD("TAGVIEW: erase asked");
    askTagEraseFromView();
    return;
  }
  if (s_write_pending) {
    s_write_pending = false;
    const int id = s_shown.spool_id;
    dropView();
    logSDf("TAGVIEW: write asked, spool %d", id);
    if (id > 0) showTagWriteAskPopup(id);
    return;
  }

  Shown now;
  snapshot(&now);
  if (memcmp(&now, &s_shown, sizeof(now)) != 0) {
    memcpy(&s_shown, &now, sizeof(now));
    dropView();
    build();
  }
}
