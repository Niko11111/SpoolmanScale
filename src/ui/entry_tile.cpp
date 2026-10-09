#include "entry_tile.h"

#include "lang.h"
#include "ui/theme.h"

// The screen's own coordinates: tiles from under the context line at y 60
// down to the low row, which ends 16 px above the bottom edge.
#define ENTRY_X             16
#define ENTRY_GAP           8
#define ENTRY_ROW_W         (480 - 2 * ENTRY_X)
#define ENTRY_TILE_Y        84
#define ENTRY_TILE_H        156
#define ENTRY_LOW_Y         256
#define ENTRY_LOW_H         48
// Air between the caption and the tile's sides, and between symbol and
// caption.
#define TILE_TEXT_PAD_X     6
#define TILE_SYMBOL_GAP     10
// The longest caption wraps to two lines ("Archivierte Spulen", "Nouvelle de
// la base" in 132 px); symbol and two lines are centred as one block.
#define TILE_CAPTION_LINES  2

static void neutralLook(lv_obj_t* b) {
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(b, 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_LINE), 0);
}

EntryRect entryTileRect(int i, int n) {
  if (n < 1) n = 1;
  const lv_coord_t w = (ENTRY_ROW_W - (n - 1) * ENTRY_GAP) / n;
  return { (lv_coord_t)(ENTRY_X + i * (w + ENTRY_GAP)), ENTRY_TILE_Y, w, ENTRY_TILE_H };
}

static lv_obj_t* entryBase(lv_obj_t* parent, const EntryRect& r, lv_event_cb_t cb) {
  lv_obj_t* b = lv_btn_create(parent);
  lv_obj_set_size(b, r.w, r.h);
  lv_obj_set_pos(b, r.x, r.y);
  lv_obj_set_style_radius(b, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_pad_all(b, 0, 0);
  lv_obj_add_event_cb(b, cb, LV_EVENT_CLICKED, NULL);
  return b;
}

lv_obj_t* entryTile(lv_obj_t* parent, const EntryRect& r, const char* symbol,
                    const char* caption, lv_event_cb_t cb) {
  lv_obj_t* b = entryBase(parent, r, cb);
  neutralLook(b);

  const lv_coord_t symbol_h = lv_font_get_line_height(UI_FONT_ICON);
  const lv_coord_t block_h = symbol_h + TILE_SYMBOL_GAP +
                             TILE_CAPTION_LINES * lv_font_get_line_height(UI_FONT_BODY);
  const lv_coord_t symbol_y = (r.h - block_h) / 2;

  lv_obj_t* sym = lv_label_create(b);
  lv_label_set_text(sym, symbol);
  lv_obj_set_style_text_font(sym, UI_FONT_ICON, 0);
  lv_obj_set_style_text_color(sym, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_align(sym, LV_ALIGN_TOP_MID, 0, symbol_y);

  lv_obj_t* l = lv_label_create(b);
  lv_label_set_text(l, caption);
  lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(l, r.w - 2 * TILE_TEXT_PAD_X);
  lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(l, LV_ALIGN_TOP_MID, 0, symbol_y + symbol_h + TILE_SYMBOL_GAP);
  return b;
}

static lv_obj_t* entryLowButton(lv_obj_t* parent, const EntryRect& r, const char* caption,
                                bool cancel, lv_event_cb_t cb) {
  lv_obj_t* b = entryBase(parent, r, cb);
  if (cancel) {
    lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_BAD_BG), 0);
    lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_BAD_BG_PRESSED), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(b, 0, 0);
  } else {
    neutralLook(b);
  }
  lv_obj_t* l = lv_label_create(b);
  lv_label_set_text(l, caption);
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
  lv_obj_set_width(l, r.w - 2 * TILE_TEXT_PAD_X);
  lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(cancel ? UI_COL_BAD_TEXT : UI_COL_INK_2), 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_center(l);
  return b;
}

void entryBottomRow(lv_obj_t* parent, const char* id_caption, lv_event_cb_t id_cb,
                    lv_event_cb_t cancel_cb) {
  const lv_coord_t half_w = (ENTRY_ROW_W - ENTRY_GAP) / 2;
  const EntryRect id_r = { ENTRY_X, ENTRY_LOW_Y, half_w, ENTRY_LOW_H };
  const EntryRect cancel_r = { (lv_coord_t)(ENTRY_X + half_w + ENTRY_GAP), ENTRY_LOW_Y,
                               half_w, ENTRY_LOW_H };
  entryLowButton(parent, id_r, id_caption, false, id_cb);
  entryLowButton(parent, cancel_r, T(STR_CANCEL), true, cancel_cb);
}
