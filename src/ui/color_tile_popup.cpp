#include "color_tile_popup.h"

#include <Arduino.h>
#include <lvgl.h>
#include <stdio.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui/theme.h"
#include "ui_common.h"

// The card: a title row as tall as the close button, the tile, one line of
// codes. 300 of the panel's 320, so the tile can be as large as it gets.
#define CT_BOX_W     440
#define CT_BOX_H     300
#define CT_PAD        14
#define CT_HDR_Y      10
#define CT_TILE_Y     64
#define CT_TILE_H    180
#define CT_CODE_Y    256
#define CT_NAME_GAP   8    // between the name and the close button
#define CT_CODES_MAX 32    // "#RRGGBBAA  #RRGGBBAA" and its terminator

static lv_obj_t* s_pop = nullptr;

static void closeColorTile(lv_event_t* e) {
  if (!s_pop) return;
  // Asynchronous: this runs inside the click of a child of what is freed.
  lv_obj_del_async(s_pop);
  s_pop = nullptr;
}

// Cleared here too, so a screen rebuilt underneath that takes the tile with
// it leaves no stale pointer behind.
static void onColorTileDeleted(lv_event_t* e) {
  if (s_pop == lv_event_get_target(e)) s_pop = nullptr;
}

// A plain rectangle that lets a tap through to the scrim, which closes.
static lv_obj_t* passiveBox(lv_obj_t* parent, int x, int y, int w, int h) {
  lv_obj_t* o = lv_obj_create(parent);
  lv_obj_set_pos(o, x, y);
  lv_obj_set_size(o, w, h);
  lv_obj_set_style_pad_all(o, 0, 0);
  lv_obj_clear_flag(o, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(o, LV_OBJ_FLAG_CLICKABLE);
  return o;
}

// The colour itself. Two colours run into each other across the tile, the
// way the small swatches of the tag view and the pickers draw them.
static void buildTile(lv_obj_t* box, const ColorTileSpec& spec) {
  lv_obj_t* tile = passiveBox(box, CT_PAD, CT_TILE_Y, CT_BOX_W - 2 * CT_PAD, CT_TILE_H);
  lv_obj_set_style_radius(tile, UI_RADIUS_BTN, 0);
  lv_obj_set_style_border_color(tile, lv_color_hex(UI_COL_RULE), 0);
  lv_obj_set_style_border_width(tile, 1, 0);
  swatchPaint(tile, spec.color);
  if (!spec.second.valid) return;
  lv_obj_set_style_bg_grad_color(tile, lv_color_hex(spec.second.rgb), 0);
  lv_obj_set_style_bg_grad_dir(tile, LV_GRAD_DIR_HOR, 0);
}

static void buildCloseButton(lv_obj_t* box) {
  lv_obj_t* btn = lv_btn_create(box);
  lv_obj_set_size(btn, UI_TOUCH_MIN, UI_TOUCH_MIN);
  lv_obj_set_pos(btn, CT_BOX_W - CT_PAD - UI_TOUCH_MIN, CT_HDR_Y);
  lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
  lv_obj_add_event_cb(btn, closeColorTile, LV_EVENT_CLICKED, NULL);
  lv_obj_t* x = lv_label_create(btn);
  lv_label_set_text(x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_font(x, UI_FONT_TITLE, 0);
  lv_obj_center(x);
  uiBtnRole(btn, BTN_CLOSE);
}

// Name and close button on one row, codes and kind under the tile.
static void buildWords(lv_obj_t* box, const ColorTileSpec& spec, const char* codes) {
  const bool has_name = spec.name && spec.name[0];
  const int name_w = CT_BOX_W - 2 * CT_PAD - UI_TOUCH_MIN - CT_NAME_GAP;
  lv_obj_t* name = labelOneLine(box, has_name ? spec.name : codes, UI_FONT_HEADLINE, name_w);
  lv_obj_set_style_text_color(name, lv_color_hex(UI_COL_INK), 0);
  lv_obj_align(name, LV_ALIGN_TOP_LEFT, CT_PAD,
               CT_HDR_Y + (UI_TOUCH_MIN - lv_font_get_line_height(UI_FONT_HEADLINE)) / 2);

  if (has_name) {
    lv_obj_t* code = lv_label_create(box);
    lv_label_set_text(code, codes);
    lv_obj_set_style_text_font(code, UI_FONT_BODY, 0);
    lv_obj_set_style_text_color(code, lv_color_hex(UI_COL_INK_2), 0);
    lv_obj_set_pos(code, CT_PAD, CT_CODE_Y);
  }

  int kind_id = -1;
  if (spec.second.valid)                     kind_id = STR_COLOR_TILE_TWO;
  else if (spoolColorSeeThrough(spec.color)) kind_id = STR_COLOR_TILE_CLEAR;
  if (kind_id < 0) return;
  lv_obj_t* kind = lv_label_create(box);
  lv_label_set_text(kind, T(kind_id));
  lv_obj_set_style_text_font(kind, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_color(kind, lv_color_hex(UI_COL_CAPTION), 0);
  lv_obj_align(kind, LV_ALIGN_TOP_RIGHT, -CT_PAD, CT_CODE_Y + 2);
}

void showColorTile(const ColorTileSpec& spec) {
  if (!spec.color.valid) return;
  if (s_pop) { lv_obj_del_async(s_pop); s_pop = nullptr; }

  char codes[CT_CODES_MAX];
  char first[SPOOL_COLOR_HEX_MAX], second[SPOOL_COLOR_HEX_MAX];
  spoolColorFormat(spec.color, first, sizeof(first));
  spoolColorFormat(spec.second, second, sizeof(second));
  snprintf(codes, sizeof(codes), second[0] ? "%s  %s" : "%s", first, second);
  logSDf("ColorTile: open %s", codes);

  s_pop = lv_obj_create(lv_scr_act());
  lv_obj_set_size(s_pop, 480, 320);
  lv_obj_set_pos(s_pop, 0, 0);
  lv_obj_set_style_bg_color(s_pop, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(s_pop, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(s_pop, 0, 0);
  lv_obj_set_style_radius(s_pop, 0, 0);
  lv_obj_clear_flag(s_pop, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(s_pop, closeColorTile, LV_EVENT_CLICKED, NULL);
  lv_obj_add_event_cb(s_pop, onColorTileDeleted, LV_EVENT_DELETE, NULL);

  lv_obj_t* box = passiveBox(s_pop, 0, 0, CT_BOX_W, CT_BOX_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);

  buildTile(box, spec);
  buildWords(box, spec, codes);
  buildCloseButton(box);
}

static void onSwatchClicked(lv_event_t* e) {
  const ColorTileSource source = (ColorTileSource)lv_event_get_user_data(e);
  if (source) showColorTile(source());
}

void colorTileAttach(lv_obj_t* swatch, ColorTileSource source, int extra_px) {
  if (!swatch || !source) return;
  lv_obj_add_flag(swatch, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_set_ext_click_area(swatch, extra_px);
  lv_obj_add_event_cb(swatch, onSwatchClicked, LV_EVENT_CLICKED, (void*)source);
}
