#include "ui/list_row.h"

#include "ui/theme.h"
#include "ui/ui_common.h"

#define LR_SWATCH_PX            14
#define LR_LOCATION_PAD_BOTTOM  4
#define LR_HIT_BORDER_W         2

static lv_style_t s_st_frame[2];
static lv_style_t s_st_pressed;
static lv_style_t s_st_text[LR_TEXT_KINDS];
static lv_style_t s_st_swatch;
static lv_style_t s_st_hit_frame, s_st_hit_text, s_st_current_frame, s_st_current_text;
static bool       s_ready = false;

static void initFrames() {
  lv_style_t* spool = &s_st_frame[LR_FRAME_SPOOL];
  lv_style_init(spool);
  lv_style_set_bg_color(spool, lv_color_hex(UI_COL_SURFACE));
  lv_style_set_radius(spool, UI_RADIUS_INPUT);
  lv_style_set_shadow_width(spool, 0);
  lv_style_set_border_width(spool, 1);
  lv_style_set_border_color(spool, lv_color_hex(UI_COL_LINE_SOFT));
  lv_style_set_pad_all(spool, 0);

  lv_style_t* loc = &s_st_frame[LR_FRAME_LOCATION];
  lv_style_init(loc);
  lv_style_set_bg_color(loc, lv_color_hex(UI_COL_CHIP));
  lv_style_set_radius(loc, UI_RADIUS_INPUT);
  lv_style_set_shadow_width(loc, 0);
  lv_style_set_border_width(loc, 1);
  lv_style_set_border_color(loc, lv_color_hex(UI_COL_DIVIDER));
  lv_style_set_pad_bottom(loc, LR_LOCATION_PAD_BOTTOM);

  lv_style_init(&s_st_pressed);
  lv_style_set_bg_color(&s_st_pressed, lv_color_hex(UI_COL_PRESS_FILL));
}

static void initText(ListRowText kind, const lv_font_t* font, uint32_t colour) {
  lv_style_init(&s_st_text[kind]);
  lv_style_set_text_font(&s_st_text[kind], font);
  lv_style_set_text_color(&s_st_text[kind], lv_color_hex(colour));
}

static void initTexts() {
  initText(LR_TEXT_ID,       UI_FONT_BODY,  UI_COL_ACCENT);
  initText(LR_TEXT_NAME,     UI_FONT_BODY,  UI_COL_INK);
  initText(LR_TEXT_WEIGHT,   UI_FONT_SMALL, UI_COL_CAPTION);
  initText(LR_TEXT_MATERIAL, UI_FONT_TITLE, UI_COL_WARN);
  initText(LR_TEXT_MAKER,    UI_FONT_TITLE, UI_COL_INK);
  initText(LR_TEXT_COUNT,    UI_FONT_BODY,  UI_COL_CAPTION);
  initText(LR_TEXT_LOCATION, UI_FONT_BODY,  UI_COL_INK_BRIGHT);
  lv_style_set_text_align(&s_st_text[LR_TEXT_LOCATION], LV_TEXT_ALIGN_CENTER);
}

static void initMarks() {
  lv_style_init(&s_st_swatch);
  lv_style_set_radius(&s_st_swatch, UI_RADIUS_SWATCH);
  lv_style_set_border_width(&s_st_swatch, 1);
  lv_style_set_border_color(&s_st_swatch, lv_color_hex(UI_COL_RULE));
  lv_style_set_pad_all(&s_st_swatch, 0);

  lv_style_init(&s_st_hit_frame);
  lv_style_set_border_width(&s_st_hit_frame, LR_HIT_BORDER_W);
  lv_style_set_border_color(&s_st_hit_frame, lv_color_hex(UI_COL_GOOD));
  lv_style_init(&s_st_hit_text);
  lv_style_set_text_color(&s_st_hit_text, lv_color_hex(UI_COL_GOOD));

  lv_style_init(&s_st_current_frame);
  lv_style_set_bg_color(&s_st_current_frame, lv_color_hex(UI_COL_GO_BG));
  lv_style_set_border_color(&s_st_current_frame, lv_color_hex(UI_COL_ACCENT));
  lv_style_init(&s_st_current_text);
  lv_style_set_text_color(&s_st_current_text, lv_color_hex(UI_COL_ACCENT));
}

// Once, on the first row: the palette is chosen at boot and fixed until a
// restart, so the styles never need to follow it.
static void initStyles() {
  if (s_ready) return;
  initFrames();
  initTexts();
  initMarks();
  s_ready = true;
}

lv_obj_t* listRowCreate(lv_obj_t* list, ListRowFrame frame, lv_coord_t w, lv_coord_t h) {
  initStyles();
  lv_obj_t* row = lv_btn_create(list);
  if (!row) return nullptr;
  lv_obj_set_size(row, w, h);
  lv_obj_add_style(row, &s_st_frame[frame], 0);
  lv_obj_add_style(row, &s_st_pressed, LV_STATE_PRESSED);
  return row;
}

lv_obj_t* listRowLabel(lv_obj_t* row, ListRowText kind, const char* text) {
  initStyles();
  lv_obj_t* l = lv_label_create(row);
  lv_label_set_text(l, text);
  lv_obj_add_style(l, &s_st_text[kind], 0);
  return l;
}

lv_obj_t* listRowSwatch(lv_obj_t* row, const char* color_hex) {
  initStyles();
  lv_obj_t* sw = lv_obj_create(row);
  lv_obj_set_size(sw, LR_SWATCH_PX, LR_SWATCH_PX);
  lv_obj_add_style(sw, &s_st_swatch, 0);
  lv_obj_clear_flag(sw, LV_OBJ_FLAG_SCROLLABLE);
  swatchPaintHex(sw, color_hex);
  return sw;
}

void listRowMarkHit(lv_obj_t* row) {
  lv_obj_add_style(row, &s_st_hit_frame, 0);
}

void listRowLabelHit(lv_obj_t* label) {
  lv_obj_add_style(label, &s_st_hit_text, 0);
}

void listRowMarkCurrent(lv_obj_t* row, lv_obj_t* label) {
  lv_obj_add_style(row, &s_st_current_frame, 0);
  if (label) lv_obj_add_style(label, &s_st_current_text, 0);
}
