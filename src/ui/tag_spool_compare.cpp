#include "ui/tag_spool_compare.h"

#include "app/app_state.h"
#include "app_config.h"
#include "lang.h"
#include "ui/theme.h"
#include "ui/ui_common.h"

// Where the two value columns start, and how far a row sits below the last.
#define TSC_LABEL_X    16
#define TSC_COL_TAG    150
#define TSC_COL_SPOOL  300
#define TSC_VALUE_W    140
#define TSC_ROW_H      24
#define TSC_HEAD_H     20
#define TSC_SWATCH_W   22
#define TSC_SWATCH_H   18

static lv_obj_t* tscLabel(lv_obj_t* box, const char* text, uint32_t color,
                          const lv_font_t* font, int x, int y, int w) {
  lv_obj_t* l = lv_label_create(box);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_color(l, lv_color_hex(color), 0);
  lv_obj_set_style_text_font(l, font, 0);
  if (w > 0) {
    lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
    lv_obj_set_width(l, w);
  }
  lv_obj_set_pos(l, x, y);
  return l;
}

// A value pair on one row, both red when they differ.
static void tscValueRow(lv_obj_t* box, int y, StringID caption, bool differs,
                        const char* tag_value, const char* spool_value) {
  const uint32_t col = differs ? UI_COL_BAD_TEXT : UI_COL_INK_2;
  tscLabel(box, T(caption), UI_COL_CAPTION, UI_FONT_SMALL, TSC_LABEL_X, y, 0);
  tscLabel(box, tag_value[0] ? tag_value : "?", col, UI_FONT_SMALL, TSC_COL_TAG, y, TSC_VALUE_W);
  tscLabel(box, spool_value[0] ? spool_value : "?", col, UI_FONT_SMALL, TSC_COL_SPOOL, y, TSC_VALUE_W - 16);
}

int tagSpoolCompareRows(lv_obj_t* box, int y, const TagSpoolVerdict& v,
                        const char* spool_material, const char* spool_color_hex,
                        const char* spool_vendor) {
  if (!box) return 0;
  const int top = y;

  tscLabel(box, T(STR_REMOTE_LINK_COL_TAG),   UI_COL_CAPTION, UI_FONT_CAPTION, TSC_COL_TAG,   y, 0);
  tscLabel(box, T(STR_REMOTE_LINK_COL_SPOOL), UI_COL_CAPTION, UI_FONT_CAPTION, TSC_COL_SPOOL, y, 0);
  y += TSC_HEAD_H;

  tscValueRow(box, y, STR_REMOTE_LINK_ROW_MATERIAL, v.material,
              g_tag.material, spool_material ? spool_material : "");
  y += TSC_ROW_H;

  // Two swatches say more than two hex strings.
  tscLabel(box, T(STR_REMOTE_LINK_ROW_COLOR), UI_COL_CAPTION, UI_FONT_SMALL, TSC_LABEL_X, y, 0);
  for (int i = 0; i < 2; i++) {
    lv_obj_t* sw = lv_obj_create(box);
    lv_obj_set_size(sw, TSC_SWATCH_W, TSC_SWATCH_H);
    lv_obj_set_pos(sw, i == 0 ? TSC_COL_TAG : TSC_COL_SPOOL, y);
    lv_obj_set_style_radius(sw, UI_RADIUS_INPUT, 0);
    lv_obj_set_style_border_color(sw, lv_color_hex(v.color ? UI_COL_BAD_TEXT : UI_COL_LINE), 0);
    lv_obj_set_style_border_width(sw, 1, 0);
    lv_obj_set_style_pad_all(sw, 0, 0);
    lv_obj_clear_flag(sw, LV_OBJ_FLAG_SCROLLABLE);
    if (i == 0) swatchPaint(sw, g_tag.color);
    else        swatchPaintHex(sw, spool_color_hex ? spool_color_hex : "");
  }
  y += TSC_ROW_H;

  // Only when it is what differs: every Bambu spool shares the maker, so the
  // row would otherwise say the same thing twice on every warning.
  if (v.vendor) {
    tscValueRow(box, y, STR_LBL_VENDOR, true, BAMBU_VENDOR_NAME,
                spool_vendor ? spool_vendor : "");
    y += TSC_ROW_H;
  }
  return y - top;
}
