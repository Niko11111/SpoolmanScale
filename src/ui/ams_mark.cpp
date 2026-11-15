#include "ui/ams_mark.h"

#include "lang.h"
#include "ui/theme.h"

// Inset from the corner, so the badge clears the parent's rounded border.
#define AMS_MARK_INSET   2
#define AMS_MARK_PAD_X   4
#define AMS_MARK_PAD_Y   1
#define AMS_MARK_RADIUS  4

static const char* markGlyph(AmsHotend hotend) {
  if (hotend == AMS_HOTEND_LEFT)  return T(STR_AMSV_HOTEND_L);
  if (hotend == AMS_HOTEND_RIGHT) return T(STR_AMSV_HOTEND_R);
  return LV_SYMBOL_PLAY;
}

lv_obj_t* amsMarkBadge(lv_obj_t* parent, AmsHotend hotend, bool feeding) {
  lv_obj_t* b = lv_label_create(parent);
  if (!b) return nullptr;
  lv_label_set_text(b, markGlyph(hotend));
  lv_obj_set_style_text_font(b, UI_FONT_CAPTION, 0);
  lv_obj_set_style_bg_opa(b, LV_OPA_COVER, 0);
  lv_obj_set_style_radius(b, AMS_MARK_RADIUS, 0);
  lv_obj_set_style_pad_hor(b, AMS_MARK_PAD_X, 0);
  lv_obj_set_style_pad_ver(b, AMS_MARK_PAD_Y, 0);
  lv_obj_set_style_border_width(b, 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(feeding ? UI_COL_ACCENT : UI_COL_SURFACE), 0);
  lv_obj_set_style_text_color(b,
    lv_color_hex(feeding ? UI_COL_ON_ACCENT_DARK : UI_COL_ACCENT), 0);
  lv_obj_align(b, LV_ALIGN_TOP_RIGHT, -AMS_MARK_INSET, AMS_MARK_INSET);
  return b;
}
