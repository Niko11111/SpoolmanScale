#include "ui/ams_rack.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#include "ui/icons.h"
#include "ui/theme.h"

// Five bays across the front, the most the width holds at a tile that still
// carries three lines of text.
#define RACK_COLS       5
// The frame's distance from the tiles it surrounds, and its corner.
#define RACK_FRAME_PAD  3
#define RACK_FRAME_R    8
#define RACK_FLAME_PX   16
// Space between the flame and the text under it.
#define RACK_FLAME_GAP  2

static int tileWidth(const AmsRackArea& a) {
  return (a.right - a.left - (RACK_COLS - 1) * a.gap) / RACK_COLS;
}

// A bay's left edge. Odd ids sit at the back, half a bay further right.
static int bayX(const AmsRackArea& a, int tray_id, int tile_w) {
  const int pitch = tile_w + a.gap;
  const bool back = (tray_id % 2) == 1;
  return a.left + (tray_id / 2) * pitch + (back ? pitch / 2 : 0);
}

static int bayY(const AmsRackArea& a, int tray_id) {
  const bool back = (tray_id % 2) == 1;
  return back ? a.top : a.top + a.tile_h + 2 * a.gap;
}

bool amsUnitIsRack(const AmsSlotUnit& unit) {
  return unit.model == AMS_MODEL_AMS_3H && unit.tray_count == AMS_3H_BAYS;
}

// Whole degrees: the space right of the chamber holds no more.
static void formatDegrees(char* out, size_t n, int16_t c10) {
  if (c10 == AMS_TEMP_NA) snprintf(out, n, "-");
  else                    snprintf(out, n, "%d °C", (int)lroundf(c10 / 10.0f));
}

// Resting: the chamber's humidity over its temperature. Drying: the flame,
// the temperature now and the time left, as h:mm.
static void chamberText(const AmsSlotUnit& u, char* out, size_t n) {
  char deg[12];
  formatDegrees(deg, sizeof(deg), u.dryer_temp_c10);
  if (!u.drying) {
    char hum[8] = "-";
    if (u.dryer_humidity != AMS_HUMIDITY_NA) snprintf(hum, sizeof(hum), "%d%%", (int)u.dryer_humidity);
    snprintf(out, n, "%s\n%s", hum, deg);
    return;
  }
  // No chamber reading yet: the target is the next best thing to show.
  if (u.dryer_temp_c10 == AMS_TEMP_NA && u.dry_target_c > 0) {
    snprintf(deg, sizeof(deg), "%d °C", (int)u.dry_target_c);
  }
  if (u.dry_minutes > 0) {
    snprintf(out, n, "%s\n%d:%02d h", deg, u.dry_minutes / 60, u.dry_minutes % 60);
  } else {
    snprintf(out, n, "%s", deg);
  }
}

static void buildFlame(lv_obj_t* body, int x, int y) {
  lv_obj_t* img = lv_img_create(body);
  if (!img) return;
  lv_img_set_src(img, &ICON_FLAME);
  lv_obj_set_style_img_recolor(img, lv_color_hex(UI_COL_WARN), 0);
  lv_obj_set_style_img_recolor_opa(img, LV_OPA_COVER, 0);
  lv_obj_set_pos(img, x, y);
}

// The readings in the space the frame keeps right of the chamber's bays,
// x to x + w, centred on the height of a tile.
static void buildChamberInfo(const AmsRackArea& a, const AmsSlotUnit& u, int x, int w) {
  char txt[32];
  chamberText(u, txt, sizeof(txt));
  const lv_font_t* font = &lv_font_montserrat_ext_12;
  lv_obj_t* l = lv_label_create(a.body);
  if (!l) return;
  lv_label_set_text(l, txt);
  lv_obj_set_width(l, w);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(u.drying ? UI_COL_WARN : UI_COL_CAPTION), 0);
  const int lines   = strchr(txt, '\n') ? 2 : 1;
  const int text_h  = lines * lv_font_get_line_height(font);
  const int block_h = text_h + (u.drying ? RACK_FLAME_PX + RACK_FLAME_GAP : 0);
  const int y0      = a.top + (a.tile_h - block_h) / 2;
  if (u.drying) buildFlame(a.body, x + (w - RACK_FLAME_PX) / 2, y0);
  lv_obj_set_pos(l, x, y0 + block_h - text_h);
}

// The frame from the first chamber bay to the right edge, around the tiles
// and the readings. Drawn before the tiles, so it lies under them.
static void buildChamberFrame(const AmsRackArea& a, const AmsSlotUnit& u, int x0) {
  lv_obj_t* f = lv_obj_create(a.body);
  if (!f) return;
  lv_obj_remove_style_all(f);
  lv_obj_set_pos(f, x0 - RACK_FRAME_PAD, a.top - RACK_FRAME_PAD);
  lv_obj_set_size(f, a.right - x0 + RACK_FRAME_PAD, a.tile_h + 2 * RACK_FRAME_PAD);
  lv_obj_set_style_radius(f, RACK_FRAME_R, 0);
  lv_obj_set_style_border_width(f, u.drying ? 2 : 1, 0);
  lv_obj_set_style_border_color(f, lv_color_hex(u.drying ? UI_COL_WARN : UI_COL_CAPTION), 0);
  lv_obj_clear_flag(f, LV_OBJ_FLAG_CLICKABLE);
}

// The chamber's left edge and the right edge of its last bay, or false when
// the unit reports no chamber in the back row.
static bool chamberSpan(const AmsRackArea& a, const AmsSlotUnit& u, int tile_w,
                        int& x0, int& x1) {
  x0 = -1;
  x1 = 0;
  for (uint8_t t = 0; t < u.tray_count; t++) {
    const uint8_t id = u.tray[t].tray_id;
    if ((id % 2) == 0 || !(u.dryer_mask & (1u << id))) continue;
    const int x = bayX(a, id, tile_w);
    if (x0 < 0 || x < x0) x0 = x;
    if (x + tile_w > x1) x1 = x + tile_w;
  }
  return x0 >= 0;
}

int amsRackBuild(const AmsRackArea& a, const AmsSlotUnit& u, AmsRackTileFn tile,
                 int& tiles) {
  const int tile_w = tileWidth(a);
  int x0 = 0, x1 = 0;
  const bool chamber = chamberSpan(a, u, tile_w, x0, x1);
  if (chamber) buildChamberFrame(a, u, x0);
  for (uint8_t t = 0; t < u.tray_count; t++) {
    const uint8_t id = u.tray[t].tray_id;
    if (!tile(u, u.tray[t], bayX(a, id, tile_w), bayY(a, id), tile_w)) return -1;
    tiles++;
  }
  if (chamber) {
    const int info_x = x1 + RACK_FRAME_PAD;
    buildChamberInfo(a, u, info_x, a.right - info_x - RACK_FRAME_PAD);
  }
  return bayY(a, 0) + a.tile_h - a.top;
}
