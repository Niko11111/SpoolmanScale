#include "update_badges.h"
#include "app/app_state.h"
#include "services/ota_state.h"

#include <lvgl.h>


namespace {
constexpr int BADGE_SIZE   = 18;
constexpr int BADGE_BORDER = 2;
// Amber, not red: red is this UI's colour for something being wrong, and a
// waiting update is a notice. 0xf0b838 is the amber the rest of the project
// already uses rather than a new one invented here.
constexpr uint32_t BADGE_COLOR        = 0xf0b838;
// Drawn in the screen background colour, so the dot keeps a clean rim where it
// overlaps the button underneath.
constexpr uint32_t BADGE_BORDER_COLOR = 0x0a1020;
}  // namespace


static void setBadgeVisible(lv_obj_t *badge, bool show) {
  if (!badge) return;
  if (show) lv_obj_clear_flag(badge, LV_OBJ_FLAG_HIDDEN);
  else      lv_obj_add_flag(badge, LV_OBJ_FLAG_HIDDEN);
}

lv_obj_t* createUpdateBadge(lv_obj_t* parent, lv_obj_t* anchor) {
  if (!parent || !anchor) return nullptr;

  lv_obj_t *badge = lv_obj_create(parent);
  lv_obj_set_size(badge, BADGE_SIZE, BADGE_SIZE);
  lv_obj_set_style_radius(badge, BADGE_SIZE / 2, 0);
  lv_obj_set_style_bg_color(badge, lv_color_hex(BADGE_COLOR), 0);
  lv_obj_set_style_border_color(badge, lv_color_hex(BADGE_BORDER_COLOR), 0);
  lv_obj_set_style_border_width(badge, BADGE_BORDER, 0);
  lv_obj_set_style_pad_all(badge, 0, 0);
  lv_obj_clear_flag(badge, LV_OBJ_FLAG_SCROLLABLE);
  // Without this the dot would swallow taps on the corner of the button it
  // sits on, and that corner is part of the button the user is aiming for.
  lv_obj_clear_flag(badge, LV_OBJ_FLAG_CLICKABLE);

  // Sat on the rounded corner rather than on the sharp one the rectangle would
  // have had. For a corner of radius r the arc's centre is at (right - r,
  // top + r), and the point on that arc at 45 degrees is r - r/sqrt(2), about
  // 0.293 * r, further in. Placing the dot's centre there makes it hug the
  // curve instead of floating off a corner that is not drawn.
  //
  // The radius is read from the anchor, so the four badges - tile, burger and
  // two buttons - each sit correctly without their sizes being repeated here.
  lv_coord_t r = lv_obj_get_style_radius(anchor, LV_PART_MAIN);
  const lv_coord_t w = lv_obj_get_width(anchor);
  const lv_coord_t h = lv_obj_get_height(anchor);
  const lv_coord_t r_max = (w < h ? w : h) / 2;
  if (r > r_max) r = r_max;          // LV_RADIUS_CIRCLE and anything oversized
  if (r < 0)     r = 0;
  const int inset = (r * 293 + 500) / 1000;

  // lv_obj_align_to() resolves across parents, which the burger dot relies on.
  lv_obj_align_to(badge, anchor, LV_ALIGN_TOP_RIGHT,
                  BADGE_SIZE / 2 - inset, -BADGE_SIZE / 2 + inset);

  setBadgeVisible(badge, update_available);
  return badge;
}

void showUpdateBadges(bool show) {
  setBadgeVisible(lbl_burger_badge, show);
  setBadgeVisible(lbl_system_badge, show);
  setBadgeVisible(lbl_fw_badge, show);
  setBadgeVisible(lbl_gh_btn_badge, show);
}
