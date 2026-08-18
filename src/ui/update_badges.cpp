#include "update_badges.h"
#include "app/app_state.h"
#include "services/ota_state.h"

#include <lvgl.h>


namespace {
constexpr int BADGE_SIZE   = 14;
constexpr int BADGE_BORDER = 2;
// Drawn in the screen background colour, so the dot keeps a clean rim where it
// overlaps the button underneath.
constexpr uint32_t BADGE_COLOR        = 0xe03030;
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

  // Centred on the corner: half the dot hangs over the top edge, half over the
  // right one. lv_obj_align_to() resolves across parents, which the burger dot
  // relies on.
  lv_obj_align_to(badge, anchor, LV_ALIGN_TOP_RIGHT,
                  BADGE_SIZE / 2, -BADGE_SIZE / 2);

  setBadgeVisible(badge, update_available);
  return badge;
}

void showUpdateBadges(bool show) {
  setBadgeVisible(lbl_burger_badge, show);
  setBadgeVisible(lbl_system_badge, show);
  setBadgeVisible(lbl_fw_badge, show);
  setBadgeVisible(lbl_gh_btn_badge, show);
}
