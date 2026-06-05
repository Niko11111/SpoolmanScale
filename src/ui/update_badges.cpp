#include "update_badges.h"

#include <lvgl.h>

extern lv_obj_t *lbl_burger_badge;
extern lv_obj_t *lbl_system_badge;
extern lv_obj_t *lbl_fw_badge;
extern lv_obj_t *lbl_gh_btn_badge;

static void setBadgeVisible(lv_obj_t *badge, bool show) {
  if (!badge) return;
  if (show) lv_obj_clear_flag(badge, LV_OBJ_FLAG_HIDDEN);
  else      lv_obj_add_flag(badge, LV_OBJ_FLAG_HIDDEN);
}

void showUpdateBadges(bool show) {
  setBadgeVisible(lbl_burger_badge, show);
  setBadgeVisible(lbl_system_badge, show);
  setBadgeVisible(lbl_fw_badge, show);
  setBadgeVisible(lbl_gh_btn_badge, show);
}
