#include "tag_display.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>

#include "bambu/bambu_tag.h"
#include "lang.h"
#include "main_screen_helpers.h"
#include "spool_flow.h"
#include "theme.h"


// ============================================================
//  CLEAR DISPLAY (no tag detected)
// ============================================================
void clearTagDisplay() {
  lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
  lv_obj_set_style_text_color(lbl_nfc_dot, tc(TH_WARNING), 0);  // yellow = kein Tag
  lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
  lv_obj_set_style_text_color(lbl_status, tc(TH_WARNING), 0);
  lv_label_set_text(lbl_uid, "-");
  lv_label_set_text(lbl_tray_uuid, "-");
  lv_label_set_text(lbl_material, "-");
  lv_label_set_text(lbl_date, "-");
  lv_label_set_text(lbl_spoolman_id, "?");
  lv_obj_set_style_text_color(lbl_spoolman_id, tc(TH_WARNING), 0);
  lv_label_set_text(lbl_color, "-");
  lv_label_set_text(lbl_temp, "-");
  lv_label_set_text(lbl_vendor, "-");
  lv_label_set_text(lbl_detail, "-");
  lv_label_set_text(lbl_filament_name, "");
  lv_label_set_text(lbl_last_used, "-");
  lv_label_set_text(lbl_spoolman_weight, "---");
  lv_label_set_text(lbl_spoolman_pct, "");
  lv_label_set_text(lbl_spoolman_dried_val, "-");
  lv_label_set_text(lbl_scale_weight, "---");
  // Reset progress bar fill width to 0
  if (lbl_scale_diff) lv_obj_set_width(lbl_scale_diff, 0);
  if (lbl_spoolman_dried) lv_label_set_text(lbl_spoolman_dried, "");
  if (lbl_keys) lv_label_set_text(lbl_keys, "");
  if (lbl_raw_info) lv_label_set_text(lbl_raw_info, "");
  if (lbl_bag_sm_diff) lv_label_set_text(lbl_bag_sm_diff, "");
  lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(0x333333), 0);
  // Also reset Spoolman data
  sm_found = false; sm_id = 0; sm_filament_id = 0; sm_vendor_id = 0; sm_spool_weight = 0;
  sm_last_dried[0] = '\0'; sm_article_nr[0] = '\0';
  sm_filament_name[0] = '\0'; sm_material_global[0] = '\0'; sm_color_global[0] = '\0'; sm_last_used[0] = '\0';
  sm_location_name[0] = '\0';
  tag_present = false;
  nfc_retry_count = 0; nfc_absent_count = 0; nfc_fast_polls = 0;
  g_tag.uid_str[0] = '\0';
  g_tag.tray_uuid[0] = '\0';
  g_tag.material[0] = '\0';   // CRITICAL: otherwise is_ntag=false remains after Bambu scan
  g_tag.color_hex[0] = '\0';
  g_tag.vendor[0] = '\0';
  spoolman_queried_uid[0] = '\0';
  link_tag_uid[0] = '\0';   // Also clear link UID
  link_popup_dismissed = false;
  link_tag_first_seen_ms = 0;
  g_tag_displayed = false;
  updateLinkButton();
  Serial.println("Display cleared (no tag)");
}
