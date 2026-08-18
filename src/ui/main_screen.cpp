#include "main_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "services/backend.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstdio>
#include <cstring>

#include "app_config.h"
#include "bambu/bambu_tag.h"
#include "hardware/scale.h"
#include "hardware/scale_state.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/auto_weight_state.h"
#include "services/user_options.h"
#include "ui/confirm_popup.h"
#include "ui/dried_action.h"
#include "ui/update_badges.h"
#include "ui/header_status.h"
#include "ui/more_info_screen.h"
#include "ui/settings_screen.h"
#include "ui/spool_flow.h"
#include "ui_common.h"

// ============================================================
//  FILL DISPLAY WITH TAG DATA
// ============================================================
void updateDisplay() {
  scan_count++;
  updateHeaderStatus();

  // Status bar: green dot + tag found
  lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
  lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0x28d49a), 0);
  lv_label_set_text(lbl_status, T(STR_TAG_FOUND));
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);

  // Material (Zone 3 Row A)
  lv_label_set_text(lbl_material,
    strlen(g_tag.material) > 0 ? g_tag.material : T(STR_UNKNOWN));

  // SM-ID: shown as "?" until querySpoolman fills it
  lv_label_set_text(lbl_spoolman_id, "?");
  lv_obj_set_style_text_color(lbl_spoolman_id, lv_color_hex(0xf0b838), 0);

  // Filament name: cleared until Spoolman responds
  lv_label_set_text(lbl_filament_name, "");

  // Color swatch + hex text
  lv_label_set_text(lbl_color,
    strlen(g_tag.color_hex) > 1 ? g_tag.color_hex : "-");
  if (strlen(g_tag.color_hex) == 7) {
    lv_obj_set_style_bg_color(lbl_color_swatch, swatchColorFromHex(g_tag.color_hex), 0);
  }

  // Temp (Zone 3 Row B)
  char temp_str[24];
  if (g_tag.temp_min > 0 && g_tag.temp_max > 0) {
    snprintf(temp_str, sizeof(temp_str), "%d - %d C", g_tag.temp_min, g_tag.temp_max);
  } else {
    strncpy(temp_str, T(STR_UNKNOWN), sizeof(temp_str)-1);
  }
  lv_label_set_text(lbl_temp, temp_str);

  // Vendor (Zone 3 Row B)
  lv_label_set_text(lbl_vendor,
    strlen(g_tag.vendor) > 0 ? g_tag.vendor : "Bambu Lab");

  // Hidden labels still written for More Info screen compatibility
  lv_label_set_text(lbl_uid, g_tag.uid_str);
  lv_label_set_text(lbl_tray_uuid,
    strlen(g_tag.tray_uuid) == 32 ? g_tag.tray_uuid : T(STR_NOT_READABLE));
  lv_label_set_text(lbl_date,
    strlen(g_tag.production_date) > 4 ? g_tag.production_date : T(STR_UNKNOWN));
  lv_label_set_text(lbl_detail, sm_article_nr[0] ? sm_article_nr : "-");

  // (lbl_raw_info is now used for SM diff display, updated in loop)
}

//  Zone 1: Header      y=0..25   (26px)  Name/Version | WiFi NFC
//  Zone 2: Status      y=26..47  (22px)  dot + status text | #scans
//  Zone 3: Spool Info  y=48..183 (136px) full width: swatch/id/mat/name | vendor/temp | dates/more
//  Zone 4: Weights     y=184..263 (80px) Spoolman(+bar) | Scale(+diff) | TARE btn
//  Zone 5: Buttons     y=264..319 (56px) [Update Weight] [Dried today] [Settings]
// ============================================================
void buildUI() {
  lv_obj_set_style_bg_color(lv_scr_act(), lv_color_hex(0x0a1020), 0);

  // ── ZONE 1: Header y=0..25 (26px) ───────────────────────
  // Name+Version left | WiFi NFC right — scan counter moved to status bar
  lv_obj_t *hdr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(hdr, 480, 26);
  lv_obj_set_pos(hdr, 0, 0);
  lv_obj_set_style_bg_color(hdr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_set_style_pad_all(hdr, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *hdr_lbl = lv_label_create(hdr);
  lv_label_set_text(hdr_lbl, "SpoolmanScale " FW_VERSION);
  lv_obj_set_style_text_color(hdr_lbl, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(hdr_lbl, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(hdr_lbl, LV_ALIGN_LEFT_MID, 6, 0);

  // SD card indicator in header — only visible when sd_available
  lv_obj_t *lbl_sd_hdr = lv_label_create(hdr);
  lv_label_set_text(lbl_sd_hdr, LV_SYMBOL_SD_CARD);
  lv_obj_set_style_text_color(lbl_sd_hdr, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_sd_hdr, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_sd_hdr, LV_ALIGN_RIGHT_MID, -120, 0);
  if (!sd_available) lv_obj_add_flag(lbl_sd_hdr, LV_OBJ_FLAG_HIDDEN);

  lbl_hdr_wifi = lv_label_create(hdr);
  lv_label_set_text(lbl_hdr_wifi, LV_SYMBOL_WIFI);
  lv_obj_set_style_text_color(lbl_hdr_wifi, lv_color_hex(0x606060), 0);
  lv_obj_set_style_text_font(lbl_hdr_wifi, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_hdr_wifi, LV_ALIGN_RIGHT_MID, -100, 0);

  lbl_hdr_nfc = lv_label_create(hdr);
  lv_label_set_text(lbl_hdr_nfc, "NFC");
  lv_obj_set_style_text_color(lbl_hdr_nfc, lv_color_hex(0x606060), 0);
  lv_obj_set_style_text_font(lbl_hdr_nfc, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_hdr_nfc, LV_ALIGN_RIGHT_MID, -68, 0);

  lbl_hdr_scl = lv_label_create(hdr);
  lv_label_set_text(lbl_hdr_scl, "SCL");
  lv_obj_set_style_text_color(lbl_hdr_scl, lv_color_hex(0x606060), 0);
  lv_obj_set_style_text_font(lbl_hdr_scl, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_hdr_scl, LV_ALIGN_RIGHT_MID, -36, 0);

  // Fix 10: Spoolman reachability indicator
  lbl_hdr_sm = lv_label_create(hdr);
  lv_label_set_text(lbl_hdr_sm, backendIsFilaMan() ? "FLM" : "SPM");
  lv_obj_set_style_text_color(lbl_hdr_sm, lv_color_hex(0x606060), 0);
  lv_obj_set_style_text_font(lbl_hdr_sm, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_hdr_sm, LV_ALIGN_RIGHT_MID, -4, 0);

  // ── ZONE 2: Status bar y=26..47 (22px) ──────────────────
  // dot + status text centered | #scan_count right
  // Fix 9: status bar same color as background — no odd contrast stripe
  lv_obj_t *status_bar = lv_obj_create(lv_scr_act());
  lv_obj_set_size(status_bar, 480, 22);
  lv_obj_set_pos(status_bar, 0, 26);
  lv_obj_set_style_bg_color(status_bar, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(status_bar, 0, 0);
  lv_obj_set_style_radius(status_bar, 0, 0);
  lv_obj_set_style_pad_all(status_bar, 0, 0);
  lv_obj_clear_flag(status_bar, LV_OBJ_FLAG_SCROLLABLE);

  lbl_nfc_dot = lv_label_create(status_bar);
  lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
  lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_nfc_dot, &lv_font_montserrat_ext_14, 0);
  lv_obj_align(lbl_nfc_dot, LV_ALIGN_LEFT_MID, 6, 0);

  lbl_status = lv_label_create(status_bar);
  lv_label_set_text(lbl_status, T(STR_BOOTING));
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x5090e0), 0);
  lv_obj_set_style_text_font(lbl_status, &lv_font_montserrat_ext_14, 0);
  lv_obj_align(lbl_status, LV_ALIGN_LEFT_MID, 22, 0);
  // Bounded so a longer translation can never run into the address on the
  // right. Today's longest status ends well clear of it, but that is not
  // something to leave to chance.
  lv_label_set_long_mode(lbl_status, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_status, 320);

  // Optional address, left of the scan counter. Filled by updateHeaderStatus()
  // according to g_ip_bar_mode, hidden while the mode is off.
  lbl_hdr_ip = lv_label_create(status_bar);
  lv_label_set_text(lbl_hdr_ip, "");
  lv_obj_set_style_text_color(lbl_hdr_ip, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_hdr_ip, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_hdr_ip, LV_ALIGN_RIGHT_MID, -44, 0);
  lv_obj_add_flag(lbl_hdr_ip, LV_OBJ_FLAG_HIDDEN);

  // Scan counter: right side of status bar
  lbl_hdr_scans = lv_label_create(status_bar);
  lv_label_set_text(lbl_hdr_scans, "#0");
  lv_obj_set_style_text_color(lbl_hdr_scans, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_hdr_scans, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_hdr_scans, LV_ALIGN_RIGHT_MID, -6, 0);

  lbl_scan_count = lbl_hdr_scans;

  // Thin separator line
  lv_obj_t *sep1 = lv_obj_create(lv_scr_act());
  lv_obj_set_size(sep1, 480, 1);
  lv_obj_set_pos(sep1, 0, 48);
  lv_obj_set_style_bg_color(sep1, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(sep1, 0, 0);
  lv_obj_set_style_radius(sep1, 0, 0);
  lv_obj_set_style_pad_all(sep1, 0, 0);

  // ── ZONE 3: Spool Info y=49..184 (136px) full width ─────
  // Row A: [swatch] [#ID] [Material] [FilamentName]
  // Row B: Vendor / Temp + More info btn top-right
  // separator
  // Row C: Last used / Last dried

  // Swatch (42x42, y=63)
  lbl_color_swatch = lv_obj_create(lv_scr_act());
  lv_obj_set_size(lbl_color_swatch, 42, 42);
  lv_obj_set_pos(lbl_color_swatch, 8, 54);
  lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(0x333333), 0);
  lv_obj_set_style_radius(lbl_color_swatch, 6, 0);
  lv_obj_set_style_border_color(lbl_color_swatch, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_border_width(lbl_color_swatch, 1, 0);
  lv_obj_set_style_pad_all(lbl_color_swatch, 0, 0);
  lv_obj_clear_flag(lbl_color_swatch, LV_OBJ_FLAG_SCROLLABLE);

  // Cap: ID (x=58, y=51)
  lv_obj_t *lbl_id_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_id_cap, "ID");
  lv_obj_set_style_text_color(lbl_id_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_id_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_id_cap, 58, 51);

  // SM-ID value (x=58, y=65)
  lbl_spoolman_id = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_id, "?");
  lv_obj_set_style_text_color(lbl_spoolman_id, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_spoolman_id, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_spoolman_id, 58, 65);

  // Cap: Material (x=92, y=51)
  lv_obj_t *lbl_mat_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_mat_cap, "Material");
  lv_obj_set_style_text_color(lbl_mat_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_mat_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_mat_cap, 92, 51);

  // Material value (x=92, y=65)
  lbl_material = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_material, "-");
  lv_obj_set_style_text_color(lbl_material, lv_color_hex(0xf0f0f0), 0);
  lv_obj_set_style_text_font(lbl_material, &lv_font_montserrat_ext_20, 0);
  lv_obj_set_pos(lbl_material, 92, 63);
  lv_label_set_long_mode(lbl_material, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_material, 160);

  // Cap: Filament (x=260, y=51)
  lv_obj_t *lbl_fil_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_fil_cap, "Filament");
  lv_obj_set_style_text_color(lbl_fil_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_fil_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_fil_cap, 232, 51);  // Fix 5: slightly left

  // Filament Name value (x=260, y=65)
  lbl_filament_name = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_filament_name, "-");
  lv_obj_set_style_text_color(lbl_filament_name, lv_color_hex(0xf0f0f0), 0);  // Fix 8: same as material
  lv_obj_set_style_text_font(lbl_filament_name, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_filament_name, 232, 66);  // Fix 5: slightly left
  lv_label_set_long_mode(lbl_filament_name, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_filament_name, 212);

  // Hex color: hidden dummy (only shown in More Info screen)
  lbl_color = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_color, "");
  lv_obj_add_flag(lbl_color, LV_OBJ_FLAG_HIDDEN);

  // Row B: Vendor (x=8, y=98) | Temp (x=210, y=98) | More info btn TOP RIGHT bigger
  lv_obj_t *lbl_vendor_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_vendor_cap, T(STR_LBL_VENDOR));
  lv_obj_set_style_text_color(lbl_vendor_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_vendor_cap, &lv_font_montserrat_ext_14, 0);  // Fix 5: +1 size
  lv_obj_set_pos(lbl_vendor_cap, 8, 98);

  lbl_vendor = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_vendor, "-");
  lv_obj_set_style_text_color(lbl_vendor, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_vendor, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_vendor, 8, 115);  // Fix 5: +2px gap
  lv_label_set_long_mode(lbl_vendor, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_vendor, 190);

  lv_obj_t *lbl_temp_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_temp_cap, T(STR_LBL_TEMP));
  lv_obj_set_style_text_color(lbl_temp_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_temp_cap, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(lbl_temp_cap, 248, 98);  // Fix 5: more right

  lbl_temp = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_temp, "-");
  lv_obj_set_style_text_color(lbl_temp, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_temp, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_temp, 248, 115);  // Fix 5: more right

  // "More info" button — Fix 4: more prominent, teal border
  lv_obj_t *btn_more = lv_btn_create(lv_scr_act());
  lv_obj_set_size(btn_more, 84, 34);
  lv_obj_set_pos(btn_more, 388, 100);
  lv_obj_set_style_bg_color(btn_more, lv_color_hex(0x0d1f38), 0);
  lv_obj_set_style_bg_color(btn_more, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_more, 1, 0);
  lv_obj_set_style_border_color(btn_more, lv_color_hex(0x28d49a), 0);  // teal border
  lv_obj_set_style_radius(btn_more, 6, 0);
  lv_obj_set_style_shadow_width(btn_more, 0, 0);
  lv_obj_add_event_cb(btn_more, [](lv_event_t *e){ logSD("BTN: Main -> MoreInfo"); showMoreInfoScreen(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_more = lv_label_create(btn_more);
  char more_buf[24]; strncpy(more_buf, T(STR_BTN_MORE_INFO), sizeof(more_buf)-1);
  more_buf[sizeof(more_buf)-1] = '\0';
  lv_label_set_text(lbl_more, more_buf);
  lv_obj_set_style_text_color(lbl_more, lv_color_hex(0x28d49a), 0);  // teal text
  lv_obj_set_style_text_font(lbl_more, &lv_font_montserrat_ext_12, 0);
  lv_obj_center(lbl_more);

  // Inner separator y=136 — Fix 2: slightly lower to give More info btn breathing room
  lv_obj_t *sep_inner = lv_obj_create(lv_scr_act());
  lv_obj_set_size(sep_inner, 464, 1);
  lv_obj_set_pos(sep_inner, 8, 138);
  lv_obj_set_style_bg_color(sep_inner, lv_color_hex(0x0f1e30), 0);
  lv_obj_set_style_border_width(sep_inner, 0, 0);
  lv_obj_set_style_radius(sep_inner, 0, 0);
  lv_obj_set_style_pad_all(sep_inner, 0, 0);

  // Row C: Last used / Last dried — Fix 3: date values lower (y=158 instead of y=152)
  lbl_lu_cap = lv_label_create(lv_scr_act());
  // Cap text depends on last_used_mode
  char lu_cap_buf[32];
  // The weighed variant reuses the option label, which carries no colon
  if (last_used_mode == 1)
    snprintf(lu_cap_buf, sizeof(lu_cap_buf), "%s:", T(STR_LASTUSED_OPT_WEIGHED));
  else
    strncpy(lu_cap_buf, T(STR_LBL_LAST_USED), sizeof(lu_cap_buf)-1);
  lu_cap_buf[sizeof(lu_cap_buf)-1] = '\0';
  lv_label_set_text(lbl_lu_cap, lu_cap_buf);
  lv_obj_set_style_text_color(lbl_lu_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_lu_cap, &lv_font_montserrat_ext_14, 0);  // Fix 5
  lv_obj_set_pos(lbl_lu_cap, 8, 142);

  lbl_last_used = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_last_used, "-");
  lv_obj_set_style_text_color(lbl_last_used, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(lbl_last_used, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_last_used, 8, 158);  // Fix 3: more gap
  lv_label_set_long_mode(lbl_last_used, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_last_used, 228);

  lv_obj_t *lbl_ld_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_ld_cap, T(STR_LBL_LAST_DRIED));
  lv_obj_set_style_text_color(lbl_ld_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_ld_cap, &lv_font_montserrat_ext_14, 0);  // Fix 5
  lv_obj_set_pos(lbl_ld_cap, 244, 142);

  lbl_spoolman_dried_val = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_dried_val, "-");
  lv_obj_set_style_text_color(lbl_spoolman_dried_val, lv_color_hex(0x5090e0), 0);
  lv_obj_set_style_text_font(lbl_spoolman_dried_val, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_spoolman_dried_val, 244, 158);  // Fix 3
  lv_label_set_long_mode(lbl_spoolman_dried_val, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_spoolman_dried_val, 210);
  lbl_spoolman_dried = lbl_spoolman_dried_val;
  // Ampel-Symbol (WARNING) rechts vom Datum, standardmaessig versteckt
  lbl_dried_sym = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_dried_sym, LV_SYMBOL_WARNING);
  lv_obj_set_style_text_color(lbl_dried_sym, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_dried_sym, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_dried_sym, 456, 158);
  lv_obj_add_flag(lbl_dried_sym, LV_OBJ_FLAG_HIDDEN);

  // Unused labels still needed by updateDisplay / querySpoolman
  // lbl_uid, lbl_tray_uuid, lbl_detail, lbl_date — hidden dummy labels
  lbl_uid = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_uid, "");
  lv_obj_add_flag(lbl_uid, LV_OBJ_FLAG_HIDDEN);

  lbl_tray_uuid = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_tray_uuid, "");
  lv_obj_add_flag(lbl_tray_uuid, LV_OBJ_FLAG_HIDDEN);

  lbl_detail = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_detail, "");
  lv_obj_add_flag(lbl_detail, LV_OBJ_FLAG_HIDDEN);

  lbl_date = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_date, "");
  lv_obj_add_flag(lbl_date, LV_OBJ_FLAG_HIDDEN);

  // Separator zone 3/4
  lv_obj_t *sep2 = lv_obj_create(lv_scr_act());
  lv_obj_set_size(sep2, 480, 1);
  lv_obj_set_pos(sep2, 0, 184);
  lv_obj_set_style_bg_color(sep2, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(sep2, 0, 0);
  lv_obj_set_style_radius(sep2, 0, 0);
  lv_obj_set_style_pad_all(sep2, 0, 0);

  // ── ZONE 4: Weights y=185..263 (79px) ───────────────────
  // Left  (x=0..209):  Spoolman filament remaining (big) + % + bar
  // Right (x=210..424): Scale filament netto (big) + SM diff | live total | live -bag
  // Far right (x=425..479): TARE

  // Backend section — caption. Kept in a global so the text can follow a
  // backend switch without rebuilding the main screen. The product names are
  // not translated, and STR_LBL_SPOOLMAN is identical in both languages.
  lbl_sm_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_sm_cap, backendIsFilaMan() ? "FilaMan:" : "Spoolman:");
  lv_obj_set_style_text_color(lbl_sm_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_sm_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_sm_cap, 8, 188);

  // Spoolman filament remaining — BIG
  lbl_spoolman_weight = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_weight, wifi_ok ? "..." : T(STR_NO_WIFI));
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_spoolman_weight, &lv_font_montserrat_ext_20, 0);
  lv_obj_set_pos(lbl_spoolman_weight, 8, 204);

  // Percent — Fix 3: right of weight, same row
  lbl_spoolman_pct = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_pct, "");
  lv_obj_set_style_text_color(lbl_spoolman_pct, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_spoolman_pct, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(lbl_spoolman_pct, 88, 208);  // right of weight, vertically centered

  // Progress bar — Fix 3: higher (y=230) and thicker (6px)
  lv_obj_t *bar_bg = lv_obj_create(lv_scr_act());
  lv_obj_set_size(bar_bg, 190, 8);
  lv_obj_set_pos(bar_bg, 8, 244);
  lv_obj_set_style_bg_color(bar_bg, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_border_width(bar_bg, 0, 0);
  lv_obj_set_style_radius(bar_bg, 4, 0);
  lv_obj_set_style_pad_all(bar_bg, 0, 0);
  lv_obj_clear_flag(bar_bg, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *bar_fill = lv_obj_create(bar_bg);
  lv_obj_set_size(bar_fill, 0, 8);
  lv_obj_set_pos(bar_fill, 0, 0);
  lv_obj_set_style_bg_color(bar_fill, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(bar_fill, 0, 0);
  lv_obj_set_style_radius(bar_fill, 4, 0);
  lv_obj_set_style_pad_all(bar_fill, 0, 0);
  lv_obj_clear_flag(bar_fill, LV_OBJ_FLAG_SCROLLABLE);
  lbl_scale_diff = (lv_obj_t*)bar_fill;

  // Vertical divider left/mid
  lv_obj_t *vdiv1 = lv_obj_create(lv_scr_act());
  lv_obj_set_size(vdiv1, 1, 76);
  lv_obj_set_pos(vdiv1, 210, 186);
  lv_obj_set_style_bg_color(vdiv1, lv_color_hex(0x0f1e30), 0);
  lv_obj_set_style_border_width(vdiv1, 0, 0);
  lv_obj_set_style_radius(vdiv1, 0, 0);
  lv_obj_set_style_pad_all(vdiv1, 0, 0);

  // Scale filament netto caption — Fix 3: "Waage - Spule" / "Scale - Spool"
  lv_obj_t *lbl_sc_cap = lv_label_create(lv_scr_act());
  char sc_cap_buf[24]; strncpy(sc_cap_buf, T(STR_LBL_SCALE_SPOOL_CAP), sizeof(sc_cap_buf)-1);
  sc_cap_buf[sizeof(sc_cap_buf)-1] = '\0';
  lv_label_set_text(lbl_sc_cap, sc_cap_buf);
  lv_obj_set_style_text_color(lbl_sc_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_sc_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_sc_cap, 218, 188);

  // Scale filament netto — BIG
  lbl_scale_weight = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_scale_weight, scale_ready ? "0 g" : "---");
  lv_obj_set_style_text_color(lbl_scale_weight, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_scale_weight, &lv_font_montserrat_ext_20, 0);
  lv_obj_set_pos(lbl_scale_weight, 218, 204);

  // SM diff caption + value — both diffs stacked on right side (Fix 3)
  lv_obj_t *lbl_diff_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_diff_cap, "Diff:");
  lv_obj_set_style_text_color(lbl_diff_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_diff_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_diff_cap, 362, 188);

  lbl_raw_info = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_raw_info, "");
  lv_obj_set_style_text_color(lbl_raw_info, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_raw_info, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_raw_info, 362, 204);  // Fix 3: right column

  // Fix 1: "Gesamt" / "Total" — Fix 4: value x same as o.Beutel value
  lv_obj_t *lbl_live_cap = lv_label_create(lv_scr_act());
  char live_cap_buf[16]; strncpy(live_cap_buf, T(STR_LBL_TOTAL_CAP), sizeof(live_cap_buf)-1);
  live_cap_buf[sizeof(live_cap_buf)-1] = '\0';
  lv_label_set_text(lbl_live_cap, live_cap_buf);
  lv_obj_set_style_text_color(lbl_live_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_live_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_live_cap, 218, 228);

  lbl_spoolman_dried = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_dried, "");
  lv_obj_set_style_text_color(lbl_spoolman_dried, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(lbl_spoolman_dried, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(lbl_spoolman_dried, 286, 226);  // Fix 4: same x as o.Beutel value

  // Fix 2: "o. Beutel" / "w/o Bag"
  lv_obj_t *lbl_bag_cap = lv_label_create(lv_scr_act());
  char bag_cap_buf[16]; strncpy(bag_cap_buf, T(STR_LBL_WO_BAG_CAP), sizeof(bag_cap_buf)-1);
  bag_cap_buf[sizeof(bag_cap_buf)-1] = '\0';
  lv_label_set_text(lbl_bag_cap, bag_cap_buf);
  lv_obj_set_style_text_color(lbl_bag_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_bag_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_bag_cap, 218, 246);

  lv_obj_t *lbl_bag_diff = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_bag_diff, "");
  lv_obj_set_style_text_color(lbl_bag_diff, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_bag_diff, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(lbl_bag_diff, 286, 244);
  lbl_keys = lbl_bag_diff;

  // Fix 3+4: bag SM diff — stacked below Waage-Spule diff, with "g"
  lbl_bag_sm_diff = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_bag_sm_diff, "");
  lv_obj_set_style_text_color(lbl_bag_sm_diff, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_bag_sm_diff, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_bag_sm_diff, 362, 244);  // same x as Waage-Spule diff, below

  // Vertical divider zone 4 mid/right — Fix 7: moved left for TARE breathing room
  lv_obj_t *vdiv2 = lv_obj_create(lv_scr_act());
  lv_obj_set_size(vdiv2, 0, 0);
  lv_obj_set_pos(vdiv2, 418, 186);
  lv_obj_set_style_bg_color(vdiv2, lv_color_hex(0x0f1e30), 0);
  lv_obj_set_style_border_width(vdiv2, 0, 0);
  lv_obj_set_style_radius(vdiv2, 0, 0);
  lv_obj_set_style_pad_all(vdiv2, 0, 0);

  // TARE button — Fix 1: 50px width (same as menu btn), divider gives left breathing room
  lv_obj_t *btn_tare = lv_btn_create(lv_scr_act());
  lv_obj_set_size(btn_tare, 54, 70);
  lv_obj_set_pos(btn_tare, 422, 188);
  lv_obj_set_style_bg_color(btn_tare, lv_color_hex(0x2a2010), 0);
  lv_obj_set_style_bg_color(btn_tare, lv_color_hex(0x4a4020), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_tare, 1, 0);
  lv_obj_set_style_border_color(btn_tare, lv_color_hex(0x3a3010), 0);
  lv_obj_set_style_radius(btn_tare, 8, 0);
  lv_obj_set_style_shadow_width(btn_tare, 0, 0);
  lv_obj_add_event_cb(btn_tare, [](lv_event_t *e) {
    logSD("UI: Button -> TARE (main)");
    if (scale_ready) {
      int32_t raw = scaleHardwareReadRaw();
      saveTareOffset(raw);
      scale_weight_g = 0.0f;
      resetScaleFilter();
      lv_label_set_text(lbl_scale_weight, "0 g");
      Serial.println("TARE (main)");
      logSDf("TARE applied (raw=%d)", raw);
    } else {
      logSD("TARE: scale not ready");
    }
  }, LV_EVENT_CLICKED, NULL);
  // Icon top, text bottom — both centered
  lv_obj_t *lbl_tare_icon = lv_label_create(btn_tare);
  lv_label_set_text(lbl_tare_icon, LV_SYMBOL_REFRESH);
  lv_obj_set_style_text_color(lbl_tare_icon, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_tare_icon, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_tare_icon, LV_ALIGN_CENTER, 0, -10);
  lv_obj_t *lbl_tare_txt = lv_label_create(btn_tare);
  lv_label_set_text(lbl_tare_txt, "TARE");
  lv_obj_set_style_text_color(lbl_tare_txt, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_tare_txt, &lv_font_montserrat_ext_10, 0);
  lv_obj_align(lbl_tare_txt, LV_ALIGN_CENTER, 0, 12);

  // Separator zone 4/5
  lv_obj_t *sep3 = lv_obj_create(lv_scr_act());
  lv_obj_set_size(sep3, 480, 1);
  lv_obj_set_pos(sep3, 0, 264);
  lv_obj_set_style_bg_color(sep3, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(sep3, 0, 0);
  lv_obj_set_style_radius(sep3, 0, 0);
  lv_obj_set_style_pad_all(sep3, 0, 0);

  // ── ZONE 5: Button bar y=265..319 (55px) ────────────────
  // [Update Weight flex:1] [Dried today flex:1] [Settings 44px]
  // When no link: both replaced by [Link spool flex:1] [Settings 44px]
  lv_obj_t *btn_bar = lv_obj_create(lv_scr_act());
  lv_obj_set_size(btn_bar, 480, 55);
  lv_obj_set_pos(btn_bar, 0, 265);
  lv_obj_set_style_bg_color(btn_bar, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(btn_bar, 0, 0);
  lv_obj_set_style_radius(btn_bar, 0, 0);
  lv_obj_set_style_pad_all(btn_bar, 0, 0);
  lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);

  // "Update Weight" button (x=6, w=204)
  btn_weight_main = lv_btn_create(btn_bar);
  lv_obj_set_size(btn_weight_main, 204, 40);
  lv_obj_set_pos(btn_weight_main, 6, 8);
  lv_obj_set_style_bg_color(btn_weight_main, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_weight_main, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_weight_main, 1, 0);
  lv_obj_set_style_border_color(btn_weight_main, lv_color_hex(0x2a5030), 0);
  lv_obj_set_style_radius(btn_weight_main, 8, 0);
  lv_obj_set_style_shadow_width(btn_weight_main, 0, 0);
  lv_obj_add_event_cb(btn_weight_main, [](lv_event_t *e) {
    logSD("UI: Button -> Update Weight");
    { char qb[64]; backendText(T(STR_POPUP_WEIGHT_Q), qb, sizeof(qb)); showConfirmPopup(qb, 2); }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_wm = lv_label_create(btn_weight_main);
  lbl_weight_main_lbl = lbl_wm;
  {
    char wmbuf[48];
    if (g_auto_weight)
      snprintf(wmbuf, sizeof(wmbuf), "%s (A)", T(STR_BTN_WEIGHT));
    else {
      strncpy(wmbuf, T(STR_BTN_WEIGHT), sizeof(wmbuf)-1);
      wmbuf[sizeof(wmbuf)-1] = '\0';
    }
    lv_label_set_text(lbl_wm, wmbuf);
  }
  lv_obj_set_style_text_color(lbl_wm, g_auto_weight ? lv_color_hex(0x28d49a) : lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_wm, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_wm, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_wm, LV_ALIGN_CENTER, 0, 0);

  // "Dried today" button (x=216, w=204)
  btn_dried = lv_btn_create(btn_bar);
  lv_obj_set_size(btn_dried, 204, 40);
  lv_obj_set_pos(btn_dried, 216, 8);
  lv_obj_set_style_bg_color(btn_dried, lv_color_hex(0x0a2040), 0);
  lv_obj_set_style_bg_color(btn_dried, lv_color_hex(0x1a4080), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_dried, 1, 0);
  lv_obj_set_style_border_color(btn_dried, lv_color_hex(0x1a4080), 0);
  lv_obj_set_style_radius(btn_dried, 8, 0);
  lv_obj_set_style_shadow_width(btn_dried, 0, 0);
  lv_obj_add_event_cb(btn_dried, [](lv_event_t *e) {
    logSD("UI: Button -> Dried (popup)");
    if (!sm_found || sm_id == 0) { btn_dried_cb(nullptr); return; }
    showConfirmPopup(T(STR_POPUP_DRIED_Q), 1);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_dr = lv_label_create(btn_dried);
  lv_label_set_text(lbl_dr, T(STR_BTN_DRIED));
  lv_obj_set_style_text_color(lbl_dr, lv_color_hex(0x5090e0), 0);
  lv_obj_set_style_text_font(lbl_dr, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_dr, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_dr, LV_ALIGN_CENTER, 0, 0);

  // "Link spool" button — same slot, initially hidden
  // Link button — 204px, olive-green, matches Update Weight style
  // ID= >100 spools recommended | List= <100 spools recommended
  btn_link = lv_btn_create(btn_bar);
  lv_obj_set_size(btn_link, 204, 40);
  lv_obj_set_pos(btn_link, 6, 8);
  lv_obj_set_style_bg_color(btn_link, lv_color_hex(0x1e3000), 0);
  lv_obj_set_style_bg_color(btn_link, lv_color_hex(0x2e5000), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_link, 1, 0);
  lv_obj_set_style_border_color(btn_link, lv_color_hex(0x4a7800), 0);
  lv_obj_set_style_radius(btn_link, 8, 0);
  lv_obj_set_style_shadow_width(btn_link, 0, 0);
  lv_obj_add_flag(btn_link, LV_OBJ_FLAG_HIDDEN);
  lv_obj_add_event_cb(btn_link, [](lv_event_t *e) {
    logSD("UI: Button -> Link Spool");
    link_popup_dismissed = false;
    showLinkEntryPopup(strlen(g_tag.tray_uuid) == 32);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_lk = lv_label_create(btn_link);
  char lbl_lk_buf[32]; strncpy(lbl_lk_buf, T(STR_BTN_LINK), sizeof(lbl_lk_buf)-1);
  lv_label_set_text(lbl_lk, lbl_lk_buf);
  lv_obj_set_style_text_color(lbl_lk, lv_color_hex(0xb8e030), 0);
  lv_obj_set_style_text_font(lbl_lk, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_lk, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_lk, LV_ALIGN_CENTER, 0, 0);

  // Copy spool button — 204px, teal, matches Dried Today style
  // ID= >100 spools recommended | List= <100 spools recommended
  btn_copy = lv_btn_create(btn_bar);
  lv_obj_set_size(btn_copy, 204, 40);
  lv_obj_set_pos(btn_copy, 216, 8);
  lv_obj_set_style_bg_color(btn_copy, lv_color_hex(0x00222a), 0);
  lv_obj_set_style_bg_color(btn_copy, lv_color_hex(0x003a48), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_copy, 1, 0);
  lv_obj_set_style_border_color(btn_copy, lv_color_hex(0x00b8d4), 0);
  lv_obj_set_style_radius(btn_copy, 8, 0);
  lv_obj_set_style_shadow_width(btn_copy, 0, 0);
  lv_obj_add_flag(btn_copy, LV_OBJ_FLAG_HIDDEN);
  lv_obj_add_event_cb(btn_copy, [](lv_event_t *e) {
    logSD("UI: Button -> Copy Spool");
    showCopyEntryPopup();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_cp = lv_label_create(btn_copy);
  char lbl_cp_buf[32]; strncpy(lbl_cp_buf, T(STR_BTN_COPY_SPOOL), sizeof(lbl_cp_buf)-1);
  lv_label_set_text(lbl_cp, lbl_cp_buf);
  lv_obj_set_style_text_color(lbl_cp, lv_color_hex(0x20d8f8), 0);
  lv_obj_set_style_text_font(lbl_cp, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_cp, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_cp, LV_ALIGN_CENTER, 0, 0);

  // Settings/Burger button (x=426, w=48)
  lv_obj_t *btn_menu = lv_btn_create(btn_bar);
  lv_obj_set_size(btn_menu, 44, 40);
  lv_obj_set_pos(btn_menu, 429, 8);
  lv_obj_set_style_bg_color(btn_menu, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_menu, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_menu, 1, 0);
  lv_obj_set_style_border_color(btn_menu, lv_color_hex(0x1a2840), 0);
  lv_obj_set_style_radius(btn_menu, 8, 0);
  lv_obj_set_style_shadow_width(btn_menu, 0, 0);
  lv_obj_add_event_cb(btn_menu, [](lv_event_t *e){ logSD("UI: Button -> Burger Menu"); showSettingsScreen(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_menu = lv_label_create(btn_menu);
  lv_label_set_text(lbl_menu, LV_SYMBOL_LIST);
  lv_obj_set_style_text_color(lbl_menu, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_menu, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_menu);

  // Notification dot on the burger button. It hangs on the screen rather than
  // on the button bar, because a child of the bar would be clipped at the bar's
  // edge and half of this dot sits outside it.
  lbl_burger_badge = createUpdateBadge(lv_scr_act(), btn_menu);

  page_main = lv_scr_act();
  // lbl_raw_info points to SM diff label on main screen (see above)
}
