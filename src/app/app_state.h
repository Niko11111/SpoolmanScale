#pragma once

#include <Arduino.h>
#include <Wire.h>
#include <lvgl.h>

#include "app_config.h"
#include "bambu/bambu_tag.h"

extern int bright_normal;
extern int dim_timeout_ms;
extern int sleep_timeout_ms;

extern TwoWire I2C_EXT;

extern char cfg_wifi_ssid[33];
extern char cfg_wifi_password[65];
extern char cfg_spoolman_ip[64];
extern char cfg_spoolman_base[80];
extern bool cfg_lang_set;
extern bool cfg_first_boot;
extern bool spoolman_fail_is_setup;

extern bool nfc_ok;
extern bool scl_ok;

extern BambuTagData g_tag;
extern bool g_tag_ready;
extern bool g_tag_displayed;
extern unsigned long g_tag_shown_ms;
extern bool wifi_ok;
extern bool sm_reachable;
extern bool tag_present;

extern lv_obj_t *scr_main;
extern lv_obj_t *scr_settings;
extern lv_obj_t *scr_wifi;
extern lv_obj_t *scr_backend;
extern lv_obj_t *scr_spoolman;
extern lv_obj_t *scr_spoolman_fail;
extern lv_obj_t *scr_welcome;
extern lv_obj_t *scr_first_boot;
extern lv_obj_t *scr_extra_fields;
extern lv_obj_t *scr_cal_reminder;
extern lv_obj_t *scr_wifi_setup;
extern lv_obj_t *scr_factor;
extern lv_obj_t *scr_bag;
extern lv_obj_t *scr_lastused;
extern lv_obj_t *scr_connection;
extern lv_obj_t *scr_scale_sub;
extern lv_obj_t *scr_drying_reminder;
extern lv_obj_t *scr_display;
extern lv_obj_t *scr_system;
extern lv_obj_t *scr_ota;
extern lv_obj_t *scr_ota_browser;
extern lv_obj_t *scr_ota_github;

extern lv_obj_t *lbl_ota_status;
extern lv_obj_t *lbl_burger_badge;
extern lv_obj_t *lbl_system_badge;
extern lv_obj_t *lbl_fw_badge;
extern lv_obj_t *lbl_gh_btn_badge;
extern lv_obj_t *lbl_wifi_info;
extern lv_obj_t *ta_factor_weight;
extern lv_obj_t *kb_factor;
extern lv_obj_t *lbl_factor_result;
extern lv_obj_t *lbl_factor_cal_weight;
extern lv_obj_t *scr_wifi_pass;
extern lv_obj_t *scr_wifi_connecting;

extern int sm_id;
extern int sm_filament_id;
extern int sm_vendor_id;
extern bool sm_found;
extern float sm_remaining;
extern float sm_total;
extern float sm_spool_weight;
extern char sm_last_dried[32];
extern char sm_article_nr[32];
extern char sm_filament_name[32];
extern char sm_material_global[32];
extern char sm_color_global[16];
extern char sm_location_name[48];
extern int sm_location_id;

extern float scale_weight_g;
extern bool scale_ready;
extern float cal_factor;
extern int32_t zero_offset;
extern float scale_filter_buf[SCALE_FILTER_SIZE];
extern int scale_filter_idx;
extern bool scale_filter_full;

extern lv_obj_t *lbl_weight_main_lbl;
extern float bag_weight_g;
extern char spoolman_queried_uid[24];
extern char sm_last_used[32];
extern int nfc_retry_count;
extern int nfc_absent_count;

extern lv_obj_t *lbl_status;
extern lv_obj_t *lbl_uid;
extern lv_obj_t *lbl_tray_uuid;
extern lv_obj_t *lbl_material;
extern lv_obj_t *lbl_color;
extern lv_obj_t *lbl_filament_name;
extern lv_obj_t *lbl_color_swatch;
extern lv_obj_t *lbl_vendor;
extern lv_obj_t *lbl_temp;
extern lv_obj_t *lbl_detail;
extern lv_obj_t *lbl_date;
extern lv_obj_t *lbl_spoolman_id;
extern lv_obj_t *lbl_scan_count;
extern lv_obj_t *lbl_keys;
extern lv_obj_t *lbl_raw_info;
extern lv_obj_t *lbl_spoolman_weight;
extern lv_obj_t *lbl_scale_weight;
extern lv_obj_t *lbl_scale_diff;
extern lv_obj_t *lbl_last_used;
extern lv_obj_t *lbl_lu_cap;
extern lv_obj_t *lbl_spoolman_pct;
extern lv_obj_t *lbl_spoolman_dried;
extern lv_obj_t *lbl_spoolman_dried_val;
extern lv_obj_t *lbl_dried_sym;
extern int s_dry_numpad_target;
extern int s_dry_numpad_value;
extern lv_obj_t *s_dry_numpad_scr;
extern lv_obj_t *s_dry_numpad_lbl;
extern lv_obj_t *lbl_nfc_dot;
extern lv_obj_t *lbl_hdr_wifi;
extern lv_obj_t *lbl_hdr_nfc;
extern lv_obj_t *lbl_hdr_scl;
extern lv_obj_t *lbl_hdr_scans;
extern lv_obj_t *lbl_hdr_sm;
extern lv_obj_t *lbl_bag_sm_diff;

extern lv_obj_t *btn_dried;
extern lv_obj_t *btn_link;
extern lv_obj_t *btn_weight_main;
extern lv_obj_t *scr_more_info;
extern int scan_count;
extern lv_obj_t *page_main;
extern lv_obj_t *scr_info;
