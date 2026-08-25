#pragma once

#include "services/tag_field.h"  // TagFieldId, TAG_FIELD_COUNT
#include "services/tag_uid.h"   // CARD_UIDS_MAX

#include <Arduino.h>
#include <Wire.h>
#include <lvgl.h>

#include "app_config.h"
#include "bambu/bambu_tag.h"

extern int bright_normal;
extern int dim_timeout_ms;
extern int off_timeout_ms;
extern int sleep_timeout_ms;

extern TwoWire I2C_EXT;

extern char cfg_wifi_ssid[33];
extern char cfg_wifi_password[65];
extern char cfg_spoolman_ip[64];
extern char cfg_spoolman_base[80];
extern bool cfg_lang_set;
extern bool cfg_first_boot;
extern bool spoolman_fail_is_setup;

// True while the user is walking through the first time setup chain
// (language, WiFi, backend, address, credentials). Screens that appear in
// both the setup and the settings menu use it to decide which way "back"
// goes and what to hide. Previously this was guessed from whether the
// connection screen happened to exist, which broke as soon as a new step was
// inserted. Cleared by showMainScreen(), which every exit path goes through.
extern bool setup_active;

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
extern lv_obj_t *scr_filaman_options;
extern lv_obj_t *scr_ams_assign;
extern lv_obj_t *scr_filaman_fields;
extern lv_obj_t *scr_bambuddy_options;
extern lv_obj_t *scr_bambuddy_dried;
extern lv_obj_t *scr_timezone;
extern lv_obj_t *scr_spoolman_options;
extern lv_obj_t *scr_spoolman;
extern lv_obj_t *scr_spoolman_fail;
extern lv_obj_t *scr_welcome;
extern lv_obj_t *scr_first_boot;
extern lv_obj_t *scr_extra_fields;
extern lv_obj_t *scr_tag_field;
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

// How many spools answered to the tag that was just looked up. Above one
// means the backend holds more than one record for the same physical spool -
// what FilaMan's Bambu Lab plugin produces when it creates a spool this scale
// had already linked. The scan takes the best ranked one; this is what lets
// the status line say that there was a choice to make.
extern int sm_dup_count;
extern int sm_filament_id;
extern int sm_vendor_id;
extern bool sm_found;
extern float sm_remaining;
extern float sm_total;
// Which level supplied the empty-spool weight. An inherited value is a
// reasonable starting point, not a measurement, and the UI says so.
enum TareSource : uint8_t {
  TARE_NONE = 0,   // nothing known, the spool counts as 0 g
  TARE_SPOOL,      // measured for this spool
  TARE_FILAMENT,   // default for this filament
  TARE_VENDOR      // default for the brand
};

extern float sm_spool_weight;
extern uint8_t sm_tare_source;
extern char sm_last_dried[32];
// What the matched spool holds in each tag field, indexed by TagFieldId, quote
// stripped, empty where the field holds nothing. Filled by captureBindings()
// in spoolman_lookup.cpp.
//
// All of them rather than just the selected one, because that is what says
// which field actually binds this spool: an unlink has to empty the right one
// and leave the others alone, and the unlink popup sizes itself from the UID
// count without spending an HTTP request. 192 characters hold twelve 7 byte
// UIDs; anything longer is dropped rather than shortened.
extern char sm_tag_values[TAG_FIELD_COUNT][CARD_UIDS_MAX];

// The spool that already holds the tag a link was just refused for, or 0.
// Written by patchSpoolTag() on Spoolman's 409, read by the link flow so it
// can name that spool instead of reporting a bare failure.
extern int sm_tag_conflict_spool;

// Shorthand for the field the user selected, which is the one most callers
// mean. Never null.
const char* smSelectedTagValue();

// How many UIDs the matched spool is bound by, across every tag field. More
// than one only ever comes from a list field, and that is what makes "unlink"
// an ambiguous request that has to be asked about.
int smBoundUidCount();
extern char sm_article_nr[32];
extern char sm_filament_name[32];
extern char sm_material_global[32];
extern char sm_vendor_g[32];
extern char sm_color_global[16];
extern char sm_location_name[48];
extern int sm_location_id;
// FilaMan spool status, 1..6 (see FILAMAN_STATUS_* in filaman_api.h).
// 0 means unknown, which is also what Spoolman and BamBuddy always leave here.
extern int sm_status_id;

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
// Which NTAG the poll has already dealt with. Distinct from the one above,
// which means "asked the backend about this one" and is written only when the
// query actually runs, and from g_tag, which is what the display is showing.
extern char ntag_handled_uid[24];

// Clears both markers above. They answer the same question - "has the poll
// already dealt with the tag lying on the pad" - for the two tag kinds, so
// anything that changes what the backend knows about that tag has to clear
// both or the poll keeps the stale answer. Linking, copying and creating all
// do exactly that, and each one clearing whichever marker its author had in
// mind is how a freshly linked spool ended up still reading as unlinked until
// it was physically lifted off.
void tagLookupForget();
extern char sm_last_used[32];
extern int nfc_retry_count;
extern int nfc_absent_count;

// Fast re-poll state and read statistics (v0.6.1-beta).
// nfc_fast_polls counts the consecutive short-interval retries inside the
// current detection gap. The stat counters are cumulative since boot and are
// dumped to the SD log as an aggregate, never per event.
extern int nfc_fast_polls;
extern int nfc_miss_streak;
extern unsigned long nfc_stat_scans;
extern unsigned long nfc_stat_misses;
extern unsigned long nfc_stat_recovered;
extern unsigned long nfc_stat_removals;
extern unsigned long nfc_stat_reinits;

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

// Numpad for the AMS assignment window, in seconds. Held here for the
// same reason as the drying one: showMainScreen() has to be able to tear
// it down from outside the screen that built it.
extern int s_ams_numpad_value;
extern lv_obj_t *s_ams_numpad_scr;
extern lv_obj_t *s_ams_numpad_lbl;
extern lv_obj_t *lbl_nfc_dot;
extern lv_obj_t *lbl_hdr_wifi;
extern lv_obj_t *lbl_hdr_nfc;
extern lv_obj_t *lbl_hdr_scl;
extern lv_obj_t *lbl_hdr_scans;
extern lv_obj_t *lbl_hdr_ip;    // status bar address, left of the scan counter
extern lv_obj_t *lbl_hdr_sm;
extern lv_obj_t *lbl_hdr_sd;   // header SD indicator, leftmost chip
extern lv_obj_t *lbl_sm_cap;   // "Spoolman:" / "FilaMan:" above the database weight
extern lv_obj_t *lbl_bag_sm_diff;

extern lv_obj_t *btn_dried;
extern lv_obj_t *btn_link;
extern lv_obj_t *btn_weight_main;
extern lv_obj_t *scr_more_info;
extern int scan_count;
extern lv_obj_t *page_main;
extern lv_obj_t *scr_info;
