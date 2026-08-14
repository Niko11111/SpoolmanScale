#include "app_state.h"

int     bright_normal   = BRIGHT_NORMAL_DEFAULT;
int     dim_timeout_ms  = DIM_TIMEOUT_DEFAULT;
int     sleep_timeout_ms = SLEEP_TIMEOUT_DEFAULT;

TwoWire I2C_EXT   = TwoWire(1);

char cfg_wifi_ssid[33]     = "";
char cfg_wifi_password[65] = "";
char cfg_spoolman_ip[64]   = "";
char cfg_spoolman_base[80] = "";
bool cfg_lang_set          = false;
bool cfg_first_boot        = true;
bool spoolman_fail_is_setup  = false;
bool setup_active            = false;

bool nfc_ok = false;
bool scl_ok = false;

BambuTagData g_tag;
bool g_tag_ready = false;
bool g_tag_displayed = false;
unsigned long g_tag_shown_ms = 0;
bool wifi_ok = false;
bool sm_reachable = false;

bool tag_present = false;

lv_obj_t *scr_main   = nullptr;
lv_obj_t *scr_settings   = nullptr;
lv_obj_t *scr_wifi       = nullptr;
lv_obj_t *scr_backend    = nullptr;
lv_obj_t *scr_spoolman   = nullptr;
lv_obj_t *scr_spoolman_fail = nullptr;
lv_obj_t *scr_welcome    = nullptr;
lv_obj_t *scr_first_boot = nullptr;
lv_obj_t *scr_extra_fields = nullptr;
lv_obj_t *scr_cal_reminder = nullptr;
lv_obj_t *scr_wifi_setup = nullptr;
lv_obj_t *scr_factor     = nullptr;
lv_obj_t *scr_bag        = nullptr;
lv_obj_t *scr_lastused   = nullptr;

lv_obj_t *scr_connection = nullptr;
lv_obj_t *scr_scale_sub  = nullptr;
lv_obj_t *scr_drying_reminder = nullptr;
lv_obj_t *scr_display    = nullptr;
lv_obj_t *scr_system     = nullptr;
lv_obj_t *scr_ota        = nullptr;
lv_obj_t *scr_ota_browser = nullptr;
lv_obj_t *scr_ota_github  = nullptr;

lv_obj_t *lbl_ota_status = nullptr;

lv_obj_t *lbl_burger_badge   = nullptr;
lv_obj_t *lbl_system_badge   = nullptr;
lv_obj_t *lbl_fw_badge       = nullptr;
lv_obj_t *lbl_gh_btn_badge   = nullptr;
lv_obj_t *lbl_wifi_info = nullptr;

lv_obj_t *ta_factor_weight = nullptr;
lv_obj_t *kb_factor     = nullptr;
lv_obj_t *lbl_factor_result = nullptr;
lv_obj_t *lbl_factor_cal_weight = nullptr;

lv_obj_t *scr_wifi_pass         = nullptr;
lv_obj_t *scr_wifi_connecting   = nullptr;

int   sm_id = 0;
int   sm_filament_id = 0;
int   sm_vendor_id = 0;
bool  sm_found = false;
float sm_remaining = 0;
float sm_total = 1000;
float sm_spool_weight = 0;
char  sm_last_dried[32] = "";
char  sm_article_nr[32] = "";
char  sm_filament_name[32] = "";
char  sm_material_global[32] = "";
char  sm_color_global[16] = "";
char  sm_location_name[48] = "";
int   sm_location_id = 0;

float scale_weight_g = 0.0f;
bool scale_ready = false;
float cal_factor = CAL_FACTOR_DEFAULT;
int32_t zero_offset = 0;

float scale_filter_buf[SCALE_FILTER_SIZE] = {0};
int   scale_filter_idx = 0;
bool  scale_filter_full = false;

lv_obj_t *lbl_weight_main_lbl = nullptr;

float bag_weight_g = 50.0f;

char spoolman_queried_uid[24] = "";
char  sm_last_used[32] = "";

int nfc_retry_count = 0;
int nfc_absent_count = 0;

lv_obj_t *lbl_status;
lv_obj_t *lbl_uid;
lv_obj_t *lbl_tray_uuid;
lv_obj_t *lbl_material;
lv_obj_t *lbl_color;
lv_obj_t *lbl_filament_name;
lv_obj_t *lbl_color_swatch;
lv_obj_t *lbl_vendor;
lv_obj_t *lbl_temp;
lv_obj_t *lbl_detail;
lv_obj_t *lbl_date;
lv_obj_t *lbl_spoolman_id;
lv_obj_t *lbl_scan_count;
lv_obj_t *lbl_keys;
lv_obj_t *lbl_raw_info;

lv_obj_t *lbl_spoolman_weight;
lv_obj_t *lbl_scale_weight;
lv_obj_t *lbl_scale_diff;
lv_obj_t *lbl_last_used;
lv_obj_t *lbl_lu_cap = nullptr;
lv_obj_t *lbl_spoolman_pct;
lv_obj_t *lbl_spoolman_dried;
lv_obj_t *lbl_spoolman_dried_val;
lv_obj_t *lbl_dried_sym = nullptr;
int  s_dry_numpad_target = 0;
int  s_dry_numpad_value  = 0;
lv_obj_t* s_dry_numpad_scr = nullptr;
lv_obj_t* s_dry_numpad_lbl = nullptr;
lv_obj_t *lbl_nfc_dot;
lv_obj_t *lbl_hdr_wifi;
lv_obj_t *lbl_hdr_nfc;
lv_obj_t *lbl_hdr_scl = nullptr;
lv_obj_t *lbl_hdr_scans;
lv_obj_t *lbl_hdr_sm = nullptr;
lv_obj_t *lbl_sm_cap = nullptr;
lv_obj_t *lbl_bag_sm_diff = nullptr;

lv_obj_t *btn_dried  = nullptr;
lv_obj_t *btn_link   = nullptr;
lv_obj_t *btn_weight_main = nullptr;

lv_obj_t *scr_more_info = nullptr;

int scan_count = 0;
lv_obj_t *page_main;

lv_obj_t *scr_info = nullptr;
