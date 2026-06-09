#include "app_settings.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <cstring>

#include "app_config.h"
#include "auto_weight_state.h"
#include "drying_config.h"
#include "lang.h"
#include "list_limits.h"
#include "ota_state.h"
#include "prefs_store.h"
#include "user_options.h"


void loadPrefs() {
  String ssid = prefsGetString("wifi_ssid", cfg_wifi_ssid);
  String pass = prefsGetString("wifi_pass", cfg_wifi_password);
  String ip   = prefsGetString("spoolman_ip", cfg_spoolman_ip);
  strncpy(cfg_wifi_ssid, ssid.c_str(), sizeof(cfg_wifi_ssid) - 1);
  strncpy(cfg_wifi_password, pass.c_str(), sizeof(cfg_wifi_password) - 1);
  strncpy(cfg_spoolman_ip, ip.c_str(), sizeof(cfg_spoolman_ip) - 1);
  snprintf(cfg_spoolman_base, sizeof(cfg_spoolman_base), "http://%s", cfg_spoolman_ip);

  cal_factor = prefsGetFloat("cal_factor", CAL_FACTOR_DEFAULT);
  zero_offset = prefsGetInt("zero_offset", 0);
  bag_weight_g = prefsGetFloat("bag_weight", 50.0f);

  spool_list_limit = (int)prefsGetUChar("list_limit", 16);
  if (spool_list_limit < 5) spool_list_limit = 5;
  if (spool_list_limit > 100) spool_list_limit = 100;
  location_list_limit = (int)prefsGetUChar("loc_limit", 30);
  if (location_list_limit < 5) location_list_limit = 5;
  if (location_list_limit > 100) location_list_limit = 100;

  bright_normal = prefsGetUChar("bright", BRIGHT_NORMAL_DEFAULT);
  int dim_min = prefsGetUInt("dim_min", DIM_TIMEOUT_DEFAULT / 60000);
  int sleep_min = prefsGetUInt("sleep_min", SLEEP_TIMEOUT_DEFAULT / 60000);
  dim_timeout_ms = dim_min * 60000;
  sleep_timeout_ms = sleep_min * 60000;

  g_lang = (Lang)prefsGetUChar("lang", 1);
  g_date_fmt = prefsGetUChar("date_fmt", 0);
  cfg_lang_set = prefsGetBool("lang_set", false);
  cfg_first_boot = prefsGetBool("first_boot", true);
  last_used_mode = prefsGetUChar("lu_mode", 0);
  g_whole_gram = prefsGetBool("whole_gram", false);
  g_auto_weight = prefsGetBool("auto_weight", false);
  g_auto_loc_popup = prefsGetBool("auto_loc_popup", false);
  gh_prerelease = prefsGetBool("gh_prerelease", false);

  g_dry_mode = prefsGetUChar("dry_mode", 0);
  g_dry_man_yellow = (int)prefsGetInt("dry_man_y", 30);
  g_dry_man_red = (int)prefsGetInt("dry_man_r", 90);
  g_dry_mult_sealed = prefsGetFloat("dry_mult_s", 2.0f);
  char key[16];
  for (int i = 0; i < DRY_MAT_COUNT; i++) {
    snprintf(key, sizeof(key), "dry_y_%s", DRY_MAT_NAMES[i]);
    g_dry_mat_yellow[i] = (int)prefsGetInt(key, DRY_MAT_DEF_YELLOW[i]);
    snprintf(key, sizeof(key), "dry_r_%s", DRY_MAT_NAMES[i]);
    g_dry_mat_red[i] = (int)prefsGetInt(key, DRY_MAT_DEF_RED[i]);
    snprintf(key, sizeof(key), "dry_s_%s", DRY_MAT_NAMES[i]);
    g_dry_mat_sealed[i] = prefsGetBool(key, false);
  }

  Serial.printf("Prefs: SSID=%s Spoolman=%s\n", cfg_wifi_ssid, cfg_spoolman_base);
  Serial.printf("Scale: cal_factor=%.4f  zero_offset=%d  bag_weight=%.1fg\n",
    cal_factor, zero_offset, bag_weight_g);
  Serial.printf("Display: bright=%d dim=%dmin sleep=%dmin\n",
    bright_normal, dim_min, sleep_min);
}

void saveWifiCredentials(const char* ssid, const char* pass) {
  strncpy(cfg_wifi_ssid, ssid, sizeof(cfg_wifi_ssid) - 1);
  strncpy(cfg_wifi_password, pass, sizeof(cfg_wifi_password) - 1);
  prefsPutString("wifi_ssid", ssid);
  prefsPutString("wifi_pass", pass);
  Serial.printf("WiFi saved: SSID=%s\n", ssid);
}

void saveSpoolmanIP(const char* ip) {
  strncpy(cfg_spoolman_ip, ip, sizeof(cfg_spoolman_ip) - 1);
  snprintf(cfg_spoolman_base, sizeof(cfg_spoolman_base), "http://%s", ip);
  prefsPutString("spoolman_ip", ip);
}
