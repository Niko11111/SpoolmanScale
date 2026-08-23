#include "navigation.h"
#include "app/app_state.h"
#include "ui_common.h"
#include "web_screen.h"
#include "app/setup_flow.h"

#include <lvgl.h>

#include "hardware/display_power.h"
#include "hardware/sd_logger.h"
#include "ui/extra_fields_screen.h"
#include "ui/main_screen_helpers.h"
#include "ui/settings_screen.h"
#include "ui/spool_flow.h"


void hideAllOverlays() {
  if (sd_verbose) {
    int visible_count = 0;
    if (scr_settings && !lv_obj_has_flag(scr_settings, LV_OBJ_FLAG_HIDDEN)) visible_count++;
    if (scr_connection && !lv_obj_has_flag(scr_connection, LV_OBJ_FLAG_HIDDEN)) visible_count++;
    if (scr_scale_sub && !lv_obj_has_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN)) visible_count++;
    if (scr_display && !lv_obj_has_flag(scr_display, LV_OBJ_FLAG_HIDDEN)) visible_count++;
    if (scr_system && !lv_obj_has_flag(scr_system, LV_OBJ_FLAG_HIDDEN)) visible_count++;
    logSDf("[verbose] hideAllOverlays: %d visible, more_info=%s",
      visible_count, scr_more_info ? "yes(will delete)" : "no");
  }

  if (scr_more_info) {
    if (sd_verbose) logSD("[verbose] hideAllOverlays: deleting scr_more_info");
    lv_obj_del(scr_more_info); scr_more_info = nullptr;
    if (sd_verbose) logSD("[verbose] hideAllOverlays: scr_more_info deleted OK");
  }

  // Hide screens here. Deleting from a screen's own event callback can panic;
  // safe deletion is handled by showMainScreen() and showSettingsScreen().
  if (scr_settings)    lv_obj_add_flag(scr_settings,    LV_OBJ_FLAG_HIDDEN);
  if (scr_connection)  lv_obj_add_flag(scr_connection,  LV_OBJ_FLAG_HIDDEN);
  if (scr_scale_sub)   lv_obj_add_flag(scr_scale_sub,   LV_OBJ_FLAG_HIDDEN);
  if (scr_drying_reminder) lv_obj_add_flag(scr_drying_reminder, LV_OBJ_FLAG_HIDDEN);
  if (scr_display)     lv_obj_add_flag(scr_display,     LV_OBJ_FLAG_HIDDEN);
  if (scr_system)      lv_obj_add_flag(scr_system,      LV_OBJ_FLAG_HIDDEN);
  if (scr_web)         lv_obj_add_flag(scr_web,         LV_OBJ_FLAG_HIDDEN);
  if (scr_ota)         lv_obj_add_flag(scr_ota,         LV_OBJ_FLAG_HIDDEN);
  if (scr_ota_browser) lv_obj_add_flag(scr_ota_browser, LV_OBJ_FLAG_HIDDEN);
  if (scr_ota_github)  lv_obj_add_flag(scr_ota_github,  LV_OBJ_FLAG_HIDDEN);
  if (scr_factor)      lv_obj_add_flag(scr_factor,      LV_OBJ_FLAG_HIDDEN);
  if (scr_bag)         lv_obj_add_flag(scr_bag,         LV_OBJ_FLAG_HIDDEN);
  if (scr_lastused)    lv_obj_add_flag(scr_lastused,    LV_OBJ_FLAG_HIDDEN);
  if (scr_backend)     lv_obj_add_flag(scr_backend,     LV_OBJ_FLAG_HIDDEN);
  if (scr_filaman_options) lv_obj_add_flag(scr_filaman_options, LV_OBJ_FLAG_HIDDEN);
  if (scr_ams_assign)      lv_obj_add_flag(scr_ams_assign, LV_OBJ_FLAG_HIDDEN);
  if (scr_bambuddy_options) lv_obj_add_flag(scr_bambuddy_options, LV_OBJ_FLAG_HIDDEN);
  if (scr_bambuddy_dried) lv_obj_add_flag(scr_bambuddy_dried, LV_OBJ_FLAG_HIDDEN);
  if (scr_spoolman_options) lv_obj_add_flag(scr_spoolman_options, LV_OBJ_FLAG_HIDDEN);
  if (scr_tag_field)     lv_obj_add_flag(scr_tag_field, LV_OBJ_FLAG_HIDDEN);
  if (scr_spoolman_fail) lv_obj_add_flag(scr_spoolman_fail, LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi)        lv_obj_add_flag(scr_wifi,        LV_OBJ_FLAG_HIDDEN);
  if (scr_spoolman)    lv_obj_add_flag(scr_spoolman,    LV_OBJ_FLAG_HIDDEN);
  if (scr_welcome)     lv_obj_add_flag(scr_welcome,     LV_OBJ_FLAG_HIDDEN);
  if (scr_first_boot)  lv_obj_add_flag(scr_first_boot,  LV_OBJ_FLAG_HIDDEN);
  if (scr_extra_fields) lv_obj_add_flag(scr_extra_fields, LV_OBJ_FLAG_HIDDEN);
  if (scr_cal_reminder) lv_obj_add_flag(scr_cal_reminder, LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_setup)  lv_obj_add_flag(scr_wifi_setup,  LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_pass)   lv_obj_add_flag(scr_wifi_pass,   LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_connecting) lv_obj_add_flag(scr_wifi_connecting, LV_OBJ_FLAG_HIDDEN);
  hideSpoolFlowOverlays();
}

void showMainScreen() {
  logSD("SHOW: MainScreen");
  logSD("UI: Screen -> Main");
  // Every way out of the setup chain ends here, whether the user finished it,
  // skipped it or closed it, so this is the one place the flag has to clear.
  // Logged, because an unexpected call from somewhere in the middle of the
  // chain would silently drop the setup back to menu behaviour.
  setSetupActive(false, "main screen shown");
  setSpoolFlowIdInputOpen(false);
  hideAllOverlays();

  if (scr_settings)    { lv_obj_del(scr_settings);    scr_settings    = nullptr; }
  if (scr_connection)  { lv_obj_del(scr_connection);  scr_connection  = nullptr; }
  if (scr_scale_sub)   { lv_obj_del(scr_scale_sub);   scr_scale_sub   = nullptr; }
  if (scr_drying_reminder) { lv_obj_del(scr_drying_reminder); scr_drying_reminder = nullptr; }
  if (s_dry_numpad_scr)    { lv_obj_del(s_dry_numpad_scr);    s_dry_numpad_scr    = nullptr; }
  s_dry_numpad_lbl = nullptr;
  if (scr_display)     { lv_obj_del(scr_display);     scr_display     = nullptr; }
  if (scr_system)      { lv_obj_del(scr_system);      scr_system      = nullptr; }
  if (scr_ota)         { lv_obj_del(scr_ota);         scr_ota         = nullptr; }
  if (scr_ota_browser) { lv_obj_del(scr_ota_browser); scr_ota_browser = nullptr; }
  if (scr_ota_github)  { lv_obj_del(scr_ota_github);  scr_ota_github  = nullptr; }
  if (scr_factor)      { lv_obj_del(scr_factor);      scr_factor      = nullptr; }
  if (scr_bag)         { lv_obj_del(scr_bag);         scr_bag         = nullptr; }
  if (scr_filaman_options) { lv_obj_del(scr_filaman_options); scr_filaman_options = nullptr; }
  if (scr_ams_assign)      { lv_obj_del(scr_ams_assign);      scr_ams_assign      = nullptr; }
  if (s_ams_numpad_scr)    { lv_obj_del(s_ams_numpad_scr);    s_ams_numpad_scr    = nullptr; }
  if (scr_spoolman_options) { lv_obj_del(scr_spoolman_options); scr_spoolman_options = nullptr; }
  if (scr_bambuddy_options) { lv_obj_del(scr_bambuddy_options); scr_bambuddy_options = nullptr; }
  if (scr_bambuddy_dried)  { lv_obj_del(scr_bambuddy_dried);  scr_bambuddy_dried  = nullptr; }
  if (scr_lastused)    { lv_obj_del(scr_lastused);    scr_lastused    = nullptr; }
  if (scr_spoolman_fail){ lv_obj_del(scr_spoolman_fail); scr_spoolman_fail = nullptr; }
  if (scr_welcome)     { lv_obj_del(scr_welcome);     scr_welcome     = nullptr; }
  if (scr_first_boot)  { lv_obj_del(scr_first_boot);  scr_first_boot  = nullptr; }
  if (scr_extra_fields){ lv_obj_del(scr_extra_fields); scr_extra_fields = nullptr;
                         resetExtraFieldsScreenState(); }
  if (scr_tag_field)   { lv_obj_del(scr_tag_field);   scr_tag_field   = nullptr; }
  if (scr_cal_reminder){ lv_obj_del(scr_cal_reminder); scr_cal_reminder = nullptr; }
  deleteSpoolFlowOverlays();
  resetActivityTimer();
  updateLinkButton();
}

void showSettingsScreen() {
  logSD("SHOW: SettingsScreen");
  logSD("UI: Screen -> Settings");

  if (scr_welcome)    { lv_obj_del(scr_welcome);    scr_welcome    = nullptr; }
  if (scr_first_boot) { lv_obj_del(scr_first_boot); scr_first_boot = nullptr; }
  if (scr_wifi_setup) { lv_obj_del(scr_wifi_setup); scr_wifi_setup = nullptr; }
  if (scr_wifi_pass)  { lv_obj_del(scr_wifi_pass);  scr_wifi_pass  = nullptr; }
  hideAllOverlays();

  if (scr_settings)    { lv_obj_del(scr_settings);    scr_settings    = nullptr; }
  if (scr_connection)  { lv_obj_del(scr_connection);  scr_connection  = nullptr; }
  if (scr_scale_sub)   { lv_obj_del(scr_scale_sub);   scr_scale_sub   = nullptr; }
  if (scr_display)     { lv_obj_del(scr_display);     scr_display     = nullptr; }
  if (scr_system)      { lv_obj_del(scr_system);      scr_system      = nullptr; }
  if (scr_ota)         { lv_obj_del(scr_ota);         scr_ota         = nullptr; }
  if (scr_ota_browser) { lv_obj_del(scr_ota_browser); scr_ota_browser = nullptr; }
  if (scr_ota_github)  { lv_obj_del(scr_ota_github);  scr_ota_github  = nullptr; }
  if (scr_factor)      { lv_obj_del(scr_factor);      scr_factor      = nullptr; }
  if (scr_bag)         { lv_obj_del(scr_bag);         scr_bag         = nullptr; }
  if (scr_lastused)    { lv_obj_del(scr_lastused);    scr_lastused    = nullptr; }
  if (scr_spoolman_fail){ lv_obj_del(scr_spoolman_fail); scr_spoolman_fail = nullptr; }
  buildSettingsScreen();
  lv_obj_clear_flag(scr_settings, LV_OBJ_FLAG_HIDDEN);
  resetActivityTimer();
}
