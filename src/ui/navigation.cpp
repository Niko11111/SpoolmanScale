#include "navigation.h"
#include "scale_menu.h"
#include "app/app_state.h"
#include "ui_common.h"
#include "web_screen.h"
#include "app/setup_flow.h"

#include <lvgl.h>

#include "hardware/display_power.h"
#include "hardware/sd_logger.h"
#include "ui/ams_view.h"
#include "ui/ble_devices_screen.h"
#include "ui/bluetooth_screen.h"
#include "ui/confirm_popup.h"
#include "ui/connection_screen.h"
#include "ui/extra_fields_screen.h"
#include "ui/language_screen.h"
#include "ui/nfc_reset_popup.h"
#include "ui/ota_github.h"
#include "ui/reboot_popup.h"
#include "ui/system_screen.h"
#include "ui/spoolman_screen.h"
#include "ui/wifi_info.h"
#include "ui/wifi_menu_screen.h"
#include "ui/wifi_setup_screen.h"
#include "ui/wifi_portal_screen.h"
#include "ui/more_info_screen.h"
#include "ui/main_screen_helpers.h"
#include "ui/header_status.h"
#include "ui/settings_screen.h"
#include "ui/spool_flow.h"
#include "ui/tag_view.h"


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
  if (scr_filaman_fields)  lv_obj_add_flag(scr_filaman_fields, LV_OBJ_FLAG_HIDDEN);
  if (scr_bambuddy_options) lv_obj_add_flag(scr_bambuddy_options, LV_OBJ_FLAG_HIDDEN);
  if (scr_bambuddy_dried) lv_obj_add_flag(scr_bambuddy_dried, LV_OBJ_FLAG_HIDDEN);
  if (scr_tagwrite)       lv_obj_add_flag(scr_tagwrite,       LV_OBJ_FLAG_HIDDEN);
  if (scr_timezone)    lv_obj_add_flag(scr_timezone,    LV_OBJ_FLAG_HIDDEN);
  if (scr_spoolman_options) lv_obj_add_flag(scr_spoolman_options, LV_OBJ_FLAG_HIDDEN);
  if (scr_tag_field)     lv_obj_add_flag(scr_tag_field, LV_OBJ_FLAG_HIDDEN);
  if (scr_spoolman_fail) lv_obj_add_flag(scr_spoolman_fail, LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi)        lv_obj_add_flag(scr_wifi,        LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_menu)   lv_obj_add_flag(scr_wifi_menu,   LV_OBJ_FLAG_HIDDEN);
  if (scr_bluetooth)   lv_obj_add_flag(scr_bluetooth,   LV_OBJ_FLAG_HIDDEN);
  if (scr_ble_devices) lv_obj_add_flag(scr_ble_devices, LV_OBJ_FLAG_HIDDEN);
  if (scr_spoolman)    lv_obj_add_flag(scr_spoolman,    LV_OBJ_FLAG_HIDDEN);
  if (scr_welcome)     lv_obj_add_flag(scr_welcome,     LV_OBJ_FLAG_HIDDEN);
  if (scr_first_boot)  lv_obj_add_flag(scr_first_boot,  LV_OBJ_FLAG_HIDDEN);
  if (scr_extra_fields) lv_obj_add_flag(scr_extra_fields, LV_OBJ_FLAG_HIDDEN);
  if (scr_cal_reminder) lv_obj_add_flag(scr_cal_reminder, LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_setup)  lv_obj_add_flag(scr_wifi_setup,  LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_pass)   lv_obj_add_flag(scr_wifi_pass,   LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_connecting) lv_obj_add_flag(scr_wifi_connecting, LV_OBJ_FLAG_HIDDEN);
  // Hidden means over: the loop sees it and takes the access point down.
  if (scr_wifi_portal) lv_obj_add_flag(scr_wifi_portal, LV_OBJ_FLAG_HIDDEN);
  hideSpoolFlowOverlays();
  hideMoreInfoOverlays();
  hideAmsViewOverlays();
  webPinScreenHide();
  hideLanguageScreen();
  // The dialogs that used to be locals of whichever callback built them, so
  // nothing outside could reach them and a navigation left them standing over
  // the next screen. Closed rather than hidden: nothing ever shows a dialog
  // again, and a hidden confirm popup would keep uiModalWaiting() true from
  // under the new screen. The deletes are asynchronous, so this is safe from
  // the callbacks hideAllOverlays() is reached from.
  closeConfirmPopups();
  closeRebootPopup();
  closeNfcResetHint();
  closeFactoryResetPopup();
  closeExtraFieldsPopup();
  closeMoreInfoPopups();
  closeTagView();
  closeBleDeviceCard();
}

void deleteOtaScreens() {
  if (scr_ota)         { lv_obj_del(scr_ota);         scr_ota         = nullptr; }
  lbl_gh_btn_badge = nullptr;
  if (scr_ota_browser) { lv_obj_del(scr_ota_browser); scr_ota_browser = nullptr; }
  lbl_ota_status = nullptr;      // written by the web upload from the loop
  if (scr_ota_github)  { lv_obj_del(scr_ota_github);  scr_ota_github  = nullptr; }
  otaGithubForgetLabels();       // written by the parked check from the loop
}

// Screens that used to be hidden here and never deleted: they stayed in the
// 96 kB pool for the rest of the session, and the two WiFi screens kept their
// refresh timers firing at objects nobody was looking at. Everything that
// carries a pointer the loop can still write goes through a close helper that
// drops the pointer with the screen.
static void deleteSecondaryScreens() {
  closeWifiInfoScreen();
  closeConnectionScreen();
  closeWifiMenuScreen();
  closeBluetoothScreen();
  closeBleDevicesScreen();
  closeSpoolmanScreen();
  closeWifiConnectingScreen();
  closeWifiPortalScreen();
  if (scr_backend)  { lv_obj_del(scr_backend);  scr_backend  = nullptr; }
  if (scr_web)      { lv_obj_del(scr_web);      scr_web      = nullptr; }
  webPinScreenClose();
  if (scr_timezone) { lv_obj_del(scr_timezone); scr_timezone = nullptr; }
  closeLanguageScreen();
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
  lbl_system_badge = nullptr;    // sat on the System tile, written from the loop
  deleteSecondaryScreens();
  // Through the helper, so the remembered list pointer goes with the screen
  // rather than outliving it.
  if (scr_scale_sub)   { scaleSubScrollForget();
                         lv_obj_del(scr_scale_sub);   scr_scale_sub   = nullptr; }
  if (scr_drying_reminder) { lv_obj_del(scr_drying_reminder); scr_drying_reminder = nullptr; }
  if (s_dry_numpad_scr)    { lv_obj_del(s_dry_numpad_scr);    s_dry_numpad_scr    = nullptr; }
  s_dry_numpad_lbl = nullptr;
  if (scr_display)     { lv_obj_del(scr_display);     scr_display     = nullptr; }
  if (scr_system)      { lv_obj_del(scr_system);      scr_system      = nullptr; }
  lbl_fw_badge = nullptr;        // sat on the Firmware row, same
  deleteOtaScreens();
  if (scr_factor)      { lv_obj_del(scr_factor);      scr_factor      = nullptr; }
  lbl_factor_result     = nullptr;   // written by cal_reset_pending from the loop
  lbl_factor_cal_weight = nullptr;
  if (scr_bag)         { lv_obj_del(scr_bag);         scr_bag         = nullptr; }
  if (scr_filaman_options) { lv_obj_del(scr_filaman_options); scr_filaman_options = nullptr; }
  if (scr_ams_assign)      { lv_obj_del(scr_ams_assign);      scr_ams_assign      = nullptr; }
  destroyAmsView();
  if (scr_filaman_fields)  { lv_obj_del(scr_filaman_fields);  scr_filaman_fields  = nullptr; }
  if (s_ams_numpad_scr)    { lv_obj_del(s_ams_numpad_scr);    s_ams_numpad_scr    = nullptr; }
  s_ams_numpad_lbl = nullptr;
  if (scr_spoolman_options) { lv_obj_del(scr_spoolman_options); scr_spoolman_options = nullptr; }
  if (scr_bambuddy_options) { lv_obj_del(scr_bambuddy_options); scr_bambuddy_options = nullptr; }
  if (scr_bambuddy_dried)  { lv_obj_del(scr_bambuddy_dried);  scr_bambuddy_dried  = nullptr; }
  if (scr_tagwrite)        { lv_obj_del(scr_tagwrite);        scr_tagwrite        = nullptr; }
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
  // The chrome as well as the button bar. Settings reached from here can change
  // what the header is allowed to show - throwing the scale switch leaves an
  // SCL chip standing that nothing else would take down until the next scan -
  // and this is the one gate every way back to the main screen passes through.
  updateHeaderStatus();
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
  lbl_system_badge = nullptr;
  deleteSecondaryScreens();
  if (scr_scale_sub)   { scaleSubScrollForget();
                         lv_obj_del(scr_scale_sub);   scr_scale_sub   = nullptr; }
  if (scr_display)     { lv_obj_del(scr_display);     scr_display     = nullptr; }
  if (scr_system)      { lv_obj_del(scr_system);      scr_system      = nullptr; }
  lbl_fw_badge = nullptr;
  deleteOtaScreens();
  if (scr_factor)      { lv_obj_del(scr_factor);      scr_factor      = nullptr; }
  lbl_factor_result     = nullptr;
  lbl_factor_cal_weight = nullptr;
  if (scr_bag)         { lv_obj_del(scr_bag);         scr_bag         = nullptr; }
  if (scr_lastused)    { lv_obj_del(scr_lastused);    scr_lastused    = nullptr; }
  if (scr_spoolman_fail){ lv_obj_del(scr_spoolman_fail); scr_spoolman_fail = nullptr; }
  buildSettingsScreen();
  lv_obj_clear_flag(scr_settings, LV_OBJ_FLAG_HIDDEN);
  resetActivityTimer();
}
