#include "bluetooth_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/ble_service.h"
#include "services/label_printer.h"
#include "ui/ble_devices_screen.h"
#include "ui/reboot_popup.h"
#include "ui/header_status.h"
#include "ui/theme.h"
#include "reboot_popup.h"
#include "ui_common.h"

// ============================================================
//  BLUETOOTH
//
//  The settings screen: the master switch, and while it is on,
//  the row into the device list. Everything a device can do
//  lives behind that row (ui/ble_devices_screen.cpp); this
//  screen keeps room for what a Bluetooth page grows later, the
//  scale's own name, say.
// ============================================================

void closeBluetoothScreen() {
  if (scr_bluetooth) { lv_obj_del(scr_bluetooth); scr_bluetooth = nullptr; }
}

void buildBluetoothScreen() {
  logSD("BUILD: BluetoothScreen");
  releaseScreen(&scr_bluetooth);
  scr_bluetooth = buildOverlayScreen();
  buildSubHeader(scr_bluetooth, T(STR_BT_TITLE),
    [](lv_event_t *e){
      logSD("BTN: Back -> Connection");
      // Deferred: the Connection screen is rebuilt so its tile shows the
      // switch, and not from inside the callback of the screen it replaces.
      show_connection_from_spoolman_pending = true;
    });
  addHeaderHelp(scr_bluetooth, STR_BT_TITLE, STR_BT_HELP);

  lv_obj_t *list = buildOptionList(scr_bluetooth);

  // The switch. The state stands on the right like on every other switch.
  { char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_BT_SWITCH);
    char buf_sub[48]; copyT(buf_sub, sizeof(buf_sub), STR_BT_SWITCH_SUB);
    char buf_s[8]; copyT(buf_s, sizeof(buf_s), bleEnabled() ? STR_ON : STR_OFF);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_BLUETOOTH, buf_t, buf_sub, bleEnabled());
    lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
    if (arr_lbl) {
      lv_label_set_text(arr_lbl, buf_s);
      lv_obj_set_style_text_color(arr_lbl,
        lv_color_hex(bleEnabled() ? UI_COL_ACCENT : UI_COL_CAPTION), 0);
      lv_obj_set_style_text_font(arr_lbl, UI_FONT_SMALL, 0);
    }
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      // This boot gave the controller's memory back because the switch was
      // off; only a restart brings it back. The switch is written by the
      // restart button, so cancelling leaves it off.
      if (!bleEnabled() && !bleStackAvailable()) {
        logSD("BTN: Bluetooth -> on, restart asked");
        showRebootPopup([]() { bleSetEnabled(true); });
        return;
      }
      bleSetEnabled(!bleEnabled());
      if (!bleEnabled()) bleDevicesForget();
      logSDf("BTN: Bluetooth -> %s", bleEnabled() ? "on" : "off");
      // Through the flag, not deleting the screen this button sits on from
      // inside its own callback.
      bluetooth_rebuild_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  // The way to the devices, with what the last scan saw as the subtitle.
  if (bleEnabled()) {
    char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_BT_DEVICES);
    char buf_sub[48];
    if (!bleDevicesScanned()) copyT(buf_sub, sizeof(buf_sub), STR_BT_DEVICES_NONE_YET);
    else snprintf(buf_sub, sizeof(buf_sub), T(STR_BT_DEVICES_FMT), bleDevicesCount());
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_LIST, buf_t, buf_sub);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Bluetooth -> Devices");
      show_ble_devices_pending = true;
    }, LV_EVENT_CLICKED, NULL);

    // The printer: the one BLE device the scale has a use for so far.
    const LabelPrinterConfig c = labelPrinterLoadConfig();
    char buf_p[40]; copyT(buf_p, sizeof(buf_p), STR_PRN_TITLE);
    char buf_ps[64];
    if (!labelPrinterConfigured(c)) copyT(buf_ps, sizeof(buf_ps), STR_PRN_NONE);
    else snprintf(buf_ps, sizeof(buf_ps), "%s  %s", labelPrinterProfile(c.model).name,
                  c.name[0] ? c.name : c.address);
    lv_obj_t *pbtn = makeListBtn(list, LV_SYMBOL_IMAGE, buf_p, buf_ps, labelPrinterConfigured(c));
    lv_obj_add_event_cb(pbtn, [](lv_event_t *e){
      logSD("BTN: Bluetooth -> Printer");
      show_printer_pending = true;
    }, LV_EVENT_CLICKED, NULL);
  }
}

void handleBluetoothDeferredActions() {
  if (bluetooth_rebuild_pending) {
    bluetooth_rebuild_pending = false;
    if (scr_bluetooth) {
      buildBluetoothScreen();        // releases the previous instance itself
      lv_obj_clear_flag(scr_bluetooth, LV_OBJ_FLAG_HIDDEN);
    }
    // The header chip follows the switch; the main screen is alive underneath.
    updateHeaderStatus();
  }
}
