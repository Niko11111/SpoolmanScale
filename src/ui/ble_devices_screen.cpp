#include "ble_devices_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/ble_service.h"
#include "services/label_printer.h"
#include "ui/info_popup.h"
#include "ui/loading_overlay.h"
#include "ui/theme.h"
#include "ui_common.h"

// How many devices a scan keeps, named ones first. The list shows only the
// named ones unless asked for all: a printer always says its name, and the
// nameless (phones, beacons, the neighbour's lamp) are most of what a scan
// sees. Twelve rows took 69 % of the old LVGL pool (23.09.2026), so "all"
// stops at that; lvPoolHasRoomForRow() guards it on top.
#define BLE_SCAN_MAX      16
#define BLE_LIST_MAX_ROWS 12
// The note under a filtered list, clear of the list's own padding.
#define BLE_NOTE_W        440
// How long one scan runs. The overlay stands for exactly this long.
#define BLE_SCAN_MS  5000

// Signal in words. dBm means nothing to most people, and three steps are
// what the difference between "next to the scale" and "next door" needs.
#define BLE_RSSI_STRONG (-60)
#define BLE_RSSI_MEDIUM (-75)

// The header's scan button: the help circle's place and size, so it sits
// where every sub screen keeps its one extra control.
#define BLE_HDR_BTN_X    386
#define BLE_HDR_BTN_Y    5
#define BLE_HDR_BTN_SIZE 34
#define BLE_HDR_BTN_EXT  6

// The card: title, three lines, two buttons. Top to bottom 18 - title - 12 -
// address - 6 - signal - 6 - role - 14 - buttons 56 - 12.
#define BLE_CARD_H         236
#define BLE_CARD_TITLE_Y   18
#define BLE_CARD_ADDR_Y    62
#define BLE_CARD_SIGNAL_Y  92
#define BLE_CARD_ROLE_Y    120
#define BLE_CARD_BTN_GAP   8
#define BLE_CARD_ROW_Y     (BLE_CARD_H - UI_CARD_ROW_X - UI_POPUP_BTN_H)

static BleDevice ble_devices[BLE_SCAN_MAX];
static int  ble_device_count = 0;
static bool ble_scanned = false;   // a scan has run since the switch went on
static bool ble_failed  = false;   // the last scan could not start the stack
static bool ble_show_all = false;  // the nameless ones too, until the next restart

static lv_obj_t *scr_card = nullptr;

bool bleDevicesScanned() { return ble_scanned; }
int  bleDevicesCount()   { return ble_device_count; }
const BleDevice* bleDevicesAt(int index) {
  return index >= 0 && index < ble_device_count ? &ble_devices[index] : nullptr;
}
bool bleDevicesScanning() { return ble_scan_pending; }

static int signalString(int8_t rssi) {
  if (rssi >= BLE_RSSI_STRONG) return STR_BT_SIG_STRONG;
  if (rssi >= BLE_RSSI_MEDIUM) return STR_BT_SIG_MEDIUM;
  return STR_BT_SIG_WEAK;
}

static void deviceName(const BleDevice& d, char* buf, size_t n) {
  if (d.name[0]) snprintf(buf, n, "%s", d.name);
  else copyT(buf, n, STR_BT_UNNAMED);
}

void closeBleDevicesScreen() {
  if (scr_ble_devices) { lv_obj_del(scr_ble_devices); scr_ble_devices = nullptr; }
}

void closeBleDeviceCard() {
  if (scr_card) { lv_obj_del(scr_card); scr_card = nullptr; }
}

bool isBleDeviceCardOpen() { return scr_card != nullptr; }

// The card over the list: what the row says, spelled out, and a way out. The
// actions a device can take (become the printer, later the reader) come with
// the features that need them and go into the row of answers here.
static void showBleDeviceCard(int index) {
  closeBleDeviceCard();
  if (index < 0 || index >= ble_device_count) return;
  const BleDevice& d = ble_devices[index];
  logSDf("SHOW: BleDeviceCard %s", d.address);

  scr_card = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_card, LV_HOR_RES, LV_VER_RES);
  lv_obj_set_pos(scr_card, 0, 0);
  lv_obj_set_style_bg_color(scr_card, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(scr_card, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(scr_card, 0, 0);
  lv_obj_set_style_radius(scr_card, 0, 0);
  lv_obj_set_style_pad_all(scr_card, 0, 0);
  lv_obj_clear_flag(scr_card, LV_OBJ_FLAG_SCROLLABLE);
  // Swallows touches meant for the list underneath.
  lv_obj_add_flag(scr_card, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *box = lv_obj_create(scr_card);
  lv_obj_set_size(box, UI_POPUP_W, BLE_CARD_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  char name[BLE_NAME_LEN];
  deviceName(d, name, sizeof(name));
  lv_obj_t *title = lv_label_create(box);
  lv_label_set_text(title, name);
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(title, UI_FONT_HEADLINE, 0);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(title, LV_LABEL_LONG_DOT);
  lv_obj_set_width(title, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, BLE_CARD_TITLE_Y);

  char line[64];
  snprintf(line, sizeof(line), "%s: %s", T(STR_BT_CARD_ADDRESS), d.address);
  lv_obj_t *addr = lv_label_create(box);
  lv_label_set_text(addr, line);
  lv_obj_set_style_text_color(addr, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(addr, UI_FONT_BODY, 0);
  lv_obj_set_style_text_align(addr, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(addr, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(addr, LV_ALIGN_TOP_MID, 0, BLE_CARD_ADDR_Y);

  snprintf(line, sizeof(line), "%s: %s (%d dBm)", T(STR_BT_CARD_SIGNAL),
           T(signalString(d.rssi)), (int)d.rssi);
  lv_obj_t *sig = lv_label_create(box);
  lv_label_set_text(sig, line);
  lv_obj_set_style_text_color(sig, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_style_text_font(sig, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_align(sig, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(sig, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(sig, LV_ALIGN_TOP_MID, 0, BLE_CARD_SIGNAL_Y);

  // The role line: what this device is to the scale, when it is anything.
  const bool is_printer = labelPrinterIsDevice(d.address);
  if (is_printer) {
    lv_obj_t *role = lv_label_create(box);
    lv_label_set_text(role, T(STR_BT_CARD_IS_PRINTER));
    lv_obj_set_style_text_color(role, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_set_style_text_font(role, UI_FONT_SMALL, 0);
    lv_obj_set_style_text_align(role, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(role, UI_POPUP_W - UI_CARD_TEXT_PAD);
    lv_obj_align(role, LV_ALIGN_TOP_MID, 0, BLE_CARD_ROLE_Y);
  }

  // The row of answers: the action on the left, the way out on the right.
  // Both run from the loop: the buttons sit on the card that would go.
  const lv_coord_t btn_w = (UI_POPUP_W - 2 * UI_CARD_ROW_X - BLE_CARD_BTN_GAP) / 2;
  lv_obj_t *act = lv_btn_create(box);
  lv_obj_set_size(act, btn_w, UI_POPUP_BTN_H);
  lv_obj_set_pos(act, UI_CARD_ROW_X, BLE_CARD_ROW_Y);
  lv_obj_set_style_bg_color(act, lv_color_hex(is_printer ? UI_COL_LINE : UI_COL_OK_BG), 0);
  lv_obj_set_style_bg_color(act, lv_color_hex(is_printer ? UI_COL_POPUP_BORDER : UI_COL_OK_BG_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(act, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(act, 0, 0);
  lv_obj_set_style_border_width(act, 0, 0);
  lv_obj_set_style_pad_all(act, 0, 0);
  lv_obj_clear_flag(act, LV_OBJ_FLAG_SCROLLABLE);
  if (is_printer) {
    lv_obj_add_event_cb(act, [](lv_event_t *e) {
      (void)e;
      ble_card_forget_printer_pending = true;
    }, LV_EVENT_CLICKED, NULL);
  } else {
    lv_obj_add_event_cb(act, [](lv_event_t *e) {
      ble_card_set_printer_pending = (int)(intptr_t)lv_event_get_user_data(e);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)index);
  }
  lv_obj_t *al = lv_label_create(act);
  lv_label_set_text(al, T(is_printer ? STR_BT_CARD_FORGET_PRINTER : STR_BT_CARD_USE_PRINTER));
  lv_obj_set_style_text_color(al, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(al, UI_FONT_TITLE, 0);
  lv_obj_center(al);

  lv_obj_t *btn = lv_btn_create(box);
  lv_obj_set_size(btn, btn_w, UI_POPUP_BTN_H);
  lv_obj_set_pos(btn, UI_CARD_ROW_X + btn_w + BLE_CARD_BTN_GAP, BLE_CARD_ROW_Y);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_POPUP_BORDER), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_set_style_pad_all(btn, 0, 0);
  lv_obj_clear_flag(btn, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(btn, [](lv_event_t *e) {
    (void)e;
    ble_card_close_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *l = lv_label_create(btn);
  lv_label_set_text(l, T(STR_BT_CLOSE));
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(l, UI_FONT_TITLE, 0);
  lv_obj_center(l);
}

// The scan button in the header: the help circle's spot, with the refresh
// symbol in it. Below the 44 px touch minimum by design, like the help; the
// hit area is widened instead.
static void addScanButton(lv_obj_t *scr) {
  lv_obj_t *btn = lv_btn_create(scr);
  lv_obj_set_size(btn, BLE_HDR_BTN_SIZE, BLE_HDR_BTN_SIZE);
  lv_obj_set_pos(btn, BLE_HDR_BTN_X, BLE_HDR_BTN_Y);
  lv_obj_set_style_bg_opa(btn, LV_OPA_TRANSP, 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_ROW_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_bg_opa(btn, LV_OPA_COVER, LV_STATE_PRESSED);
  lv_obj_set_style_border_color(btn, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_border_width(btn, 1, 0);
  lv_obj_set_style_radius(btn, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_pad_all(btn, 0, 0);
  lv_obj_set_ext_click_area(btn, BLE_HDR_BTN_EXT);
  lv_obj_add_event_cb(btn, [](lv_event_t *e) {
    (void)e;
    logSD("BTN: BleDevices -> Scan");
    // The scan blocks for seconds and starts the stack: loop only.
    ble_scan_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *ico = lv_label_create(btn);
  lv_label_set_text(ico, LV_SYMBOL_REFRESH);
  lv_obj_set_style_text_color(ico, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(ico, UI_FONT_BODY, 0);
  lv_obj_align(ico, LV_ALIGN_CENTER, 0, 0);
}

void buildBleDevicesScreen() {
  logSD("BUILD: BleDevicesScreen");
  closeBleDeviceCard();
  releaseScreen(&scr_ble_devices);
  scr_ble_devices = buildOverlayScreen();
  buildSubHeader(scr_ble_devices, T(STR_BT_DEVICES),
    [](lv_event_t *e){
      logSD("BTN: Back -> Bluetooth");
      // Deferred, and a rebuild: the Bluetooth screen's row says how many
      // devices the scan saw, so it is drawn again on the way back.
      show_bluetooth_pending = true;
    });
  addScanButton(scr_ble_devices);

  lv_obj_t *list = buildOptionList(scr_ble_devices);
  int rows = 0;
  int unnamed = 0;
  for (int i = 0; i < ble_device_count; i++) if (!ble_devices[i].name[0]) unnamed++;
  if (ble_scanned && !ble_device_count) {
    char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_BT_NONE_FOUND);
    lv_obj_t *row = makeListBtn(list, LV_SYMBOL_BLUETOOTH, buf_t, "");
    lv_obj_t *arr_lbl = lv_obj_get_child(row, -1);
    if (arr_lbl) lv_label_set_text(arr_lbl, "");
    lv_obj_clear_flag(row, LV_OBJ_FLAG_CLICKABLE);
    rows++;
  }
  for (int i = 0; i < ble_device_count; i++) {
    if (!ble_show_all && !ble_devices[i].name[0]) continue;
    if (rows >= BLE_LIST_MAX_ROWS) break;
    if (!lvPoolHasRoomForRow()) { logSDf("BLE: list cut at %d rows", i); break; }
    char name[BLE_NAME_LEN];
    deviceName(ble_devices[i], name, sizeof(name));
    char sub[48];
    snprintf(sub, sizeof(sub), "%s  %s", ble_devices[i].address,
             T(signalString(ble_devices[i].rssi)));
    lv_obj_t *row = makeListBtn(list, LV_SYMBOL_BLUETOOTH, name, sub,
                                labelPrinterIsDevice(ble_devices[i].address));
    // The role stands where the arrow is, like a switch's state.
    if (labelPrinterIsDevice(ble_devices[i].address)) {
      lv_obj_t *arr_lbl = lv_obj_get_child(row, -1);
      if (arr_lbl) {
        lv_label_set_text(arr_lbl, T(STR_PRN_TITLE));
        lv_obj_set_style_text_color(arr_lbl, lv_color_hex(UI_COL_ACCENT), 0);
        lv_obj_set_style_text_font(arr_lbl, UI_FONT_SMALL, 0);
      }
    }
    // The card is built from the loop, never inside the row's own callback.
    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      ble_card_pending = (int)(intptr_t)lv_event_get_user_data(e);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)i);
    rows++;
  }

  // Under a filtered list, what it leaves out and how to get it back; the
  // way back to the filter once everything is shown.
  if (ble_scanned && unnamed > 0) {
    if (!ble_show_all) {
      lv_obj_t *note = lv_label_create(list);
      lv_label_set_text(note, T(STR_BT_FILTER_NOTE));
      lv_label_set_long_mode(note, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(note, BLE_NOTE_W);
      lv_obj_set_style_text_font(note, UI_FONT_SMALL, 0);
      lv_obj_set_style_text_color(note, lv_color_hex(UI_COL_INK_SOFT), 0);
    }
    char buf_t[48];
    if (ble_show_all) copyT(buf_t, sizeof(buf_t), STR_BT_SHOW_NAMED);
    else snprintf(buf_t, sizeof(buf_t), T(STR_BT_SHOW_ALL_FMT), unnamed);
    lv_obj_t *tog = makeListBtn(list, ble_show_all ? LV_SYMBOL_EYE_CLOSE : LV_SYMBOL_EYE_OPEN,
                                buf_t, "");
    lv_obj_add_event_cb(tog, [](lv_event_t *e) {
      (void)e;
      ble_show_all = !ble_show_all;
      logSDf("BTN: BleDevices -> %s", ble_show_all ? "show all" : "named only");
      // A rebuild of the screen this button sits on: from the loop.
      show_ble_devices_pending = true;
    }, LV_EVENT_CLICKED, NULL);
  }
  logLvMem("ble_devices", rows);
}

void handleBleDevicesDeferredActions() {
  if (ble_scan_pending) {
    // The scan runs whether the list is on screen or not: the browser page
    // asks for one too. The overlay stands over whatever is showing.
    if (bleEnabled()) {
      closeBleDeviceCard();
      loadingOverlayShow(T(STR_BT_SCANNING));
      const int n = bleScan(ble_devices, BLE_SCAN_MAX, BLE_SCAN_MS, loadingOverlayTick);
      loadingOverlayHide();
      ble_scanned = true;
      ble_device_count = n < 0 ? 0 : n;
      ble_failed = n < 0;
      if (scr_ble_devices) {
        buildBleDevicesScreen();     // releases the previous instance itself
        lv_obj_clear_flag(scr_ble_devices, LV_OBJ_FLAG_HIDDEN);
      }
      // After the rebuild, so the popup is not taken down with the old screen.
      if (ble_failed) {
        ble_failed = false;
        showInfoPopup(STR_BT_TITLE, STR_BT_INIT_FAILED, INFO_WARN);
      }
    }
    // Cleared last: the browser page reads it as "still scanning" until here.
    ble_scan_pending = false;
  }
  if (ble_card_pending >= 0) {
    const int index = ble_card_pending;
    ble_card_pending = -1;
    if (scr_ble_devices) showBleDeviceCard(index);
  }
  if (ble_card_close_pending) {
    ble_card_close_pending = false;
    closeBleDeviceCard();
  }
  if (ble_card_set_printer_pending >= 0) {
    const int index = ble_card_set_printer_pending;
    ble_card_set_printer_pending = -1;
    closeBleDeviceCard();
    if (index >= 0 && index < ble_device_count) {
      LabelPrinterConfig c = labelPrinterLoadConfig();
      snprintf(c.name, sizeof(c.name), "%s", ble_devices[index].name);
      snprintf(c.address, sizeof(c.address), "%s", ble_devices[index].address);
      if (!labelPrinterSaveConfig(c)) showInfoPopup(STR_PRN_TITLE, STR_ERR_SAVE, INFO_WARN);
      logSDf("BTN: BleDevices -> printer is %s", c.address);
    }
    if (scr_ble_devices) {
      buildBleDevicesScreen();
      lv_obj_clear_flag(scr_ble_devices, LV_OBJ_FLAG_HIDDEN);
    }
  }
  if (ble_card_forget_printer_pending) {
    ble_card_forget_printer_pending = false;
    closeBleDeviceCard();
    labelPrinterForget();
    logSD("BTN: BleDevices -> printer forgotten");
    if (scr_ble_devices) {
      buildBleDevicesScreen();
      lv_obj_clear_flag(scr_ble_devices, LV_OBJ_FLAG_HIDDEN);
    }
  }
}

// Called when the switch goes off: what the list knew is no longer true.
void bleDevicesForget() {
  ble_device_count = 0;
  ble_scanned = false;
}
