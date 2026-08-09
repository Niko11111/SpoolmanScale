#include "header_status.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>

#include "services/wifi_manager.h"


static lv_color_t wifiColor() {
  if (!wifi_ok) return lv_color_hex(0xe04040);
  int rssi = wifiManagerRSSI();
  if (rssi >= -65) return lv_color_hex(0x28d49a);
  if (rssi >= -75) return lv_color_hex(0xf0b838);
  return lv_color_hex(0xe06020);
}

void updateHeaderStatus() {
  if (!lbl_hdr_wifi) return;

  lv_obj_set_style_text_color(lbl_hdr_wifi, wifiColor(), 0);

  if (lbl_hdr_nfc) {
    lv_label_set_text(lbl_hdr_nfc, nfc_ok ? "NFC" : "NFC!");
    lv_obj_set_style_text_color(lbl_hdr_nfc,
      nfc_ok ? lv_color_hex(0x28d49a) : lv_color_hex(0xe04040), 0);
  }

  if (lbl_hdr_scl) {
    lv_label_set_text(lbl_hdr_scl, scl_ok ? "SCL" : "SCL!");
    lv_obj_set_style_text_color(lbl_hdr_scl,
      scl_ok ? lv_color_hex(0x28d49a) : lv_color_hex(0xe04040), 0);
  }

  if (lbl_hdr_sm) {
    lv_obj_set_style_text_color(lbl_hdr_sm,
      sm_reachable ? lv_color_hex(0x28d49a) : lv_color_hex(0xe04040), 0);
  }

  if (lbl_hdr_scans) {
    char buf[12];
    snprintf(buf, sizeof(buf), "#%d", scan_count);
    lv_label_set_text(lbl_hdr_scans, buf);
  }
}
