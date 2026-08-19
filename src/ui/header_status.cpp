#include "header_status.h"
#include "app/app_state.h"
#include "services/backend.h"

#include <Arduino.h>
#include <cstring>
#include <lvgl.h>

#include "services/user_options.h"
#include "services/wifi_manager.h"
#include "theme.h"


static lv_color_t wifiColor() {
  if (!wifi_ok) return lv_color_hex(0xe04040);
  int rssi = wifiManagerRSSI();
  if (rssi >= -65) return tc(TH_ACCENT);
  if (rssi >= -75) return tc(TH_WARNING);
  return lv_color_hex(0xe06020);
}

void updateHeaderStatus() {
  if (!lbl_hdr_wifi) return;

  lv_obj_set_style_text_color(lbl_hdr_wifi, wifiColor(), 0);

  if (lbl_hdr_nfc) {
    lv_label_set_text(lbl_hdr_nfc, nfc_ok ? "NFC" : "NFC!");
    lv_obj_set_style_text_color(lbl_hdr_nfc,
      nfc_ok ? tc(TH_ACCENT) : lv_color_hex(0xe04040), 0);
  }

  if (lbl_hdr_scl) {
    lv_label_set_text(lbl_hdr_scl, scl_ok ? "SCL" : "SCL!");
    lv_obj_set_style_text_color(lbl_hdr_scl,
      scl_ok ? tc(TH_ACCENT) : lv_color_hex(0xe04040), 0);
  }

  // Both labels follow the active backend. Set here rather than only at build
  // time, because the backend can be switched while the main screen exists.
  if (lbl_hdr_sm) {
    lv_label_set_text(lbl_hdr_sm, backendIsFilaMan() ? "FLM" : "SPM");
    lv_obj_set_style_text_color(lbl_hdr_sm,
      sm_reachable ? tc(TH_ACCENT) : lv_color_hex(0xe04040), 0);
  }

  if (lbl_sm_cap) {
    lv_label_set_text(lbl_sm_cap, backendIsFilaMan() ? "FilaMan:" : "Spoolman:");
  }

  if (lbl_hdr_scans) {
    char buf[12];
    snprintf(buf, sizeof(buf), "#%d", scan_count);
    lv_label_set_text(lbl_hdr_scans, buf);
  }

  // Status bar address. Device mode needs a live link to mean anything, but
  // the backend address stays correct while offline - that something is wrong
  // is already said by the red SPM/FLM above it.
  if (lbl_hdr_ip) {
    const char *text = nullptr;
    String ip;
    char host_buf[48];
    if (g_ip_bar_mode == IP_BAR_DEVICE && wifi_ok) {
      ip = wifiManagerLocalIP().toString();
      text = ip.c_str();
    } else if (g_ip_bar_mode == IP_BAR_BACKEND) {
      // Address only, no port. The point here is telling one server from
      // another when several are around - a test instance next to the live
      // one - and the port is the same on all of them, so it only eats width.
      const char *h = backendHost();
      if (h && h[0]) {
        const char *colon = strchr(h, ':');
        if (colon) {
          size_t n = (size_t)(colon - h);
          if (n >= sizeof(host_buf)) n = sizeof(host_buf) - 1;
          memcpy(host_buf, h, n);
          host_buf[n] = '\0';
          text = host_buf;
        } else {
          text = h;
        }
      }
    }
    if (text) {
      lv_label_set_text(lbl_hdr_ip, text);
      lv_obj_clear_flag(lbl_hdr_ip, LV_OBJ_FLAG_HIDDEN);
    } else {
      lv_obj_add_flag(lbl_hdr_ip, LV_OBJ_FLAG_HIDDEN);
    }
  }
}
