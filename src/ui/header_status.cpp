#include "header_status.h"
#include "app/app_state.h"
#include "services/backend.h"

#include <Arduino.h>
#include <cstring>
#include <lvgl.h>

#include "services/device_name.h"
#include "services/mdns_service.h"
#include "services/user_options.h"
#include "services/wifi_manager.h"


static lv_color_t wifiColor() {
  if (!wifi_ok) return lv_color_hex(0xe04040);
  int rssi = wifiManagerRSSI();
  if (rssi >= -65) return lv_color_hex(0x28d49a);
  if (rssi >= -75) return lv_color_hex(0xf0b838);
  return lv_color_hex(0xe06020);
}

// Right to left, one gap between neighbours. Fixed offsets were what made the
// spacing uneven: they put the chips on a 32 px pitch while the labels differ
// in width, so the gaps came out 5, 9 and 7 px. Widths also move at runtime -
// "NFC" becomes "NFC!" on an error and the badge follows the backend - which
// is why this runs after every text change rather than once at build time.
#define HDR_CHIP_MARGIN  8
#define HDR_CHIP_GAP    10

void layoutHeaderChips() {
  if (!lbl_hdr_sm) return;
  // A label sized to its content only knows its new width after a layout pass,
  // and lv_obj_align_to() reads that width. Without this the chips would be
  // placed from the previous text.
  lv_obj_update_layout(lv_obj_get_parent(lbl_hdr_sm));

  lv_obj_align(lbl_hdr_sm, LV_ALIGN_RIGHT_MID, -HDR_CHIP_MARGIN, 0);
  lv_obj_t *prev = lbl_hdr_sm;
  lv_obj_t *chain[] = { lbl_hdr_scl, lbl_hdr_nfc, lbl_hdr_wifi, lbl_hdr_sd };
  for (unsigned i = 0; i < sizeof(chain) / sizeof(chain[0]); i++) {
    if (!chain[i]) continue;
    lv_obj_align_to(chain[i], prev, LV_ALIGN_OUT_LEFT_MID, -HDR_CHIP_GAP, 0);
    prev = chain[i];
  }

  // The address follows the scan counter for the same reason: that counter
  // grows a digit at a time and a fixed offset would eventually collide.
  if (lbl_hdr_ip && lbl_hdr_scans)
    lv_obj_align_to(lbl_hdr_ip, lbl_hdr_scans, LV_ALIGN_OUT_LEFT_MID, -HDR_CHIP_GAP, 0);
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

  // Both labels follow the active backend. Set here rather than only at build
  // time, because the backend can be switched while the main screen exists.
  if (lbl_hdr_sm) {
    lv_label_set_text(lbl_hdr_sm, backendBadge());
    lv_obj_set_style_text_color(lbl_hdr_sm,
      sm_reachable ? lv_color_hex(0x28d49a) : lv_color_hex(0xe04040), 0);
  }

  if (lbl_sm_cap) {
    char cap_buf[16];
    backendCaption(cap_buf, sizeof(cap_buf));
    lv_label_set_text(lbl_sm_cap, cap_buf);
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
    } else if (g_ip_bar_mode == IP_BAR_MDNS && mdnsRunning()) {
      // Bare label, no suffix. Same reasoning as the port below: there are
      // about 94 pixels between the status text and the scan counter, and
      // the suffix is the same on every device, so it only eats width.
      text = deviceLabel();
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

  // Last: every text above is final by now, so the widths the packing reads
  // are the ones that will actually be drawn.
  layoutHeaderChips();
}
