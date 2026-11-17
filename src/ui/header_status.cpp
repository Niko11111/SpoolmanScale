#include "header_status.h"
#include "app/app_state.h"
#include "services/backend.h"
#include "services/backend_profiles.h"
#include "services/ble_service.h"

#include <Arduino.h>
#include <cstdio>
#include <cstring>
#include <lvgl.h>

#include "hardware/fuel_gauge.h"
#include "services/device_name.h"
#include "services/mdns_service.h"
#include "services/user_options.h"
#include "ui/main_screen_helpers.h"
#include "ui/theme.h"
#include "services/wifi_manager.h"


// 192.168.4.100:7913 needs about 113 px in font 12 and the address label is
// 94 wide, so the port mode gets the room it needs and the status line to its
// left gives it up - more again when the address carries "https://".
static void sizeHeaderAddress(const char* text) {
  int ip_w = HDR_IP_W;
  if (g_ip_bar_mode == IP_BAR_BACKEND_PORT) {
    const bool https = (strncmp(text, "https://", 8) == 0);
    ip_w = https ? HDR_IP_W_HTTPS : HDR_IP_W_PORT;
  }
  lv_obj_set_width(lbl_hdr_ip, ip_w);
  if (lbl_status) lv_obj_set_width(lbl_status, HDR_STATUS_W_BESIDE(ip_w));
}

static lv_color_t wifiColor() {
  if (!wifi_ok) return lv_color_hex(UI_COL_BAD);
  int rssi = wifiManagerRSSI();
  if (rssi >= -65) return lv_color_hex(UI_COL_GOOD);
  if (rssi >= -75) return lv_color_hex(UI_COL_WARN);
  return lv_color_hex(UI_COL_SIGNAL_LOW);
}

// Right to left, one gap between neighbours. Fixed offsets were what made the
// spacing uneven: they put the chips on a 32 px pitch while the labels differ
// in width, so the gaps came out 5, 9 and 7 px. Widths also move at runtime -
// "NFC" becomes "NFC!" on an error and the badge follows the backend - which
// is why this runs after every text change rather than once at build time.
#define HDR_CHIP_MARGIN  8
#define HDR_CHIP_GAP    10

// Battery glyph steps and warning levels, in percent.
#define HDR_BAT_FULL_PCT   88
#define HDR_BAT_3_PCT      63
#define HDR_BAT_2_PCT      38
#define HDR_BAT_1_PCT      13
#define HDR_BAT_WARN_PCT   30
#define HDR_BAT_BAD_PCT    15

// Percent, glyph and a bolt while charging. Compact leaves the percent out,
// for a row that would otherwise run into the title.
static void setBatteryText(bool compact) {
  const int pct = fuelGaugePercent();
  const char *icon = LV_SYMBOL_BATTERY_EMPTY;
  if (pct >= HDR_BAT_FULL_PCT)   icon = LV_SYMBOL_BATTERY_FULL;
  else if (pct >= HDR_BAT_3_PCT) icon = LV_SYMBOL_BATTERY_3;
  else if (pct >= HDR_BAT_2_PCT) icon = LV_SYMBOL_BATTERY_2;
  else if (pct >= HDR_BAT_1_PCT) icon = LV_SYMBOL_BATTERY_1;
  const char *bolt = fuelGaugeFlow() == FUEL_FLOW_CHARGING ? LV_SYMBOL_CHARGE : "";

  char buf[24];
  if (compact) snprintf(buf, sizeof(buf), "%s%s", icon, bolt);
  else         snprintf(buf, sizeof(buf), "%d%% %s%s", pct, icon, bolt);
  lv_label_set_text(lbl_hdr_bat, buf);
}

static bool isShown(lv_obj_t *obj) {
  return obj && !lv_obj_has_flag(obj, LV_OBJ_FLAG_HIDDEN);
}

// Packs the visible chips right to left from the backend badge and returns
// the leftmost one.
static lv_obj_t *packHeaderChips() {
  // A label sized to its content only knows its new width after a layout pass,
  // and lv_obj_align_to() reads that width. Without this the chips would be
  // placed from the previous text.
  lv_obj_update_layout(lv_obj_get_parent(lbl_hdr_sm));

  lv_obj_align(lbl_hdr_sm, LV_ALIGN_RIGHT_MID, -HDR_CHIP_MARGIN, 0);
  lv_obj_t *prev = lbl_hdr_sm;
  // AMS first, so it lands directly left of the backend badge: it belongs to
  // the backend, and the two read as a pair.
  lv_obj_t *chain[] = { btn_hdr_ams, lbl_hdr_scl, btn_hdr_nfc, lbl_hdr_wifi,
                        lbl_hdr_bat, lbl_hdr_bt, lbl_hdr_sd };
  for (unsigned i = 0; i < sizeof(chain) / sizeof(chain[0]); i++) {
    // Hidden counts as absent. lv_obj_align_to() reads nothing but the
    // reference object's geometry - the hidden flag never reaches it - so a
    // hidden label keeps its slot and leaves a hole in the row. That is what
    // the SD icon has been doing on a card-less device, and it is what a chip
    // that comes and goes at runtime would do on every appearance.
    if (!isShown(chain[i])) continue;
    lv_obj_align_to(chain[i], prev, LV_ALIGN_OUT_LEFT_MID, -HDR_CHIP_GAP, 0);
    prev = chain[i];
  }
  // align_to() wrote the positions; the x read below needs them applied.
  lv_obj_update_layout(lv_obj_get_parent(lbl_hdr_sm));
  return prev;
}

static bool runsIntoTitle(lv_obj_t *leftmost) {
  if (!lbl_hdr_title || !leftmost) return false;
  const lv_coord_t title_end = lv_obj_get_x(lbl_hdr_title) + lv_obj_get_width(lbl_hdr_title);
  return lv_obj_get_x(leftmost) < title_end + HDR_CHIP_GAP;
}

void layoutHeaderChips() {
  if (!lbl_hdr_sm) return;
  // The battery shows its percent while the row has room for it, and drops
  // it when every chip is on and the row would reach the title.
  const bool bat = isShown(lbl_hdr_bat) && fuelGaugePresent();
  if (bat) setBatteryText(false);
  lv_obj_t *leftmost = packHeaderChips();
  if (bat && runsIntoTitle(leftmost)) {
    setBatteryText(true);
    packHeaderChips();
  }

  // The address ends where the row ends; the status text left of it takes the
  // rest (HDR_STATUS_W_BESIDE).
  if (lbl_hdr_ip) lv_obj_align(lbl_hdr_ip, LV_ALIGN_RIGHT_MID, -HDR_ROW_MARGIN, 0);
}

// Colour and visibility. The text is set by layoutHeaderChips(), which runs
// at the end of updateHeaderStatus() and knows how much room the row has.
static void updateHeaderBattery() {
  if (!lbl_hdr_bat) return;
  if (!fuelGaugePresent()) {
    lv_obj_add_flag(lbl_hdr_bat, LV_OBJ_FLAG_HIDDEN);
    return;
  }
  const int pct = fuelGaugePercent();
  const FuelGaugeFlow flow = fuelGaugeFlow();
  uint32_t col = UI_COL_CAPTION;
  if (flow == FUEL_FLOW_CHARGING || flow == FUEL_FLOW_FULL) col = UI_COL_GOOD;
  else if (pct <= HDR_BAT_BAD_PCT)  col = UI_COL_BAD;
  else if (pct <= HDR_BAT_WARN_PCT) col = UI_COL_WARN;
  lv_obj_set_style_text_color(lbl_hdr_bat, lv_color_hex(col), 0);
  lv_obj_clear_flag(lbl_hdr_bat, LV_OBJ_FLAG_HIDDEN);
}

void updateHeaderStatus() {
  if (!lbl_hdr_wifi) return;

  lv_obj_set_style_text_color(lbl_hdr_wifi, wifiColor(), 0);

  updateHeaderBattery();

  // Bluetooth follows the master switch: shown while BLE may be used, gone
  // otherwise. The chip chain leaves no hole for a hidden one.
  if (lbl_hdr_bt) {
    if (bleEnabled()) lv_obj_clear_flag(lbl_hdr_bt, LV_OBJ_FLAG_HIDDEN);
    else              lv_obj_add_flag(lbl_hdr_bt, LV_OBJ_FLAG_HIDDEN);
  }

  if (lbl_hdr_nfc) {
    lv_label_set_text(lbl_hdr_nfc, nfc_ok ? "NFC" : "NFC!");
    const lv_color_t c = lv_color_hex(nfc_ok ? UI_COL_GOOD : UI_COL_BAD);
    lv_obj_set_style_text_color(lbl_hdr_nfc, c, 0);
    // The chip's frame follows its label, so a fault shows on the button too.
    if (btn_hdr_nfc) lv_obj_set_style_border_color(btn_hdr_nfc, c, 0);
  }

  // The chip is not built at all when the device starts without a load cell.
  // It still exists when the switch is thrown while the device is running, and
  // then it has to go: the readings stop, so whatever it last said is frozen.
  // The restart the switch asks for rebuilds the header without it.
  if (lbl_hdr_scl) {
    if (!g_scale_fitted) {
      lv_obj_add_flag(lbl_hdr_scl, LV_OBJ_FLAG_HIDDEN);
    } else {
      lv_obj_clear_flag(lbl_hdr_scl, LV_OBJ_FLAG_HIDDEN);
      lv_label_set_text(lbl_hdr_scl, scl_ok ? "SCL" : "SCL!");
      lv_obj_set_style_text_color(lbl_hdr_scl,
        scl_ok ? lv_color_hex(UI_COL_GOOD) : lv_color_hex(UI_COL_BAD), 0);
    }
  }

  // Both labels follow the active backend. Set here rather than only at build
  // time, because the backend can be switched while the main screen exists.
  if (lbl_hdr_sm) {
    lv_label_set_text(lbl_hdr_sm, backendBadge());
    lv_obj_set_style_text_color(lbl_hdr_sm,
      sm_reachable ? lv_color_hex(UI_COL_GOOD) : lv_color_hex(UI_COL_BAD), 0);
  }

  if (lbl_sm_cap) {
    char cap_buf[16];
    backendCaption(cap_buf, sizeof(cap_buf));
    lv_label_set_text(lbl_sm_cap, cap_buf);
  }

  // Status bar address. Device mode needs a live link to mean anything, but
  // the backend address stays correct while offline - that something is wrong
  // is already said by the red SPM/FLM above it.
  if (lbl_hdr_ip) {
    const char *text = nullptr;
    String ip;
    char host_buf[48];
    const bool shows_backend = g_ip_bar_mode == IP_BAR_BACKEND || g_ip_bar_mode == IP_BAR_BACKEND_PORT;
    const char *named = shows_backend ? backendProfileHeaderName() : nullptr;
    if (named) {
      text = named;
    } else if (g_ip_bar_mode == IP_BAR_DEVICE && wifi_ok) {
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
    } else if (g_ip_bar_mode == IP_BAR_BACKEND_PORT) {
      // As the user typed it, port included. backendHost() already holds
      // "ip:port" when one was given - the mode above is the one that takes
      // it apart, this one does not.
      const char *h = backendHost();
      if (h && h[0]) text = h;
    }
    if (text) {
      sizeHeaderAddress(text);
      lv_label_set_text(lbl_hdr_ip, text);
      lv_obj_clear_flag(lbl_hdr_ip, LV_OBJ_FLAG_HIDDEN);
    } else {
      lv_obj_add_flag(lbl_hdr_ip, LV_OBJ_FLAG_HIDDEN);
      if (lbl_status) lv_obj_set_width(lbl_status, HDR_STATUS_W_FULL);
    }
  }

  // Zone 4's AMS button hangs on the backend, and this function already runs
  // on every backend switch - backendApplyMode() calls it. Costs two pointer
  // checks on a device that has a scale, where neither object exists.
  updateAmsAffordance();

  // Last: every text above is final by now, so the widths the packing reads
  // are the ones that will actually be drawn.
  layoutHeaderChips();
}
