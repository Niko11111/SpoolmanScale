#include "diag_banner.h"

#include <Arduino.h>
#include <cstring>
#include <lvgl.h>

#include "app/app_state.h"
#include "diag_popup.h"
#include "lang.h"
#include "services/diagnostics.h"

// Own pointers rather than any in app_state: nothing outside this file has
// business writing to them.
static lv_obj_t *banner_parent = nullptr;
static lv_obj_t *banner        = nullptr;
static lv_obj_t *banner_lbl    = nullptr;
// What the strip is currently showing, so an unchanged finding costs a compare
// instead of rebuilding a label 200 times a second.
static DiagCode  shown         = DIAG_NONE;

static void bannerClickedCb(lv_event_t *e) {
  (void)e;
  // Opening a modal from here is safe - it creates objects, it does not delete
  // the one the event belongs to. Everything the popup's own buttons do is
  // deferred, which is where that rule actually bites.
  showDiagPopup(diagnosticsCurrent());
}

void diagBannerInit(lv_obj_t *status_bar) {
  banner_parent = status_bar;
  banner        = nullptr;
  banner_lbl    = nullptr;
  shown         = DIAG_NONE;
}

static void buildBanner() {
  banner = lv_obj_create(banner_parent);
  // Fills the status bar exactly, so the line underneath is covered rather
  // than crowded.
  lv_obj_set_size(banner, 480, 22);
  lv_obj_set_pos(banner, 0, 0);
  lv_obj_set_style_bg_color(banner, lv_color_hex(0x3a1410), 0);
  lv_obj_set_style_bg_color(banner, lv_color_hex(0x5a2418), LV_STATE_PRESSED);
  lv_obj_set_style_bg_opa(banner, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(banner, 0, 0);
  lv_obj_set_style_radius(banner, 0, 0);
  lv_obj_set_style_shadow_width(banner, 0, 0);
  lv_obj_set_style_pad_all(banner, 0, 0);
  lv_obj_clear_flag(banner, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_flag(banner, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_event_cb(banner, bannerClickedCb, LV_EVENT_CLICKED, NULL);

  banner_lbl = lv_label_create(banner);
  lv_label_set_text(banner_lbl, "");
  lv_obj_set_style_text_color(banner_lbl, lv_color_hex(0xffb0a0), 0);
  lv_obj_set_style_text_font(banner_lbl, &lv_font_montserrat_ext_14, 0);
  lv_obj_align(banner_lbl, LV_ALIGN_LEFT_MID, 8, 0);
  // Bounded like every other label in this row. A long translation has to run
  // out of room rather than off the panel.
  lv_label_set_long_mode(banner_lbl, LV_LABEL_LONG_DOT);
  lv_obj_set_width(banner_lbl, 464);
}

void updateDiagBanner() {
  if (!banner_parent) return;

  const DiagCode c = diagnosticsCurrent();
  if (c == shown) return;
  shown = c;

  if (c == DIAG_NONE) {
    // Handed back to the pool rather than hidden. On this device the
    // difference is not theoretical - see the note in the header.
    if (banner) { lv_obj_del(banner); banner = nullptr; banner_lbl = nullptr; }
    return;
  }

  if (!banner) buildBanner();

  // T() hands back a pointer into flash, which LVGL cannot read - it has to be
  // copied into RAM first. Two of them are pasted together here, so the buffer
  // has to hold the longest banner string plus the tap hint.
  char buf[96];
  char tail[32];
  strncpy(buf, T(diagBannerString(c)), sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  strncpy(tail, T(STR_DIAG_TAP), sizeof(tail) - 1);
  tail[sizeof(tail) - 1] = '\0';

  char line[128];
  snprintf(line, sizeof(line), LV_SYMBOL_WARNING "  %s%s", buf, tail);
  lv_label_set_text(banner_lbl, line);
}
