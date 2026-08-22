#include "spoolman_actions.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <string.h>
#include <time.h>

#include "app_config.h"
#include "app/deferred_actions.h"
#include "backend.h"
#include "backend_api.h"
#include "bambuddy_api.h"
#include "hardware/sd_logger.h"
#include "user_options.h"
#include "ui/date_display.h"
#include "lang.h"
#include "services/backend.h"
#include "ui/main_screen_helpers.h"




void patchSpoolmanWeight(float remaining, bool skip_cap_check) {
  if (!wifi_ok) { Serial.println("patchSpoolmanWeight: no WiFi"); return; }
  if (!sm_found || sm_id == 0) { Serial.println("patchSpoolmanWeight: no spool"); return; }

  // BamBuddy's own inventory stores what was consumed and derives the rest
  // from the label weight, so it cannot represent a spool holding more than
  // the label says - the value would read as full again on the next scan.
  // Ask rather than let that happen silently. Behind Spoolman the remaining
  // weight is stored directly and there is no ceiling.
  // The tolerance keeps rounding noise on a genuinely full spool from asking.
  if (!skip_cap_check && backendIsBamBuddy() && bbInventoryMode() == BB_INV_LOCAL &&
      sm_total > 0.0f && remaining > sm_total + BB_CAP_TOLERANCE_G) {
    bb_cap_measured_g = remaining;
    bb_cap_label_g    = sm_total;
    show_bb_cap_pending = true;      // the popup is built from appLoop()
    logSDf("BamBuddy: %.0fg measured against a %.0fg label, asking first",
           remaining, sm_total);
    return;
  }

  char today[12] = "";
  if (last_used_mode == 1) {
    time_t now = time(nullptr);
    struct tm* t = localtime(&now);
    snprintf(today, sizeof(today), "%04d-%02d-%02d", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
  }
  Serial.printf("PATCH weight: %.1fg\n", remaining);
  // FilaMan wants the gross weight and subtracts the empty spool weight
  // itself. The callers computed remaining as scale minus sm_spool_weight,
  // so adding it back gives exactly what the scale showed.
  float measured = remaining + sm_spool_weight;
  int code = backendPatchSpoolRemaining(cfg_spoolman_base, sm_id, remaining,
                                        today[0] ? today : nullptr, nullptr, measured);
  logSDf("PATCH weight=%.1fg ID=%d HTTP %d", remaining, sm_id, code);
  if (code == 200) {
    sm_remaining = remaining;
    char w_str[16];
    snprintf(w_str, sizeof(w_str), "%.0f g", sm_remaining);
    lv_label_set_text(lbl_spoolman_weight, w_str);
    float pct = (sm_total > 0) ? (sm_remaining / sm_total * 100.0f) : 0;
    char p_str[16];
    snprintf(p_str, sizeof(p_str), "%.1f %%", pct);
    lv_label_set_text(lbl_spoolman_pct, p_str);
    if (last_used_mode == 1 && lbl_last_used) {
      char today_iso[12];
      time_t now = time(nullptr);
      struct tm* t = localtime(&now);
      snprintf(today_iso, sizeof(today_iso), "%04d-%02d-%02d", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
      char today_local[12];
      isoToDe(today_iso, today_local, sizeof(today_local));
      strncpy(sm_last_used, today_local, sizeof(sm_last_used) - 1);
      sm_last_used[sizeof(sm_last_used)-1] = '\0';
      char disp[48];
      driedDisplayStr(today_local, disp, sizeof(disp));
      lv_label_set_text(lbl_last_used, disp);
    }
    Serial.printf("OK: %.1fg saved\n", remaining);
  } else {
    Serial.printf("PATCH error: %d\n", code);
  }
}

void patchArchiveSpool() {
  if (!wifi_ok) { Serial.println("patchArchiveSpool: no WiFi"); return; }
  if (!sm_found || sm_id == 0) { Serial.println("patchArchiveSpool: no spool"); return; }
  Serial.printf("PATCH archive: spool ID %d\n", sm_id);
  int code = backendPatchArchiveSpool(cfg_spoolman_base, sm_id);
  logSDf("PATCH archive ID=%d HTTP %d", sm_id, code);
  if (code != 200) {
    Serial.printf("PATCH archive error: %d\n", code);
    lv_label_set_text(lbl_spoolman_weight, T(STR_ERR_SAVE));
    return;
  }

  Serial.println("Spool archived!");
  sm_remaining = 0;

  // Show the archived state straight away. Without this the labels kept the
  // values from before and only caught up when the tag was scanned again.
  // Mirrors what the scan path shows for an archived spool, so both routes
  // end up looking the same.
  char arch_buf[32];
  backendText(T(STR_ARCHIVED), arch_buf, sizeof(arch_buf));
  lv_label_set_text(lbl_spoolman_weight, arch_buf);
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x808080), 0);
  lv_label_set_text(lbl_spoolman_pct, "");
  lv_label_set_text(lbl_spoolman_dried_val, "-");
  if (lbl_dried_sym) lv_obj_add_flag(lbl_dried_sym, LV_OBJ_FLAG_HIDDEN);
  lv_label_set_text(lbl_last_used, "-");
  lv_label_set_text(lbl_detail, "-");
  lv_label_set_text(lbl_filament_name, "-");
  if (lbl_scale_diff)      lv_obj_set_width(lbl_scale_diff, 0);
  if (lbl_spoolman_dried)  lv_label_set_text(lbl_spoolman_dried, "");
  if (lbl_keys)            lv_label_set_text(lbl_keys, "");

  // The spool is out of the active inventory, so a further weight update or
  // dried action would target something that is no longer there.
  sm_found = false;
  updateLinkButton();
}

void patchSpoolTag(int spool_id, const char* uuid) {
  if (!wifi_ok) return;
  const bool clearing = (!uuid || !uuid[0]);
  Serial.printf("PATCH tag: '%s'%s\n", uuid ? uuid : "", clearing ? "  (UNLINK)" : "");
  int code = backendPatchSpoolTag(cfg_spoolman_base, spool_id, uuid);
  Serial.printf("patchSpoolTag: HTTP %d\n", code);
  // The uuid is part of the log line on purpose. An empty one is a valid
  // unlink and a silent disaster for a link, and the old line could not tell
  // the two apart afterwards.
  logSDf("PATCH tag ID=%d uuid='%s'%s HTTP %d",
         spool_id, uuid ? uuid : "", clearing ? " UNLINK" : "", code);
}

void patchInitialWeight(float initial_w) {
  if (!wifi_ok) { Serial.println("patchInitialWeight: kein WiFi"); return; }
  if (!sm_found || sm_id == 0) { Serial.println("patchInitialWeight: keine Spule"); return; }
  Serial.printf("PATCH initial_weight: %.1fg\n", initial_w);
  int code = backendPatchInitialWeight(cfg_spoolman_base, sm_id, initial_w);
  if (code == 200) {
    sm_remaining = initial_w;
    sm_total = initial_w;
    Serial.printf("initial_weight OK: %.1fg\n", initial_w);
  } else {
    Serial.printf("PATCH initial_weight Fehler: %d\n", code);
  }
}

void patchSpoolWeight(float spool_w) {
  if (!wifi_ok) { Serial.println("patchSpoolWeight: no WiFi"); return; }
  if (!sm_found || sm_id == 0) { Serial.println("patchSpoolWeight: no spool"); return; }
  Serial.printf("PATCH spool_weight: %.1fg\n", spool_w);
  int code = backendPatchSpoolWeight(cfg_spoolman_base, sm_id, spool_w);
  logSDf("PATCH spool_weight=%.1fg ID=%d HTTP %d", spool_w, sm_id, code);
  if (code == 200) {
    sm_spool_weight = spool_w;
    // The value now comes from this spool, so drop any inherited source.
    // Without this the details screen keeps claiming "(filament)" over a
    // number that was just measured here.
    sm_tare_source = TARE_SPOOL;
    Serial.printf("spool_weight OK: %.1fg\n", spool_w);
  } else {
    Serial.printf("PATCH spool_weight Fehler: %d\n", code);
  }
}

void patchFilamentSpoolWeight(float spool_w) {
  if (!wifi_ok) return;
  if (sm_filament_id == 0) { Serial.println("patchFilamentSpoolWeight: keine filament_id"); return; }
  Serial.printf("PATCH filament spool_weight: ID=%d %.1fg\n", sm_filament_id, spool_w);
  int code = backendPatchFilamentSpoolWeight(cfg_spoolman_base, sm_filament_id, spool_w);
  Serial.printf("patchFilamentSpoolWeight: HTTP %d\n", code);
  logSDf("PATCH filament_spool_weight=%.1fg fil_ID=%d HTTP %d", spool_w, sm_filament_id, code);
}

void patchVendorSpoolWeight(float spool_w) {
  if (!wifi_ok) return;
  if (sm_vendor_id == 0) { Serial.println("patchVendorSpoolWeight: keine vendor_id"); return; }
  Serial.printf("PATCH vendor empty_spool_weight: ID=%d %.1fg\n", sm_vendor_id, spool_w);
  int code = backendPatchVendorEmptySpoolWeight(cfg_spoolman_base, sm_vendor_id, spool_w);
  Serial.printf("patchVendorSpoolWeight: HTTP %d\n", code);
  logSDf("PATCH vendor_empty_spool=%.1fg vendor_ID=%d HTTP %d", spool_w, sm_vendor_id, code);
}
