#include "spoolman_actions.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <string.h>
#include <time.h>

#include "spoolman_api.h"
#include "hardware/sd_logger.h"
#include "user_options.h"
#include "ui/date_display.h"




void patchSpoolmanWeight(float remaining) {
  if (!wifi_ok) { Serial.println("patchSpoolmanWeight: no WiFi"); return; }
  if (!sm_found || sm_id == 0) { Serial.println("patchSpoolmanWeight: no spool"); return; }
  char today[12] = "";
  if (last_used_mode == 1) {
    time_t now = time(nullptr);
    struct tm* t = localtime(&now);
    snprintf(today, sizeof(today), "%04d-%02d-%02d", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
  }
  Serial.printf("PATCH weight: %.1fg\n", remaining);
  int code = spoolmanPatchSpoolRemaining(cfg_spoolman_base, sm_id, remaining, today[0] ? today : nullptr);
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
  int code = spoolmanPatchArchiveSpool(cfg_spoolman_base, sm_id);
  if (code == 200) {
    sm_remaining = 0;
    Serial.println("Spool archived!");
  } else {
    Serial.printf("PATCH archive error: %d\n", code);
  }
}

void patchSpoolTag(int spool_id, const char* uuid) {
  if (!wifi_ok) return;
  Serial.printf("PATCH tag: %s\n", uuid);
  int code = spoolmanPatchSpoolTag(cfg_spoolman_base, spool_id, uuid);
  Serial.printf("patchSpoolTag: HTTP %d\n", code);
  logSDf("PATCH tag ID=%d HTTP %d", spool_id, code);
}

void patchInitialWeight(float initial_w) {
  if (!wifi_ok) { Serial.println("patchInitialWeight: kein WiFi"); return; }
  if (!sm_found || sm_id == 0) { Serial.println("patchInitialWeight: keine Spule"); return; }
  Serial.printf("PATCH initial_weight: %.1fg\n", initial_w);
  int code = spoolmanPatchInitialWeight(cfg_spoolman_base, sm_id, initial_w);
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
  int code = spoolmanPatchSpoolWeight(cfg_spoolman_base, sm_id, spool_w);
  logSDf("PATCH spool_weight=%.1fg ID=%d HTTP %d", spool_w, sm_id, code);
  if (code == 200) {
    sm_spool_weight = spool_w;
    Serial.printf("spool_weight OK: %.1fg\n", spool_w);
  } else {
    Serial.printf("PATCH spool_weight Fehler: %d\n", code);
  }
}

void patchFilamentSpoolWeight(float spool_w) {
  if (!wifi_ok) return;
  if (sm_filament_id == 0) { Serial.println("patchFilamentSpoolWeight: keine filament_id"); return; }
  Serial.printf("PATCH filament spool_weight: ID=%d %.1fg\n", sm_filament_id, spool_w);
  int code = spoolmanPatchFilamentSpoolWeight(cfg_spoolman_base, sm_filament_id, spool_w);
  Serial.printf("patchFilamentSpoolWeight: HTTP %d\n", code);
  logSDf("PATCH filament_spool_weight=%.1fg fil_ID=%d HTTP %d", spool_w, sm_filament_id, code);
}

void patchVendorSpoolWeight(float spool_w) {
  if (!wifi_ok) return;
  if (sm_vendor_id == 0) { Serial.println("patchVendorSpoolWeight: keine vendor_id"); return; }
  Serial.printf("PATCH vendor empty_spool_weight: ID=%d %.1fg\n", sm_vendor_id, spool_w);
  int code = spoolmanPatchVendorEmptySpoolWeight(cfg_spoolman_base, sm_vendor_id, spool_w);
  Serial.printf("patchVendorSpoolWeight: HTTP %d\n", code);
  logSDf("PATCH vendor_empty_spool=%.1fg vendor_ID=%d HTTP %d", spool_w, sm_vendor_id, code);
}
