#include "dried_action.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <cstring>
#include <time.h>

#include "date_display.h"
#include "hardware/sd_logger.h"
#include "services/backend_api.h"
#include "lang.h"


void btn_dried_cb(lv_event_t *e) {
  logSD("UI: Button -> Dried Today");
  if (!wifi_ok) {
    lv_label_set_text(lbl_spoolman_dried_val, "No WiFi!");
    return;
  }
  if (!sm_found || sm_id == 0) {
    lv_label_set_text(lbl_spoolman_dried_val, T(STR_WAIT_SCAN));
    return;
  }

  struct tm ti;
  char iso_full_buf[32] = "2026-01-01T00:00:00.000Z";
  if (getLocalTime(&ti)) {
    time_t now = mktime(&ti);
    struct tm *utc = gmtime(&now);
    snprintf(iso_full_buf, sizeof(iso_full_buf), "%04d-%02d-%02dT%02d:%02d:%02d.000Z",
      utc->tm_year+1900, utc->tm_mon+1, utc->tm_mday,
      utc->tm_hour, utc->tm_min, utc->tm_sec);
  }
  String iso_full = String(iso_full_buf);
  String today = iso_full.substring(0, 10);

  Serial.printf("Setting last_dried: %s for spool ID %d\n", iso_full.c_str(), sm_id);

  int code = backendPatchSpoolLastDried(cfg_spoolman_base, sm_id, iso_full.c_str());

  if (code == 200) {
    char de_date[12];
    isoToDe(today.c_str(), de_date, sizeof(de_date));
    strncpy(sm_last_dried, de_date, sizeof(sm_last_dried)-1);
    applyDriedLabel(lbl_spoolman_dried_val, lbl_dried_sym, de_date);
    Serial.println("last_dried set!");
  } else {
    Serial.printf("PATCH error: %d\n", code);
    lv_label_set_text(lbl_spoolman_dried_val, T(STR_ERR_SAVE));
  }
}
