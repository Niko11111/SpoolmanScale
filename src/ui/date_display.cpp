#include "date_display.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <cstring>
#include <time.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/drying_config.h"

static int dryingAlertLevel(const char* last_dried_local);

// ============================================================
//  DATE HELPER
// ============================================================

// ISO date "YYYY-MM-DD" -> local format based on g_date_fmt:
//   0 = DD.MM.YYYY  (German style)
//   1 = YYYY-MM-DD  (ISO)
void isoToLocal(const char* iso, char* out, size_t len) {
  if (strlen(iso) >= 10 && iso[4] == '-' && iso[7] == '-') {
    if (g_date_fmt == 1) {
      // ISO belassen
      snprintf(out, len, "%.10s", iso);
    } else {
      // DD.MM.YYYY
      snprintf(out, len, "%.2s.%.2s.%.4s", iso+8, iso+5, iso);
    }
  } else {
    strncpy(out, iso, len-1);
    out[len-1] = '\0';
  }
}
// Legacy alias so all existing calls continue to work
void isoToDe(const char* iso, char* out, size_t len) { isoToLocal(iso, out, len); }

// Days since a localized date until today
// Supports DD.MM.YYYY (fmt 0) and YYYY-MM-DD (fmt 1)
int daysSince(const char* local_date) {
  if (!local_date || strlen(local_date) < 10) return -1;
  int day, month, year;
  if (g_date_fmt == 1) {
    // YYYY-MM-DD
    if (sscanf(local_date, "%d-%d-%d", &year, &month, &day) != 3) return -1;
  } else {
    // DD.MM.YYYY
    if (sscanf(local_date, "%d.%d.%d", &day, &month, &year) != 3) return -1;
  }
  struct tm ti;
  if (!getLocalTime(&ti)) return -1;
  // Datum als Unix-Timestamp
  struct tm then = {};
  then.tm_mday = day;
  then.tm_mon  = month - 1;
  then.tm_year = year - 1900;
  then.tm_hour = 12; then.tm_min = 0; then.tm_sec = 0;
  time_t t_then = mktime(&then);
  // Heute Mittag
  struct tm today = ti;
  today.tm_hour = 12; today.tm_min = 0; today.tm_sec = 0;
  time_t t_today = mktime(&today);
  if (t_then < 0 || t_today < 0) return -1;
  int days = (int)((t_today - t_then) / 86400);
  return days >= 0 ? days : -1;
}

// Drying date as display string: "DD.MM.YYYY  (N days ago)" or just date
void driedDisplayStr(const char* de_date, char* out, size_t len) {
  if (!de_date || strcmp(de_date, "-") == 0 || strlen(de_date) < 8) {
    strncpy(out, "-", len-1);
    return;
  }
  int days = daysSince(de_date);
  if (days < 0) {
    strncpy(out, de_date, len-1);
  } else if (days == 0) {
    snprintf(out, len, "%s  (%s)", de_date, T(STR_TODAY));
  } else if (days == 1) {
    snprintf(out, len, "%s  (%s)", de_date, T(STR_YESTERDAY));
  } else {
    char rel[32]; snprintf(rel, sizeof(rel), T(STR_DAYS_AGO), days);
    snprintf(out, len, "%s  (%s)", de_date, rel);
  }
}

// Same logic for last used
// ── Ampel: last_dried Label mit Farbe + Symbol setzen ────────
// Ruft driedDisplayStr + dryingAlertLevel auf und setzt Farbe/Symbol.
// lbl_sym darf nullptr sein (kein Symbol-Label).
void applyDriedLabel(lv_obj_t* lbl_val, lv_obj_t* lbl_sym, const char* de_date) {
  if (!lbl_val) return;
  // Text
  char disp[56];
  driedDisplayStr(de_date, disp, sizeof(disp));
  lv_label_set_text(lbl_val, disp);
  // Ampel-Level
  int level = dryingAlertLevel(de_date);
  if (sd_verbose) logSDf("[verbose] applyDriedLabel: date=%s level=%d mode=%d", de_date, level, g_dry_mode);
  uint32_t col;
  if      (level == 2) col = 0xe04040;  // rot
  else if (level == 1) col = 0xf0b838;  // gelb
  else if (level == 0) col = 0x28d49a;  // gruen
  else                 col = 0x5090e0;  // kein Modus / kein Datum -> neutral blau
  lv_obj_set_style_text_color(lbl_val, lv_color_hex(col), 0);
  // Symbol (nur bei Warnung/Alarm)
  if (lbl_sym) {
    if (level == 1 || level == 2) {
      lv_label_set_text(lbl_sym, LV_SYMBOL_WARNING);
      lv_obj_set_style_text_color(lbl_sym, lv_color_hex(col), 0);
      lv_obj_clear_flag(lbl_sym, LV_OBJ_FLAG_HIDDEN);
    } else {
      lv_obj_add_flag(lbl_sym, LV_OBJ_FLAG_HIDDEN);
    }
  }
}

// ============================================================
//  HELPER: Ampel-Level fuer last_dried (0=gruen,1=gelb,2=rot,-1=kein Datum)
// ============================================================
static int dryingAlertLevel(const char* last_dried_local) {
  if (g_dry_mode == 0) return -1;
  if (!last_dried_local || strlen(last_dried_local) < 8 || strcmp(last_dried_local, "-") == 0)
    return -1;
  int days = daysSince(last_dried_local);
  if (sd_verbose) logSDf("[verbose] dryingAlertLevel: date=%s days=%d mode=%d mat=%s", last_dried_local, days, g_dry_mode, sm_material_global);
  if (days < 0) return -1;
  int yellow_thresh = g_dry_man_yellow;
  int red_thresh    = g_dry_man_red;
  if (g_dry_mode == 1) {
    int mat_idx = -1;
    for (int i = 0; i < DRY_MAT_COUNT; i++) {
      if (strncasecmp(sm_material_global, DRY_MAT_NAMES[i], strlen(DRY_MAT_NAMES[i])) == 0) {
        mat_idx = i; break;
      }
    }
    if (mat_idx >= 0) {
      float mult = g_dry_mat_sealed[mat_idx] ? g_dry_mult_sealed : 1.0f;
      yellow_thresh = (int)(g_dry_mat_yellow[mat_idx] * mult);
      red_thresh    = (int)(g_dry_mat_red[mat_idx]    * mult);
    } else {
      // Unbekanntes Material im Material-Mode -> kein Signal
      if (sd_verbose) logSDf("[verbose] dryingAlertLevel: material '%s' not in list -> no alert", sm_material_global);
      return -1;
    }
  }
  if (days >= red_thresh)    return 2;
  if (days >= yellow_thresh) return 1;
  return 0;
}
