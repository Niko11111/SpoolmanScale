#include "drying_sync.h"

#include <Arduino.h>
#include <stdlib.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/tag_spool_match.h"

#define DRYING_TEXT_MAX       24
#define DRYING_WRITE_TIMEOUT  4000
// The same plausibility the tag decoder applies.
#define DRYING_TEMP_MIN_C     30
#define DRYING_TEMP_MAX_C     120
#define DRYING_HOURS_MAX      48

static bool s_pending     = false;
static int  s_filament_id = 0;
static int  s_spool_id    = 0;
static char s_value[DRYING_TEXT_MAX] = "";
// What was last tried, so a write the server refuses is not sent again with
// every scan of the same spool.
static int  s_tried_id    = -1;
static char s_tried_value[DRYING_TEXT_MAX] = "";

void dryingFormat(int temp_c, int hours, char* out, size_t n) {
  snprintf(out, n, "%d °C, %d h", temp_c, hours);
}

bool dryingParse(const char* text, int* temp_c, int* hours) {
  if (!text) return false;
  int vals[2];
  int found = 0;
  for (const char* p = text; *p && found < 2; ) {
    if (*p >= '0' && *p <= '9') {
      char* end = nullptr;
      vals[found++] = (int)strtol(p, &end, 10);
      p = end;
    } else {
      p++;
    }
  }
  if (found < 2) return false;
  if (vals[0] < DRYING_TEMP_MIN_C || vals[0] > DRYING_TEMP_MAX_C) return false;
  if (vals[1] < 1 || vals[1] > DRYING_HOURS_MAX) return false;
  if (temp_c) *temp_c = vals[0];
  if (hours)  *hours  = vals[1];
  return true;
}

// Whether a stored drying value says anything at all. Spaces and the quotes
// Spoolman wraps a text extra in do not count; any other character does,
// also in a value the parse below cannot read ("no drying needed", "65 °C").
static bool dryingFieldHasText(const char* text) {
  for (const char* p = text; p && *p; p++)
    if (*p != ' ' && *p != '"') return true;
  return false;
}

void dryingSyncNote(JsonObjectConst spool) {
  // A Bambu tag that said something about drying. The tray UUID is cleared
  // whenever another kind of tag is read, the drying values are not, so it
  // is what keeps an old Bambu reading off an NTAG's spool.
  if (!g_tag.tray_uuid[0] || g_tag.dry_temp_c <= 0 || g_tag.dry_hours <= 0) return;
  // A tag linked to the wrong spool would hand its advice to a filament it
  // does not describe. The lookup has judged the pair just before this.
  if (tagSpoolLookupDiffers()) return;

  const bool bambuddy = backendIsBamBuddy();
  const int filament_id = spool["filament"]["id"] | 0;
  const int spool_id    = spool["id"] | 0;
  const int key = bambuddy ? spool_id : filament_id;
  if (key <= 0) return;

  // Only an empty field is filled. A value already there stays, also one
  // that differs from the tag or that the scale cannot read: somebody may
  // have put their own drying in.
  const char* have = spool["filament"]["extra"]["drying"] | (const char*)nullptr;
  if (!have) have = spool["extra"]["drying"] | "";
  if (dryingFieldHasText(have)) return;

  char want[DRYING_TEXT_MAX];
  dryingFormat(g_tag.dry_temp_c, g_tag.dry_hours, want, sizeof(want));
  if (key == s_tried_id && strcmp(want, s_tried_value) == 0) return;

  s_pending     = true;
  s_filament_id = filament_id;
  s_spool_id    = spool_id;
  snprintf(s_value, sizeof(s_value), "%s", want);
}

void dryingSyncTick() {
  if (!s_pending || !wifi_ok) return;
  s_pending = false;
  s_tried_id = backendIsBamBuddy() ? s_spool_id : s_filament_id;
  snprintf(s_tried_value, sizeof(s_tried_value), "%s", s_value);
  const int code = backendPatchFilamentDrying(s_filament_id, s_spool_id, s_value,
                                              DRYING_WRITE_TIMEOUT);
  logSDf("Drying: '%s' for filament %d / spool %d, HTTP %d",
         s_value, s_filament_id, s_spool_id, code);
}
