#include "drying_sync.h"

#include <Arduino.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/json_util.h"
#include "services/tag_spool_match.h"

#define DRYING_TEXT_MAX       24
#define DRYING_WRITE_TIMEOUT  4000
static bool s_pending     = false;
static int  s_filament_id = 0;
static int  s_spool_id    = 0;
static char s_value[DRYING_TEXT_MAX] = "";
// FilaMan 2.0: the two native fields instead of the text.
static bool s_native      = false;
static DryingFill s_fill  = {};
// What was last tried, so a write the server refuses is not sent again with
// every scan of the same spool.
static int  s_tried_id    = -1;
static char s_tried_value[DRYING_TEXT_MAX] = "";

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
  const bool has_text = dryingFieldHasText(have);
  JsonObjectConst native = spool["filament"][DRYING_NATIVE_KEY];
  if (has_text && native.isNull()) return;

  // FilaMan 2.0 shows only its two fields, so a text an earlier scan left stays
  // invisible there: it moves over, and stays as well for a server rolled back.
  DryingFill fill = {};
  if (!native.isNull()) {
    const bool has_temp  = jsonHasKey(native, DRYING_NATIVE_TEMP);
    const bool has_hours = jsonHasKey(native, DRYING_NATIVE_HOURS);
    fill = has_text ? dryingFillFromText(has_temp, has_hours, have)
                    : dryingFillEmpty(has_temp, has_hours, g_tag.dry_temp_c, g_tag.dry_hours);
    if (fill.temp_c <= 0 && fill.hours <= 0) return;
  }

  char want[DRYING_TEXT_MAX];
  if (has_text) snprintf(want, sizeof(want), "%s", have);
  else          dryingFormat(g_tag.dry_temp_c, g_tag.dry_hours, want, sizeof(want));
  if (key == s_tried_id && strcmp(want, s_tried_value) == 0) return;

  s_pending     = true;
  s_filament_id = filament_id;
  s_spool_id    = spool_id;
  snprintf(s_value, sizeof(s_value), "%s", want);
  s_native = !native.isNull();
  s_fill   = fill;
}

void dryingSyncTick() {
  if (!s_pending || !wifi_ok) return;
  s_pending = false;
  s_tried_id = backendIsBamBuddy() ? s_spool_id : s_filament_id;
  snprintf(s_tried_value, sizeof(s_tried_value), "%s", s_value);
  const int code = s_native
      ? backendPatchFilamentDryingNative(s_filament_id, s_fill, DRYING_WRITE_TIMEOUT)
      : backendPatchFilamentDrying(s_filament_id, s_spool_id, s_value, DRYING_WRITE_TIMEOUT);
  logSDf("Drying: '%s' for filament %d / spool %d, %s, HTTP %d",
         s_value, s_filament_id, s_spool_id, s_native ? "native" : "text", code);
}
