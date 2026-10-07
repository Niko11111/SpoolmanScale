#include "dried_migrate.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend_api.h"
#include "services/dried_marker.h"
#include "services/user_options.h"

#define DRIED_MIGRATE_TIMEOUT_MS  4000
// Spools already tried in this session, so a move the server refuses, or a
// Spoolman with nothing to copy, costs its requests once and not per scan.
#define DRIED_MIGRATE_TRIED_MAX   8

static bool s_pending  = false;
static int  s_spool_id = 0;
static int  s_tried[DRIED_MIGRATE_TRIED_MAX] = {};
static uint8_t s_tried_next = 0;

static bool alreadyTried(int spool_id) {
  for (int id : s_tried)
    if (id == spool_id) return true;
  return false;
}

void driedMigrateNote(JsonObjectConst spool) {
  if (!backendHasNativeLastDried()) return;
  const int spool_id = spool["id"] | 0;
  if (spool_id <= 0 || alreadyTried(spool_id)) return;

  // The note arrives as Spoolman's "comment", whichever inventory BamBuddy
  // keeps. Spoolman's extra.last_dried only matters to someone who sent the
  // date there, and only while BamBuddy showed nothing for this spool.
  char day[DRIED_MARKER_DAY_MAX];
  const bool marker = driedMarkerParse(spool["comment"] | "", day, sizeof(day));
  const bool side   = g_bb_dried_target == BB_DRIED_SPOOLMAN &&
                      spool["extra"]["last_dried"].isNull();
  if (!marker && !side) return;

  s_pending  = true;
  s_spool_id = spool_id;
}

void driedMigrateTick() {
  if (!s_pending || !wifi_ok) return;
  s_pending = false;
  s_tried[s_tried_next] = s_spool_id;
  s_tried_next = (s_tried_next + 1) % DRIED_MIGRATE_TRIED_MAX;

  const int code = backendMigrateLastDried(s_spool_id, DRIED_MIGRATE_TIMEOUT_MS);
  if (code != 0) logSDf("Dried: move for spool %d, HTTP %d", s_spool_id, code);
}
