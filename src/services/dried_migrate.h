#pragma once

#include <ArduinoJson.h>

// ============================================================
//  MOVING OLD DRYING DATES INTO BAMBUDDY'S OWN FIELD
//
//  Before BamBuddy kept a drying date (#2863), the scale put it in the
//  spool's note as "[last_dried:YYYY-MM-DD]", or past BamBuddy into
//  Spoolman's extra.last_dried. Once the server has the field, the marker
//  would only age in the note. So after a scan finds such a spool, the date
//  moves into the field and the marker leaves the note, one spool at a time,
//  without asking: only the scale writes that marker, and nothing is lost.
//  Spoolman's extra.last_dried is copied, never cleared.
// ============================================================

// After a lookup has the spool, on the loop task. Only parks the move.
void driedMigrateNote(JsonObjectConst spool);

// From appLoop(): carries a parked move out.
void driedMigrateTick();
