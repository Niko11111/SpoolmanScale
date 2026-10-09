#pragma once

#include <stdint.h>

#include "tag_create.h"

// ============================================================
//  FILAMAN: THE FILAMENT FOR A TAG
//
//  Finds the filament a tag describes among the vendor's filaments of
//  that material, and creates it (with its vendor and colour) when the
//  inventory has none. FilaMan's own resolve-from-tag is not used: without a
//  colour match it falls back to the first filament of the same material,
//  which would put a cyan spool under a black filament.
//
//  A new filament is written the way FilaMan's FilamentDB import writes
//  them ("Tough Plus - Cyan (12601)", subgroup "tough-plus"), so it sits
//  among imported ones and the next lookup finds it by its article number.
//  An entry picked from the FilamentDB (in.db_id set) is looked up by the
//  id that import keeps in custom_fields.filamentdb_id, and created through
//  FilaMan's prepare-filament, as its own form does it.
//  Called through backend_api.h only.
// ============================================================

// Reads only: TFS_FOUND, TFS_CREATE_TAG, TFS_CREATE_DB, TFS_NEEDS_CATALOG or
// TFS_FAILED.
void filamanPlanTagFilament(const char* base_url, const char* api_key,
                            const TagCreateInput& in, TagFilamentPlan* plan);

// Creates the vendor when plan has none, the colour when FilaMan has none,
// then the filament. Returns 200 or the failing request's code.
int filamanCreateTagFilament(const char* base_url, const char* api_key,
                             const TagCreateInput& in, const TagFilamentPlan& plan,
                             int* out_filament_id);
