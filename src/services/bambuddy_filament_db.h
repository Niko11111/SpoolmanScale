#pragma once

#include <stddef.h>

#include "tag_create.h"

// ============================================================
//  BAMBUDDY: ITS COLOUR CATALOG FOR THE PICKER
//
//  Fills services/filament_db.h from BamBuddy's own inventory, which has no
//  filament database but two catalogs: the colours (GET
//  /api/v1/inventory/colors, 638 of 20 makers in one answer of 103 kB,
//  0.05 s) and the empty spools (GET /api/v1/inventory/catalog, 91, 6 kB),
//  measured 09.10.2026. A colour names maker, product ("PLA Matte"), colour
//  and hex - no weight, no temperatures, no article number. So:
//
//  - the product is split into material and product line ("PLA" and
//    "Matte"), the way a BamBuddy spool keeps them;
//  - the empty spool is asked on the screen (ui/db_pick_core_popup.h) from
//    the spool catalog, the one the inventory used last first;
//  - the net weight is the size nearest the reading, as on every card
//    without one; temperatures stay empty, as BamBuddy's own form leaves
//    them, and BamBuddy fills its own when the spool goes into an AMS;
//  - a Bambu Lab colour gets article number, every colour and its names
//    from the Bambu catalog on the scale (tagCreateBambuFromCatalog()).
//
//  The index is small and quick, so it is never kept in flash. Runs on
//  filament_db's task, through backend_api.h only; the input is completed
//  on the loop.
// ============================================================

// The index: every maker and material of the colour catalog, the empty
// spools, and which makers the inventory has. Returns the HTTP code of the
// colours; the other two only cost the order of the lists when they fail.
int bambuddyFdbLoadIndex(const char* base_url, const char* api_key);

// Every colour of one maker and material. Returns the HTTP code.
int bambuddyFdbLoadEntries(const char* base_url, const char* api_key,
                           const char* maker, const char* material);

// What the catalog leaves to the scale, once an entry is picked: the
// product as the card names it, the English colour name BamBuddy keeps,
// and for Bambu Lab what the Bambu catalog knows. Loop task only.
void bambuddyFdbCompleteInput(TagCreateInput* in);

// "PLA Matte" as "PLA" and "Matte", "Pro PLA+" as "PLA+" and "Pro",
// "PETG-HS" as itself and no line. A product without a known material word
// ("HTPLA", "NylonX") is the material as a whole. Pure, for the loader and
// its checks.
void bambuddySplitProduct(const char* product, char* material, size_t material_size,
                          char* line, size_t line_size);
