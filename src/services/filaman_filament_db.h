#pragma once

#include <stddef.h>

#include "tag_create.h"

// ============================================================
//  FILAMAN: THE FILAMENTDB FOR THE PICKER
//
//  Fills services/filament_db.h from FilaMan's proxy of the FilamentDB
//  (db.filaman.app), which an active "filamentdb_import" plugin opens. The
//  proxy lists makers (311 with filaments, 100 a page) and a maker's
//  filaments, but no maker's materials: those come from reading the maker's
//  filaments once (SUNLU, the most: 979 in 10 pages, 09.10.2026). Runs on
//  filament_db's task, through backend_api.h only.
//
//  What a new filament needs beyond the entry - the maker's id, slug and
//  logos in the FilamentDB, a material's key - stays here, for the create
//  path in filaman_filament.cpp to ask once an entry is picked.
// ============================================================

// The index: every maker the FilamentDB has filaments by, and which ones the
// inventory has. 404 when the plugin is not active. Returns the HTTP code.
int filamanFdbLoadIndex(const char* base_url, const char* api_key);

// The materials of one maker, 1.75 mm. Returns the HTTP code.
int filamanFdbLoadPairs(const char* base_url, const char* api_key, const char* maker);

// Every entry of one maker and material, 1.75 mm. Returns the HTTP code.
int filamanFdbLoadEntries(const char* base_url, const char* api_key,
                          const char* maker, const char* material);

// What the FilamentDB says about a maker, for prepare-filament: it fetches
// the logos by slug when it creates the maker. False when the index does not
// hold the maker.
struct FmFdbMakerInfo {
  char slug[32];
  bool web_logo;
  bool label_logo;
};
bool filamanFdbMakerInfo(const char* maker, FmFdbMakerInfo* out);

// The FilamentDB's key of a material the picker names ("PLA+/Pro" is
// "pla-plus"). False when no maker's materials named it yet.
bool filamanFdbMaterialKey(const char* material, char* out, size_t out_size);

// The FilamentDB entry of a tag's filament, found by its article number in
// brackets ("Cyan (12601)", how the FilamentDB names Bambu colours) among
// the maker's filaments. Of two entries for one article (the FilamentDB has
// Tough+ Cyan once as PLA, once as PLA+), the one of the tag's material.
// False when there is none, or the proxy could not be asked. On the loop,
// for the plan; one request.
bool filamanFdbFindForTag(const char* base_url, const char* api_key, const TagCreateInput& in,
                          TagDbEntry* out);
