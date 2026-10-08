#pragma once

// ============================================================
//  SPOOLMAN: SPOOLMANDB FOR THE PICKER
//
//  Fills services/filament_db.h from Spoolman's copy of SpoolmanDB. Spoolman
//  has no list of makers or materials, only the whole database (3 MB,
//  8120 filaments on 0.27.0) and a word search that answers 100 at a time.
//  So the index reads the whole database once, element by element, and
//  keeps only maker and material; a maker's list is a search for maker and
//  material, filtered to exactly those. Runs on filament_db's task, through
//  backend_api.h only.
// ============================================================

// Index: every maker and material of 1.75 mm, and which makers the inventory
// has. Returns the HTTP code.
int spoolmanFdbLoadIndex(const char* base_url);

// Every entry of one maker and material, 1.75 mm. Returns the HTTP code.
int spoolmanFdbLoadEntries(const char* base_url, const char* maker, const char* material);
