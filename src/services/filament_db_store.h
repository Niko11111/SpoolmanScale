#pragma once

// ============================================================
//  THE FILAMENT DATABASE INDEX, KEPT IN FLASH
//
//  The index (filament_db.h) is boiled down from the whole database: 3 MB
//  read for about 20 kB of makers and materials, 11.5 s on the scale
//  (08.10.2026). In PSRAM it is lost with every restart, and a restart is
//  every update. So the last one is kept in the data partition, behind the
//  Bambu catalog, for a week and for the server it came from.
//
//  A week, because the index only says which makers and materials exist.
//  Spoolman takes SpoolmanDB in once an hour, but it changes when somebody
//  adds to it on GitHub, a few times a month; and the lists themselves are
//  always read fresh, so a new colour shows at once. Only a new maker or a
//  new material of one waits for the week to end.
//
//  Both calls run on the filament database's task, never on the loop.
// ============================================================

// Puts the stored index in place, when there is one younger than a week
// from this server and the clock is set. Makers come back unmarked: whose
// spools the inventory has is asked again. False when there is none.
bool fdbStoreLoad(const char* base_url);

// Keeps the index just loaded, for this server. A failure only costs the
// next restart its 3 MB.
void fdbStoreSave(const char* base_url);
