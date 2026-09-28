#pragma once

#include <stdint.h>

// Keeps the Bambu catalog current without asking GitHub more than once a day.
// The first check comes a few minutes after boot, well after the update
// check; a device without a catalog loads it then. After that one conditional
// request a day: while BambuStudio's file is unchanged GitHub answers 304 with
// no body, and nothing is written. Follows the automatic update check's
// switch - a device told not to look for updates on its own does not do
// this either. From appLoop().
void bambuCatalogSyncTick();

// Starts a conditional check now, for the maintenance route. False when the
// web worker is busy.
bool bambuCatalogSyncNow();

// When the catalog was last compared with GitHub, UTC seconds; 0 never.
uint32_t bambuCatalogLastCheck();
