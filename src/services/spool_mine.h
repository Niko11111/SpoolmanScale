#pragma once

#include "services/spool_choice.h"

// The user's own empty spools, kept on the scale whatever the backend: up to
// SPOOL_MINE_MAX, edited on the web page "Empty spools" (page_spools.cpp),
// offered under a card's Options. One NVS string, a line per spool
// (spoolMineEncode()).

// Reads them; returns how many there are.
int spoolMineLoad(SpoolChoice out[SPOOL_MINE_MAX]);
// Replaces them all; none removes the key. False when NVS refused.
bool spoolMineSave(const SpoolChoice* list, int n);
