#pragma once

void updateHeaderStatus();

// Packs the header chips right to left with one gap each. Call after any
// change to their texts - updateHeaderStatus() does it itself.
void layoutHeaderChips();
