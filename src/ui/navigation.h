#pragma once

void hideAllOverlays();
void showMainScreen();
void showSettingsScreen();
// The three OTA screens go together, and two of them carry labels written from
// outside - the web upload and the parked GitHub check - that have to go with
// the screen. Every delete of the three goes through here.
void deleteOtaScreens();
