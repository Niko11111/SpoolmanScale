#pragma once

void buildWifiScreen();
// Builds (if needed), refreshes and shows the WiFi status screen.
void showWifiStatusScreen();
void updateWifiInfo();
// Deletes the screen, its 2 s refresh timer and the row pointers together.
// The one way out: a screen that is only hidden keeps the timer running and
// its objects in the pool for the rest of the session.
void closeWifiInfoScreen();
