#pragma once

// The networks the scale remembers (services/wifi_known.h): one row each,
// and a tap asks whether to connect to it or forget it. Reached from the
// WiFi menu.

void showWifiSavedScreen();
// Released, not hidden: it is built anew on every visit. Safe from a
// callback, the delete is asynchronous. From hideAllOverlays().
void hideWifiSavedScreen();
// Carries out a "Forget" the popup parked. From appLoop().
void wifiSavedScreenTick();
