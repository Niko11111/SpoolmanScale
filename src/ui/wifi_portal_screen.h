#pragma once

// "Set up WiFi by phone": the two QR codes for the setup portal and its status.
//
// The access point exists only while this screen is on display. Opening it
// queues the scan and the start for the loop; anything that takes the screen
// away - back, close, a finished connect, Improv - also takes the access point
// down, checked by handleWifiPortalDeferredActions() on every pass.
void showWifiPortalScreen();

// Deletes the screen and drops the label pointer the loop writes. Does not
// stop the portal itself; the next loop pass does, once it sees the screen gone.
void closeWifiPortalScreen();

// Start, stop and hand-off of the portal. From appLoop().
void handleWifiPortalDeferredActions();
