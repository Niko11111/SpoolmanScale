#pragma once

#include <stdint.h>

// ============================================================
//  ROAMING WHILE NOBODY IS USING THE SCALE
//
//  The station stays on its access point until the link breaks, and a scale
//  does not move, so on a network with several access points it can sit on
//  a weak one for good: a nearby one restarts, the scale falls back to one at
//  the far end of the house, and nothing ever makes it come back.
//
//  This looks for a better one, but only when that cannot get in anyone's
//  way. A scan while connected stalls the link for a second or two, and a
//  switch drops it for a few, so every condition below errs on the side of
//  not looking at all:
//  - The caller says the device is quiet: display dimmed or dark for a
//    while, no browser on the web interface, no job, flash or setup screen
//    running. See the call in appLoop().
//  - The signal has been weak for WIFI_ROAM_WEAK_HOLD_MS. A good link is
//    never scanned away from.
//  - At most every WIFI_ROAM_INTERVAL_MS, and once a scan found no second
//    access point on the SSID, every WIFI_ROAM_LONE_INTERVAL_MS. A home
//    with a single router scans a few times a day at most.
//  - A switch only for WIFI_ROAM_MARGIN_DB more, so two access points of
//    about the same strength cannot trade the scale back and forth.
//
//  If the switch fails, the reconnect watchdog takes over as after any lost
//  link, with a full scan that joins the strongest access point there is.
// ============================================================

// From appLoop(), every pass. quiet: the caller's verdict that nobody is
// using the device right now. Cheap when there is nothing to do.
void wifiRoamTick(bool quiet, const char* ssid, const char* password);

// True while a switch is under way. The reconnect watchdog holds off: its own
// begin() would cancel the association to the chosen access point.
bool wifiRoamSwitching();
