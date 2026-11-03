#pragma once

#include "services/backend.h"

// Changing which server the scale talks to, with everything that has to be
// let go of on the way.
//
// This used to be a static function in backend_screen.cpp that did three
// things: set the mode, mark reachability unknown, clear the tag display.
// Everything else was left standing, and most of it was then wrong - an open
// FilaMan link nobody would ever answer, an AMS window left armed on a server
// the scale no longer talks to, a BamBuddy registration heartbeating at a
// stale id, a location cache resolving ids that belong to the instance just
// left, and a row of sm_* globals that clearTagDisplay() does not touch.
//
// It lives in the app layer because the reset spans both sides: services own
// the caches and the sessions, the screens own what is on the panel. A service
// calling into the screens would turn the layering upside down, and the device
// path and the web path both have to take exactly the same steps.
void backendApplyMode(BackendMode mode);

// Changing the address of the current backend. The mode stays, but every
// cache that holds the old server's answers has to go: the FilaMan location
// list is keyed on nothing but a five minute TTL, and a spool given a
// location within that window was PATCHed with an id that belonged to the
// instance just left - HTTP 200, wrong shelf.
void backendApplyHost(const char *host);

// Changing what goes out with a request to Spoolman, from the web page. On a
// service with accounts the address stays and the inventory behind it does
// not: spool 5 of the next account is another spool, and a weight written with
// the old id lands on it. So access that really changed lets go of the same
// things a change of mode does. Saving the same key again changes nothing.
// False when the secret does not fit; nothing is changed then. The screen is
// cleared a loop pass later by backendApplyAccessChange(); the number goes up
// at once, so a request started from here on counts as the new access.
bool backendApplyAuth(uint8_t mode, const char *user, const char *secret);
void backendApplyAccessChange();

// Changing the AMS source beside Spoolman (ams_source.h): a new address, and a
// new key unless key is nullptr. The presence answer belonged to the old one,
// so the way into the AMS view is settled again on the next tick. False when a
// value does not fit; nothing is changed then.
bool backendApplyAmsSource(const char *host, const char *key);

// Exchanging the active server set for the parked one (services/server_sets.h):
// every address and credential at once, the mode stays. Lets go of the same
// things a change of mode does, because every server the scale talked to is
// left behind. False when NVS refused part of the swap.
bool backendApplySetSwap();

// Counts every switch of mode or host. Work that runs on another task takes
// it at the start, and a result that comes back under a different number is
// about a server the scale no longer talks to: it is dropped, never shown and
// never put into a cache.
uint32_t backendGeneration();
