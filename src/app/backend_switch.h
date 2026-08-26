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
