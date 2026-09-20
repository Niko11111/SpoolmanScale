#pragma once

#include <stdint.h>

// ============================================================
//  "NO CONNECTION TO THE SERVER"
//
//  A request that never reached the backend used to end in whatever each
//  flow made of it: "API Error" in green on the weight line, an empty spool
//  list that read like "no spools without a tag", a link or an unlink that
//  looked done. The header badge turned red only on the next health check,
//  up to 30 seconds later, and small enough to miss.
//
//  Every flow that talks to the server hands its HTTP code to
//  serverReachNote(). A code that says the server could not be reached marks
//  it unreachable at once and asks for the popup; the screen takes that
//  request from the loop, where building an overlay is allowed. This module
//  itself never touches LVGL.
//
//  How often the popup comes (Nikolai, 19.09.2026): every time for something
//  the user set off, once per outage for the lookup behind a tag placement -
//  otherwise a longer outage would put it up for every spool laid down.
// ============================================================

// Whether an HTTP code is the client's own for a server it could not reach or
// that stopped answering. -2 stays out: several backend calls use it for a
// parse error too, and naming the connection for that would send the user to
// the wrong place.
bool serverReachIsNetworkFailure(int code);

// Passes `code` through unchanged, so it wraps a request in place:
//     int code = serverReachNote(backendX(...), true);
// `user_action`: false only for the lookup a tag placement starts on its own.
int serverReachNote(int code, bool user_action);

// From the health check when the server answers again: the next outage gets
// its placement popup again.
void serverReachRestored();

// For the screen, from the loop. True once per request for the popup.
bool serverReachPopupTake();
