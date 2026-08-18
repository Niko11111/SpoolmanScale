#pragma once

// ============================================================
//  REMOTE LINK STATE
//
//  FilaMan can ask the scale to link the tag that is on it to a
//  spool the user picked in the web UI. The trigger arrives as
//  POST /api/v1/rfid/write on the built in web server.
//
//  Nothing is ever written to the tag. The trigger is only taken
//  as "the next spool on the scale belongs to this id", and the
//  answer goes back through /api/v1/devices/rfid-result, which
//  makes FilaMan set rfid_uid itself.
//
//  The web handler must return within the five seconds FilaMan
//  waits, so it only parks an id here. Everything else happens in
//  appLoop().
// ============================================================

// Called from the web server handler. Replaces any request that is
// still open: the newer one is what the user just clicked.
void remoteLinkSetPending(int spool_id);

// True while a request is waiting for a tag and has not timed out.
bool remoteLinkPendingActive();

// True when a tag was already on the scale the moment the trigger arrived,
// meaning the user placed the spool first and clicked afterwards. That order
// is what makes the intent unambiguous, so it is the only case the automatic
// link is allowed to act on.
bool remoteLinkTagWasPresent();

int  remoteLinkPendingSpoolId();

// Milliseconds since the request came in. Undefined when none is active.
unsigned long remoteLinkPendingAgeMs();

// Forgets the request without telling FilaMan. Only for the paths that
// report the outcome themselves.
void remoteLinkClear();

// Reports the outcome and clears the request. Safe to call when nothing
// is pending, it then does nothing. Does HTTP, so never call it from an
// LVGL event callback or the web handler.
//
// tag_uuid is what FilaMan writes into rfid_uid, so it has to be the UID
// that was really read. It may be null on a failure report, the server
// only insists on it when success is true.
void remoteLinkReport(bool ok, const char* tag_uuid, const char* error_message);

// Set when a trigger carried only a location_id. Locations are a FilaMan
// concept the scale does not handle yet, and the request has to be turned
// down through rfid-result rather than ignored, or the web UI keeps
// polling until its own timeout.
extern bool remote_link_reject_pending;

// Turns down a trigger the scale cannot serve, with no pending request
// behind it. Does HTTP, same caller restrictions as remoteLinkReport().
void remoteLinkReportUnsupported(const char* error_message);
