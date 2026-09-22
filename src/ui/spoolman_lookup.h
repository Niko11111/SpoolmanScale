#pragma once

#include <stdint.h>

// Who asked for a lookup, and so what happens with the verdict: a Bambu tag
// arms the link timer, a tag known by its uid alone (MIFARE, NTAG) also
// becomes the link target or, when found, the tag the spool is bound by.
enum LookupOrigin : uint8_t {
  LOOKUP_FROM_OTHER = 0,   // nothing to follow up
  LOOKUP_FROM_BAMBU,
  LOOKUP_FROM_UID,         // a MIFARE card read by its uid
  LOOKUP_FROM_NTAG
};

// Looks the tag up and paints what the backend knows about it. The cheap
// questions are asked right here; when none of them knows the tag, the whole
// inventory is loaded on the backend worker and the call returns before the
// verdict is in. lookupPending() says which: while it is false the caller
// follows up itself with lookupFollowUp(), otherwise lookupScanTick() does
// once the verdict is in.
void querySpoolman(const char* tray_uuid, LookupOrigin origin = LOOKUP_FROM_OTHER);

// True between a lookup handing its inventory to the worker and its verdict.
// Everything that acts on sm_found waits while it is: the verdict is not in,
// and sm_found says "not found" only because it was reset.
bool lookupPending();

// What the caller of querySpoolman() does with the verdict. See LookupOrigin.
void lookupFollowUp(LookupOrigin origin, const char* uid);

// From appLoop(): collects the inventory from the worker and reads the
// verdict out of it, repaints the status line while it comes in.
void lookupScanTick();

// True while the worker loads a list for a lookup, or a lookup waits for it.
// The uid index a scan opens stays open for that long, see uidIndexTick().
bool lookupScanBusy();

// The tag the pending lookup was for is gone: another one was put down, or
// the display was cleared. No verdict will be painted; the inventory still
// comes in and feeds the spool cache and the uid index.
void lookupAbandon();

// The status line while the inventory comes in: "searching", with the
// kilobytes read so far once there are any.
void lookupPaintSearching();
void querySpoolmanById(int spool_id);

// Re-announces a tag once, a moment after the auto-link has made it
// resolvable. The first scan of a spool that was not linked yet necessarily
// reports an unknown tag: the link only exists after the lookup that follows
// it. Without this, a paired browser gets the "unknown tag" toast and stays
// where it is, and the user has to lift the spool and put it back to see it
// open. Call from the loop.
void spoolmanRescanTick();

// Asks again whether the tag on the pad has been linked since it came up
// unknown, and lets the normal path fetch it when it has.
//
// The case it exists for: the spool is on the scale, the user links it in the
// backend's own web UI, and the scale has no way of hearing about it. Without
// this the tag has to be lifted off and put back, which is the scale looking
// broken while everything worked.
//
// Deliberately cheap: only the server side tag lookup each backend already
// has, never the inventory scan that a real miss falls through to. Call from
// the loop.
void spoolmanRecheckTick();
// Whether the backend knows a spool by this tag: the recheck's cheap lookup,
// without the inventory scan and without announcing the tag to a browser.
// Blocks for one small request, so never from an LVGL event handler.
// `out_unanswered`, when given, says whether the server never answered, which
// is not the same as answering that it does not know the tag.
// `out_spool_id`, when given, receives the id of the spool that matched.
bool spoolmanTagResolves(const char* query, bool* out_unanswered = nullptr,
                         int* out_spool_id = nullptr);

// Whether the last lookup failed because the server could not be reached, as
// opposed to answering that it does not know the tag. The status line says so
// instead of naming the backend the spool is supposedly missing from.
bool lookupLostConnection();
