#pragma once

void querySpoolman(const char* tray_uuid);
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
