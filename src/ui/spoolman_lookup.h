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
