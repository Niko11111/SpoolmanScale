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
