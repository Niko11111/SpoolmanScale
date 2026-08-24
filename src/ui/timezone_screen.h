#pragma once

// Picks the zone every timestamp on this device is written in. Reached from
// the language screen, which is where the other presentation settings live.
void buildTimeZoneScreen();

// Where Back goes, and whether the screen offers a way out at all. The picker
// is reached from the language screen in the menu and from the welcome screen
// during first setup; in setup there is no main screen worth escaping to yet,
// so the close button is left off.
void setTimeZoneReturnToWelcome(bool to_welcome);
