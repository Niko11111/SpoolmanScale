#pragma once

// The empty spool weight, weighed or typed in (issue #40). Opened from the
// weight popup's empty spool button. Either way the value goes on to the
// popup that asks where it is stored - spool, filament or brand.
void showTareChoice();

// Both dialogs of this file, for the navigation. Closed, not hidden.
void closeTareEntry();

// The choice or the keypad is up. Counts as a modal like the weight popup:
// no automatic weighing and no question on removal while it stands.
bool isTareEntryOpen();

// Every loop pass. Closes the entry without saving once the spool it was
// opened for is lifted off the pad or another spool is loaded.
void tareEntryTick();
