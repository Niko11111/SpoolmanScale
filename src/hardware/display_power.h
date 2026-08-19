#pragma once

// Pushes the saved bright_normal to the panel and arms the idle timer.
// Must run once after displayHardwareBegin(), otherwise the panel keeps
// the init-time default and ignores the user's stored brightness.
void displayPowerInit();
void resetActivityTimer();

// Called with every scale reading. Putting a spool on the pad is as clear a
// statement of intent as touching the screen, so it wakes the panel the same
// way. Without this the display stays dim over a spool that is already being
// weighed, and the reading has to be read through a dimmed backlight or the
// screen poked first.
void displayNoteWeight(float grams);
void handlePowerManagement();
