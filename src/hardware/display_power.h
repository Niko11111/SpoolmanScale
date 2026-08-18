#pragma once

// Pushes the saved bright_normal to the panel and arms the idle timer.
// Must run once after displayHardwareBegin(), otherwise the panel keeps
// the init-time default and ignores the user's stored brightness.
void displayPowerInit();
void resetActivityTimer();
void handlePowerManagement();
