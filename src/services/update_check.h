#pragma once

// Background firmware update check.
//
// The previous version called the GitHub API straight from the boot path, with
// an eight second timeout and no separate task. lv_timer_handler() did not run
// for the whole request, so the display froze, and the TLS handshake claimed
// around 40 kB of heap at the exact moment the boot needed it most. It was
// switched off for both reasons and never switched back on.
//
// This one runs in its own FreeRTOS task on the other core. A slow, hanging or
// failing request is invisible to loop(), and everything that is not thread
// safe - LVGL, the SD log, NVS - happens in updateCheckTick() on the loop task.
void updateCheckScheduleFirstRun();

// Bring the next check forward, used when the user switches the option back on
// and expects to see a result rather than to wait a day.
void updateCheckScheduleIn(unsigned long delay_ms);

// Call once per loop pass. Starts the task when a check is due and applies the
// result of a finished one.
void updateCheckTick();

// True while the background task holds a TLS connection. The manual check on
// the OTA screen asks before opening a second one: two handshakes want roughly
// 40 kB each, and the device does not have that twice over.
bool updateCheckBusy();

// Puts the badge back at boot from the version the last check stored, by
// comparing it against FW_VERSION. No network call - the check itself only
// runs once a day, so without this a reboot inside that window hid a waiting
// update.
void updateCheckRestoreBadge();
