#pragma once

#include <stdint.h>

void showOtaGithubScreen();
void buildOtaGithubScreen();
void doGithubOtaCheck();
void doGithubOtaFlash(const char* version);

// The full-screen cover shown while an image is written: icon, bar, byte
// counter, and the line asking not to cut the power.
//
// Public because an install asked for from the web UI writes the same flash
// and has to say so on the device. Without it the scale sits on its normal
// screen, responsive, for the minute the download takes - and it stays
// responsive, because githubFlashTag() pumps lv_timer_handler() from inside
// its own read loop.
//
// Show() is idempotent. Hide() belongs on every path that does not restart.
void otaGithubOverlayShow();
void otaGithubOverlayProgress(uint32_t done, uint32_t total);
void otaGithubOverlayHide();

// True while the user is looking at the GitHub OTA screen. The background
// check uses this to leave a manual result on screen alone.
bool otaGithubScreenVisible();
