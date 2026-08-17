#pragma once

void showOtaGithubScreen();
void buildOtaGithubScreen();
void doGithubOtaCheck();
void doGithubOtaFlash(const char* version);

// True while the user is looking at the GitHub OTA screen. The background
// check uses this to leave a manual result on screen alone.
bool otaGithubScreenVisible();
