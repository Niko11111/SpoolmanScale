#pragma once

#include <stddef.h>
#include <stdint.h>

extern bool update_available;
extern bool gh_prerelease;

// Newest tag seen by either the manual check on the GitHub OTA screen or the
// background check. Lives here rather than inside ota_github.cpp because both
// producers need to write it and the screen needs to read it.
// 40 to match the tag buffers in services/github_release.cpp and the
// 39-character limit its tagLooksSafe() enforces. At 32 a longer tag was
// truncated on the way in and the download URL built from it went to 404.
extern char gh_latest_version[40];

// True while doGithubOtaFlash() is writing the new image. The background check
// must not open a second TLS connection while an image is being flashed.
extern volatile bool gh_flash_active;

// Automatic background update check. NVS key "upd_check", default on.
extern bool g_upd_autocheck;
// Unix time of the last successful check. NVS key "upd_last", 0 = never.
extern uint32_t g_upd_last_epoch;

// When the running build first ran, as a UTC epoch. 0 means not known: the
// stamp is only written once the clock is set, and a build installed before
// this existed never wrote one.
uint32_t firmwareInstalledAt();

// Records the moment, once, on the first loop pass with a usable clock. A
// version that differs from what NVS holds is a fresh install; the same one is
// the build that was already there and keeps its original date.
void firmwareStampTick();

// One progress line for both OTA paths - the GitHub download and the image
// pushed from the browser. "1.42 / 1.87 MB - 76 %", or just the count when
// total is 0, which is what a missing Content-Length looks like.
//
// Shared rather than written twice because the two screens sit next to each
// other in the menu and a user comparing them should not be reading two
// different shapes of the same number.
void otaProgressLine(char* buf, size_t len, uint32_t done, uint32_t total);

// How often either path may repaint. A 512 byte read loop that painted per
// chunk would spend more time in the display than on the socket.
#define OTA_PROGRESS_MS 200
