#pragma once

#include <stdint.h>

extern bool update_available;
extern bool gh_prerelease;

// Newest tag seen by either the manual check on the GitHub OTA screen or the
// background check. Lives here rather than inside ota_github.cpp because both
// producers need to write it and the screen needs to read it.
extern char gh_latest_version[32];

// True while doGithubOtaFlash() is writing the new image. The background check
// must not open a second TLS connection while an image is being flashed.
extern volatile bool gh_flash_active;

// Automatic background update check. NVS key "upd_check", default on.
extern bool g_upd_autocheck;
// Unix time of the last successful check. NVS key "upd_last", 0 = never.
extern uint32_t g_upd_last_epoch;
