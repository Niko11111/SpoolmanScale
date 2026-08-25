#pragma once

#include <stddef.h>
#include <stdint.h>

// Release lookup and image download, with no display of its own.
//
// Both the device screen and the web firmware page want the same two things -
// the newest tag, and the image behind it. They used to exist only inside the
// LVGL screen, painting into its labels as they went, so nothing else could
// reach them.

// Newest release tag. prerelease also considers pre-releases. err carries a
// short reason on failure, fit to be shown as it is.
bool githubLatestTag(bool prerelease, char *tag, size_t tag_len,
                     char *err, size_t err_len);

// done and total in bytes; total is 0 when the server sent no Content-Length.
typedef void (*OtaProgressFn)(uint32_t done, uint32_t total);

// Downloads the image for a tag and writes it. True means the image is in
// place and the device is still running - restarting is the caller's call.
//
// Blocks for as long as the download takes, so it pumps LVGL from inside its
// own read loop whichever caller started it.
bool githubFlashTag(const char *tag, OtaProgressFn progress,
                    char *err, size_t err_len);
