#pragma once

#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>

class WiFiClientSecure;

// Trust for every connection to GitHub: the certificate bundle the ESP-IDF
// ships (Mozilla's root store, 64 kB of flash, linked only because this
// references it). Every one of these connections used to run setInsecure(),
// and the firmware image came down one of them - whoever answered DNS for
// github.com could hand the scale an image and it would flash it.
void githubTrust(WiFiClientSecure &client);

// Release lookup and image download, with no display of its own.
//
// Both the device screen and the web firmware page want the same two things -
// the newest tag, and the image behind it. They used to exist only inside the
// LVGL screen, painting into its labels as they went, so nothing else could
// reach them.

// Newest release tag, and when it was published - the list already carries
// the date, so asking for it costs nothing over asking for the tag. published
// may be null for a caller that only wants the tag. err carries a short reason
// on failure, fit to be shown as it is.
bool githubLatestTag(bool prerelease, char *tag, size_t tag_len,
                     char *published, size_t pub_len,
                     char *err, size_t err_len);

// One release as GitHub describes it. notes is the release body, markdown as
// written, capped so a long one cannot take the heap with it.
struct GithubRelease {
  char   tag[40];
  char   name[96];
  char   published[24];   // ISO 8601, straight from the API
  bool   prerelease;
  String notes;
};

// The release carrying a given tag. This is what answers "which channel is the
// build I am running from, and what changed in it" - questions the tag alone
// cannot.
bool githubReleaseByTag(const char *tag, GithubRelease &out,
                        char *err, size_t err_len);

// done and total in bytes; total is 0 when the server sent no Content-Length.
typedef void (*OtaProgressFn)(uint32_t done, uint32_t total);

// Downloads the image for a tag and writes it. True means the image is in
// place and the device is still running - restarting is the caller's call.
//
// sha256_hex is the checksum the release workflow published for this tag in
// version.json, 64 hex characters, or empty when none is known (a tag picked
// by hand on the GitHub screen). Given, it is checked against what was
// written, and a mismatch is a refusal. The image is only committed when
// every byte the server announced has arrived: a dropped connection used to
// finalise a half image and report success.
//
// Blocks for as long as the download takes, so it pumps LVGL from inside its
// own read loop whichever caller started it.
bool githubFlashTag(const char *tag, const char *sha256_hex,
                    OtaProgressFn progress, char *err, size_t err_len);
