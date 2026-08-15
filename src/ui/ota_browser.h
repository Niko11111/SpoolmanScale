#pragma once

#include <stdint.h>

// The device web server serves both the firmware upload and the FilaMan
// credential form, so one screen covers all of it. Only the framing differs:
// what the title says, where "back" goes, and whether the credential status
// is shown.
enum WebScreenContext : uint8_t {
  WEB_CTX_FIRMWARE = 0,   // opened from the update menu
  WEB_CTX_BACKEND  = 1,   // opened from the backend menu, back to that menu
  WEB_CTX_SETUP    = 2,   // credential step of the first time setup
  WEB_CTX_DRYING   = 3,   // drying thresholds, back to the reminder screen
};

void showOtaBrowserScreen(WebScreenContext ctx = WEB_CTX_FIRMWARE);
void buildOtaBrowserScreen();

// Keeps the two credential rows current while the user types in the browser.
// Cheap: it only reads values already held in memory, no request. Does
// nothing unless the screen is visible in a credential context.
void refreshWebCredentialRows();
