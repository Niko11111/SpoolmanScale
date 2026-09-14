#pragma once

#include <IPAddress.h>
#include <stdbool.h>
#include <stddef.h>

// WiFi setup by phone.
//
// The scale opens a WPA2 access point of its own, answers every DNS name with
// its address so the phone shows the portal page by itself, and takes SSID
// and password from a form (web/web_portal.cpp). It does not try them while
// the access point is up: a station searching for a network drags the channel
// along and the phone drops off before it could see the result. The form's
// answer goes out, the access point closes, and the connect runs through the
// setup screens as if the password had been typed on the device, with the
// result on the display.
//
// The portal lives exactly as long as its screen is on display
// (ui/wifi_portal_screen.cpp). Everything runs on the loop task.

// Networks the form offers, from a scan right before the access point starts.
#define SETUP_PORTAL_SCAN_MAX 20

// Scans, then starts access point and DNS. Blocks a few seconds for the scan.
// False when the access point would not come up; nothing is left running.
bool setupPortalStart();

// Access point and DNS down, a form that was sent but not handed over yet is
// dropped. Safe to call when nothing runs.
void setupPortalStop();

bool setupPortalActive();

// DNS answers, and the hand-off once the form's answer had time to reach the
// phone. From appLoop(), every pass.
void setupPortalTick();

const char* setupPortalSsid();
const char* setupPortalPassword();
IPAddress   setupPortalIP();
// "http://<address>/", what the second QR code and the redirects point at.
void        setupPortalUrl(char* out, size_t len);

int         setupPortalNetworkCount();
const char* setupPortalNetwork(int index);

// What the form sent, already checked. Handed over by setupPortalTick() a
// moment later, so the answer page still reaches the phone.
void setupPortalSubmit(const char* ssid, const char* password);

// True between setupPortalSubmit() and the hand-off.
bool setupPortalSubmitted();

// True once per submission, after the access point has closed. Copies the
// credentials out and wipes the password from the portal's own buffer.
bool setupPortalTakeCredentials(char* ssid, size_t ssid_len, char* password, size_t password_len);
