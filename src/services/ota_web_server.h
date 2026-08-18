#pragma once

// Opens the OTA, log and settings routes and makes sure the server listens.
void startOtaServer();

// Closes those routes again. The socket stays up when the FilaMan remote
// link still needs it, see webServerSyncState().
void stopOtaServer();

void handleOtaServerClient();

// Starts or stops the listener from the current conditions: WiFi up, FilaMan
// selected and a device token stored. Idempotent, meant to be called once a
// second from appLoop(). In Spoolman mode the server stays on demand exactly
// as before.
void webServerSyncState();

// True while a firmware image is being received through the web upload. The
// background update check uses this to stay out of the way; a second TLS
// connection during a flash is exactly the situation that must not happen.
bool otaWebUploadActive();
