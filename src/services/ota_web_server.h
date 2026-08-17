#pragma once

void startOtaServer();
void stopOtaServer();
void handleOtaServerClient();

// True while a firmware image is being received through the web upload. The
// background update check uses this to stay out of the way; a second TLS
// connection during a flash is exactly the situation that must not happen.
bool otaWebUploadActive();
