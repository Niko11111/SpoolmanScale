#pragma once

void handleOtaServerClient();

// The only thing that opens or closes port 80. Derived from the conditions -
// WiFi up, master switch on, or a FilaMan device token that keeps the remote
// link reachable - rather than driven by events, so a backend switch, a
// flipped switch and a returning WiFi connection all take effect without
// anyone having to remember to call something. Idempotent, called once a
// second from appLoop() and once more whenever a screen wants the answer
// now rather than within the second.
//
// There used to be a second automaton in web_access.cpp with its own copy of
// this state, plus direct calls from the web screen. The copies drifted and
// port 80 stayed shut until the next reboot.
void webServerSyncState();

// Whether the socket is currently accepting connections. Used by the mDNS
// responder to advertise the HTTP service only while there is one.
bool webServerIsListening();

// True while a firmware image is being received through the web upload. The
// background update check uses this to stay out of the way; a second TLS
// connection during a flash is exactly the situation that must not happen.
bool otaWebUploadActive();
