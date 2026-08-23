#pragma once

#include <WebServer.h>

// Images the served pages point at. GATE_ALWAYS throughout: a tab icon is not
// a read of device state, and the page that says "switched off" wants one too.
//
// They are routes rather than data URIs inside the HTML. The logo used to be
// pasted into every page as 7.1 kB of base64, which the browser then had no
// way to cache and which had to be built on the heap again for every request.
void registerAssetRoutes(WebServer &srv);
