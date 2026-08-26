#pragma once

#include <WebServer.h>

// The stylesheet and the shared script, as their own routes rather than
// pasted into every page.
//
// The CSS was ~4 kB rebuilt on the internal heap for every single request,
// on a device whose own comments call holding 5 kB permanently "a bad trade
// on a device with 320 kB" (web_assets.cpp). As a route it is sent straight
// out of flash and the browser keeps it.
//
// Cached hard, but keyed by firmware version: unlike the icons, these two
// change with every release, so the page links them as "/app.css?v=<version>"
// and a new firmware simply asks for a different URL. Without that key a
// week-old cache would style a page it has never seen.
void registerStaticRoutes(WebServer &srv);

// The version key the page has to append. Same string for both files.
const char* webStaticVersion();
