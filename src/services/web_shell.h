#pragma once

#include <Arduino.h>

// Chrome shared by every page the device serves, so the status page, the
// maintenance pages and the theme editor all read as the same project rather
// than three different ones. The logo, the wordmark colours, the community
// links and the disclaimer live here once instead of being re-typed per page.
//
// webShellHead() emits everything up to and including the logo and version
// line. Page-specific CSS goes in webShellPageCss(), which only the
// maintenance pages need.
String webShellHead(const char *subtitle);
String webShellPageCss();
// Tab strip across every page. `active` is the path of the current page so it
// can be highlighted; the FilaMan tab is omitted unless that backend is in use.
String webShellNav(const char *active);
String webShellLinks();
String webShellFoot();

// Restart button plus the overlay it shows while the device is down. The
// overlay waits before polling, because the old server answers for a moment
// after the request and an immediate poll would reload the page too early.
String webShellRestartUi();

// Base64 JPEG of the project logo, shared by the page header and /favicon.jpg.
const char* webShellLogoBase64();
