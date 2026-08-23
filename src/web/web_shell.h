#pragma once

#include <Arduino.h>

// Chrome shared by every served page: logo, colours, nav, links, disclaimer.
String webShellHead(const char *subtitle);
String webShellPageCss();
// `active` is the current path, for highlighting. FilaMan tab only in that mode.
String webShellNav(const char *active);
String webShellLinks();
String webShellFoot();

// The overlay waits before polling: the old server answers for a moment after
// the request, and an immediate poll would reload too early.
String webShellRestartUi();

const char* webShellLogoBase64();
