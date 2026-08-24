#pragma once

#include <Arduino.h>

// Chrome shared by every served page. The registry wraps each page in it, so
// a new page cannot end up with half of it or with a lookalike of its own.
//
//   webShellHead(title)   doctype, head, stylesheet, opens .wrap
//   webShellHeader()      logo, wordmark, version, the device address
//   webShellNav(path)     the tab strip, built from the page table
//   <the page's cards>
//   webShellFoot()        community links, disclaimer, closes everything
String webShellHead(const char *title);
String webShellHeader();
String webShellNav(const char *active);
String webShellLinks();
String webShellFoot();

// The overlay waits before polling: the old server answers for a moment after
// the request, and an immediate poll would reload too early.
String webShellRestartUi();

// Wraps a translated string as a JavaScript string literal, quotes included.
// Use it for every T() text that lands inside a <script> block.
String jsStr(const char *in);

const char* webShellLogoBase64();
