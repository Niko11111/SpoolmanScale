#pragma once

#include <Arduino.h>
#include <WebServer.h>
#include <stddef.h>

#include "web/web_access.h"

// One served page, described in one place.
//
// This replaces a five-way if-chain over an integer index plus two separate
// tab tables that had to be kept in step by hand. They had drifted: one knew
// about BamBuddy and the other did not, so the same device showed the tab on
// its status page and hid it everywhere else.
//
// Adding a page is now a file plus a line in WEB_PAGES. Nothing is indexed by
// number, so nothing can be off by one.
struct WebPage {
  // Both the URL and the identity used to mark the active tab.
  const char *path;
  // Tab text, resolved when the page is served rather than stored. Every
  // label goes through the string table now, and the table is read against
  // the language the device is currently set to - a fixed const char* here
  // would have frozen the tab strip in whatever language was active when the
  // firmware booted. The backend page uses the same hook to call itself
  // FilaMan or BamBuddy.
  const char *(*label)();
  WebGate gate;
  // Null means "always applicable". Otherwise the page is left out of the
  // navigation and answers 404 - the backend page does not exist at all on
  // Spoolman, which has no credentials to enter.
  bool (*applies)();
  // The cards, without any chrome. The shell wraps head, nav and foot around
  // whatever comes back.
  String (*body)();
  // The page's own JSON endpoints. Null when it has none. Called once during
  // route registration, like the page route itself.
  void (*routes)(WebServer &srv);
};

// Pointers, not copies: the addresses are constant expressions, so the whole
// table is built at compile time into ROM. An array of objects would need a
// startup pass to copy them into RAM and would depend on the order in which
// translation units initialise.
extern const WebPage* const WEB_PAGES[];
extern const size_t  WEB_PAGE_COUNT;

// The tab text for a page.
const char* webPageLabel(const WebPage &p);

// Whether a page should appear in navigation: applicable to this device and
// behind an open gate. A tab leading only to the "switched off" page is worse
// than no tab.
bool webPageVisible(const WebPage &p);
