#include "web/web_pages.h"

#include "web/web_access.h"

// Every page the device serves, in the order the tab strip shows them.
//
// Adding a page is two lines here plus its own file under pages/. Nothing is
// keyed by index, so nothing needs to be kept in step by hand - which is what
// went wrong with the two tab tables this replaces.
extern const WebPage PAGE_STATUS;
extern const WebPage PAGE_FIRMWARE;
extern const WebPage PAGE_LOGS;
extern const WebPage PAGE_DRYING;
extern const WebPage PAGE_BACKEND;
extern const WebPage PAGE_CONFIG;
extern const WebPage PAGE_TAGS;
extern const WebPage PAGE_SPOOLS;
extern const WebPage PAGE_PRINTER;
extern const WebPage PAGE_LABEL;
extern const WebPage PAGE_THEME;

// Three groups, by how often a page is opened: the inventory, what goes out
// to a printer, and the device itself, set up once and serviced now and then.
const WebPage* const WEB_PAGES[] = {
  &PAGE_STATUS,
  &PAGE_DRYING,
  &PAGE_TAGS,
  &PAGE_SPOOLS,
  &PAGE_PRINTER,
  &PAGE_LABEL,
  &PAGE_CONFIG,
  &PAGE_THEME,
  &PAGE_BACKEND,
  &PAGE_LOGS,
  &PAGE_FIRMWARE,
};

const size_t WEB_PAGE_COUNT = sizeof(WEB_PAGES) / sizeof(WEB_PAGES[0]);

const char* webPageLabel(const WebPage &p) { return p.label(); }

bool webPageVisible(const WebPage &p) {
  if (p.applies && !p.applies()) return false;
  return webGateOpen(p.gate);
}

// Eleven tabs no longer fit one row at 860 px in German or French, so the
// theme page is reached from a card on the settings page. It keeps its own
// URL, routes and gate (GATE_CONFIG, the same as its parent's), so a closed
// switch still hides exactly what it hid before.
const WebPage* webPageNavParent(const WebPage &p) {
  return &p == &PAGE_THEME ? &PAGE_CONFIG : nullptr;
}

bool webPageStartsNavGroup(const WebPage &p) {
  return &p == &PAGE_PRINTER || &p == &PAGE_CONFIG;
}
