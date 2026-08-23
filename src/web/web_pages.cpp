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
extern const WebPage PAGE_NETWORK;
extern const WebPage PAGE_BACKEND;
extern const WebPage PAGE_CONFIG;
extern const WebPage PAGE_TAGS;

const WebPage* const WEB_PAGES[] = {
  &PAGE_STATUS,
  &PAGE_NETWORK,
  &PAGE_BACKEND,
  &PAGE_CONFIG,
  &PAGE_DRYING,
  &PAGE_TAGS,
  &PAGE_LOGS,
  &PAGE_FIRMWARE,
};

const size_t WEB_PAGE_COUNT = sizeof(WEB_PAGES) / sizeof(WEB_PAGES[0]);

const char* webPageLabel(const WebPage &p) {
  return p.label_fn ? p.label_fn() : p.label;
}

bool webPageVisible(const WebPage &p) {
  if (p.applies && !p.applies()) return false;
  return webGateOpen(p.gate);
}
