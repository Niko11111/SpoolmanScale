#include "ui/copy_tagless.h"

#include <Arduino.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "ui/spool_flow.h"
#include "ui/spool_flow_internal.h"
#include "ui/tag_display.h"

// A Bambu tag's tray UUID: 32 hex characters.
#define CT_TRAY_UUID_LEN 32

static bool s_on = false;

// What a link would write: an NTAG's UID or a Bambu tray UUID. A tag put
// down while the flow covers the screen lies there without either until its
// lookup runs, so it is no link target yet.
static bool tagToLink() {
  return link_tag_uid[0] || strlen(g_tag.tray_uuid) == CT_TRAY_UUID_LEN;
}

static bool tagDataStands() {
  return tag_present || tagToLink();
}

void copyTaglessStart() {
  // The by-id button shows as soon as no tag lies on the reader, while a
  // lifted unknown tag keeps its data for the no-tag timer: a Bambu tray
  // UUID would offer New from tag and send the copy list down the Bambu path.
  clearTagDisplay();
  s_on = true;
  logSD("UI: new spool without a tag");
  showCopyEntryPopup();
}

void copyTaglessEnd(const char* why) {
  if (!s_on) return;
  s_on = false;
  logSDf("UI: new spool without a tag ended (%s)", why);
}

bool copyTaglessActive() {
  return s_on && !tagDataStands();
}

bool copyTaglessTake() {
  const bool tagless = s_on && !tagToLink();
  if (s_on && !tagless) logSD("UI: new spool without a tag - a tag turned up, it is linked");
  s_on = false;
  return tagless;
}
