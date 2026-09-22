#include "tag_link.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <esp_heap_caps.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/spool_cache.h"
#include "services/spoolman_actions.h"
#include "services/tag_field.h"
#include "services/tag_uid.h"
#include "services/tag_write.h"
#include "services/uid_index.h"
#include "services/user_options.h"
#include "ui/spoolman_lookup.h"

// Defined locally in every .cpp that needs it, as everywhere else in this
// project.
namespace {
struct SpiRamAllocator : ArduinoJson::Allocator {
  void* allocate(size_t size) override {
    void* ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
    if (!ptr) ptr = malloc(size);
    return ptr;
  }
  void deallocate(void* pointer) override { heap_caps_free(pointer); }
  void* reallocate(void* ptr, size_t new_size) override {
    void* p = heap_caps_realloc(ptr, new_size, MALLOC_CAP_SPIRAM);
    if (!p) p = realloc(ptr, new_size);
    return p;
  }
};
}

static bool          s_pending      = false;
static int           s_spool_id     = 0;
static char          s_uid[26]      = "";
static TagLinkReport s_report       = { TL_NONE, 0, 0 };
static int           s_linked_spool = 0;
// The tag on the reader when the answer was given. The answer is about that
// tag, and goes when it does: left standing, "belongs to spool 7" was still
// the page's last word about the next tag put down.
static char          s_answered_uid[26] = "";

// The target's tag fields when it is not the spool on the scale. Static
// because patchSpoolTag() takes pointers and the values have to outlive the
// fetch that filled them.
static char s_fetched[TAG_FIELD_EXTRA_COUNT][CARD_UIDS_MAX];

bool tagLinkRequest(int spool_id, const char* uid) {
  if (s_pending || spool_id <= 0 || !uid || !uid[0]) return false;
  s_pending  = true;
  s_spool_id = spool_id;
  snprintf(s_uid, sizeof(s_uid), "%s", uid);
  s_report = { TL_BUSY, spool_id, 0 };
  logSDf("TagLink: tag %s to spool %d requested", s_uid, spool_id);
  return true;
}

const TagLinkReport* tagLinkReportData() { return &s_report; }

int tagLinkTakeLinkedSpool() {
  const int id = s_linked_spool;
  s_linked_spool = 0;
  return id;
}

bool tagLinkKeepsOtherTags() {
  if (backendMode() != BACKEND_SPOOLMAN) return false;
  const TagFieldSpec& spec = tagFieldSelected();
  return spec.is_native || (spec.is_list && g_card_uids_write);
}

// The same reading as linkFillTagValues() in the link flow: quotes out,
// trimmed, and a value too long for the buffer dropped rather than shortened -
// appending to half a list would lose the tags that fell off its end.
static bool fetchTagValues(int spool_id, const char* values[]) {
  SpiRamAllocator psram;
  JsonDocument doc(&psram);
  const int code = backendGetSpoolJson(backendBaseUrl(), spool_id, doc);
  if (code != 200 || doc.isNull()) {
    logSDf("TagLink: spool %d not read, HTTP %d", spool_id, code);
    return false;
  }
  for (uint8_t f = 0; f < TAG_FIELD_EXTRA_COUNT; f++) {
    s_fetched[f][0] = '\0';
    values[f] = nullptr;
    const char* key = tagFieldSpec(f).key;
    if (doc["extra"][key].isNull()) continue;
    String v = doc["extra"][key].as<String>();
    v.replace("\"", "");
    v.trim();
    if (v.length() == 0 || v.length() >= CARD_UIDS_MAX) continue;
    snprintf(s_fetched[f], CARD_UIDS_MAX, "%s", v.c_str());
    values[f] = s_fetched[f];
  }
  return true;
}

static uint8_t runLink() {
  const int id = s_spool_id;
  if (!tag_present || !g_tag.uid_str[0]) return TL_NO_TAG;
  // The page asked about the tag it showed. One put down since would be bound
  // to a spool nobody chose for it.
  if (strcmp(g_tag.uid_str, s_uid) != 0) return TL_CHANGED;
  if (!wifi_ok) return TL_NETWORK;

  // What doLinkPatch() binds: a Bambu tag by the tray uuid both chips of the
  // spool carry, anything else by its chip uid. A bare chip uid for a Bambu
  // tag would be a binding no other Bambu reader looks for.
  const bool bambu = strlen(g_tag.tray_uuid) == 32;
  char value[40];
  snprintf(value, sizeof(value), "%s", bambu ? g_tag.tray_uuid : g_tag.uid_str);

  // Who holds the tag now, asked the way the recheck asks and verified the
  // same way, on every backend. Refused rather than moved: taking a tag off a
  // spool is a decision, and the page does not ask it (yet).
  bool unanswered = false;
  int holder = 0;
  if (spoolmanTagResolves(value, &unanswered, &holder)) {
    if (holder == id) return TL_ALREADY;
    if (holder > 0) { s_report.other_spool = holder; return TL_HELD; }
  }
  if (unanswered) return TL_NETWORK;

  // The target's tag fields, which patchSpoolTag() needs on Spoolman to grow
  // a list instead of starting it over and to move a binding out of another
  // field. The other backends keep one place for a tag and read none of this.
  const char* values[TAG_FIELD_COUNT] = {};
  const char* const* field_values = nullptr;
  if (backendMode() == BACKEND_SPOOLMAN) {
    if (sm_found && sm_id == id) {
      for (uint8_t f = 0; f < TAG_FIELD_EXTRA_COUNT; f++)
        values[f] = sm_tag_values[f][0] ? sm_tag_values[f] : nullptr;
    } else if (!fetchTagValues(id, values)) {
      return TL_NETWORK;
    }
    field_values = values;
  }

  if (!patchSpoolTag(id, value, field_values, false)) {
    // Spoolman's relation says who holds the tag in its 409.
    if (sm_tag_conflict_spool > 0) {
      s_report.other_spool = sm_tag_conflict_spool;
      return TL_HELD;
    }
    return tagBindingFailedOnNetwork() ? TL_NETWORK : TL_FAILED;
  }

  // What doLinkPatch() does after its write, so the next list and the next
  // lookup know the tag the way the device's own link would have left them.
  if (!tagFieldSelected().is_native) spoolCacheSetBound(id, true);
  const char* linked[3] = { value, tagNativeUid(value), g_tag.uid_str };
  uidIndexNote(linked, 3);
  s_linked_spool = id;
  return TL_OK;
}

void tagLinkTick() {
  if (!s_pending) {
    if (s_report.code != TL_NONE && s_report.code != TL_BUSY &&
        strcmp(tag_present ? g_tag.uid_str : "", s_answered_uid) != 0)
      s_report = { TL_NONE, 0, 0 };
    return;
  }
  // A tag write reports through its own state and may link as well. The two
  // never run in the same pass, and the link waits for the write.
  if (!strcmp(tagWriteState(), "pending")) return;
  // Nor while the lookup of the tag on the reader waits for its inventory:
  // its verdict would land on top of the link and paint the tag unknown.
  if (lookupPending()) return;
  s_pending = false;

  s_report.code = runLink();
  // For "changed" that is the new tag, which is the one the message is about.
  snprintf(s_answered_uid, sizeof(s_answered_uid), "%s", tag_present ? g_tag.uid_str : "");
  logSDf("TagLink: tag %s to spool %d -> result %u%s", s_uid, s_spool_id,
         (unsigned)s_report.code,
         s_report.other_spool ? " (held elsewhere)" : "");
}
