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
#include "services/tag_spool_match.h"
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
static bool          s_force        = false;
static int           s_spool_id     = 0;
static char          s_uid[26]      = "";
static TagLinkReport s_report       = { TL_NONE, 0, 0 };
static int           s_linked_spool = 0;
// The tag on the reader when the answer was given. The answer is about that
// tag, and goes when it does: left standing, "belongs to spool 7" was still
// the page's last word about the next tag put down.
static char          s_answered_uid[26] = "";
// What the parked request asks for beyond a plain link.
static uint8_t       s_job          = TLJ_LINK;
static int           s_from         = 0;
static bool          s_write        = false;
static uint8_t       s_fmt          = 0;

// The target's tag fields when it is not the spool on the scale. Static
// because patchSpoolTag() takes pointers and the values have to outlive the
// fetch that filled them.
static char s_fetched[TAG_FIELD_EXTRA_COUNT][CARD_UIDS_MAX];

static const char* const JOB_NAME[] = { "link", "move", "unlink", "write" };

// Every request parks the same way; what differs is set by the caller after.
static bool park(uint8_t job, int spool_id, const char* uid) {
  if (s_pending || !uid || !uid[0]) return false;
  if (job != TLJ_UNLINK && spool_id <= 0) return false;
  s_pending  = true;
  s_job      = job;
  s_force    = false;
  s_spool_id = spool_id;
  s_from     = 0;
  s_write    = false;
  s_fmt      = 0;
  snprintf(s_uid, sizeof(s_uid), "%s", uid);
  s_report = { TL_BUSY, spool_id, 0, "", "" };
  s_report.job = job;
  return true;
}

// The extras go into the report when the request is parked, so the page's
// "moving from #N" names the spool while the job still waits for the loop.
static void reportExtras() {
  s_report.from_spool = s_from;
  s_report.write      = s_write;
  s_report.fmt        = s_fmt;
}

// One write at a time: a second, parked behind the check while the first
// still runs, would write the tag twice.
static bool writeRunning() { return !strcmp(tagWriteState(), "pending"); }

bool tagLinkRequest(int spool_id, const char* uid, bool force) {
  if (!park(TLJ_LINK, spool_id, uid)) return false;
  s_force = force;
  logSDf("TagLink: tag %s to spool %d requested%s", s_uid, spool_id,
         force ? " (mismatch accepted)" : "");
  return true;
}

bool tagLinkWriteRequest(int spool_id, const char* uid, uint8_t fmt) {
  if (writeRunning() || !park(TLJ_WRITE, spool_id, uid)) return false;
  s_write = true;
  s_fmt   = fmt;
  reportExtras();
  logSDf("TagLink: write of tag %s for spool %d requested, holder check first",
         s_uid, spool_id);
  return true;
}

bool tagLinkMoveRequest(int spool_id, const char* uid, int from_spool, int write_fmt,
                        bool force) {
  if (from_spool <= 0 || from_spool == spool_id) return false;
  if (write_fmt >= 0 && writeRunning()) return false;
  if (!park(TLJ_MOVE, spool_id, uid)) return false;
  s_from  = from_spool;
  s_force = force;
  s_write = write_fmt >= 0;
  s_fmt   = s_write ? (uint8_t)write_fmt : 0;
  reportExtras();
  logSDf("TagLink: move of tag %s from spool %d to %d requested%s", s_uid, from_spool,
         spool_id, s_write ? " (with write)" : "");
  return true;
}

bool tagUnlinkRequest(const char* uid) {
  if (!park(TLJ_UNLINK, 0, uid)) return false;
  logSDf("TagLink: unlink of tag %s requested", s_uid);
  return true;
}

// A Bambu tag against the spool it is about to be linked to, by the verdict
// every link shares. True when they differ, with both sides described in the
// report for the page's question. A spool that cannot be read is not held
// against the link: the write below reports the network on its own.
static bool bambuMismatch(int spool_id) {
  SpiRamAllocator psram;
  JsonDocument doc(&psram);
  if (backendGetSpoolJson(backendBaseUrl(), spool_id, doc) != 200 || doc.isNull()) return false;
  const TagSpoolVerdict v = tagSpoolCompareTag(doc.as<JsonObjectConst>());
  if (!v.any()) return false;

  JsonObjectConst fil = doc["filament"];
  const char* mat  = fil["material"]  | "";
  const char* name = fil["name"]      | "";
  const char* col  = fil["color_hex"] | "";
  const bool name_has_mat = mat[0] && strncasecmp(name, mat, strlen(mat)) == 0;
  snprintf(s_report.tag_desc, sizeof(s_report.tag_desc), "%s %s",
           g_tag.material, g_tag.color_hex);
  snprintf(s_report.spool_desc, sizeof(s_report.spool_desc), "%s%s%s %s%s",
           name_has_mat ? "" : mat, name_has_mat || !mat[0] ? "" : " ", name,
           col[0] && col[0] != '#' ? "#" : "", col);
  char why[32];
  tagSpoolVerdictText(v, why, sizeof(why));
  logSDf("TagLink: spool %d does not match the tag (%s), asking", spool_id, why);
  return true;
}

const TagLinkReport* tagLinkReportData() { return &s_report; }

void tagLinkReportClear() {
  if (!s_pending) s_report = { TL_NONE, 0, 0 };
}

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

static uint8_t bindToSpool(int id, const char* value, int* held_by);

// What every job checks first. TL_NONE when the tag the page asked about is
// still the one on the reader and the network is up.
static uint8_t tagStillHere() {
  if (!tag_present || !g_tag.uid_str[0]) return TL_NO_TAG;
  // The page asked about the tag it showed. One put down since would be bound
  // to a spool nobody chose for it.
  if (strcmp(g_tag.uid_str, s_uid) != 0) return TL_CHANGED;
  if (!wifi_ok) return TL_NETWORK;
  return TL_NONE;
}

// What doLinkPatch() binds: a Bambu tag by the tray uuid both chips of the
// spool carry, anything else by its chip uid. A bare chip uid for a Bambu
// tag would be a binding no other Bambu reader looks for. True for Bambu.
static bool bindingValue(char* out, size_t out_size) {
  const bool bambu = strlen(g_tag.tray_uuid) == 32;
  snprintf(out, out_size, "%s", bambu ? g_tag.tray_uuid : g_tag.uid_str);
  return bambu;
}

// Who holds the tag now, asked the way the recheck asks and verified the
// same way, on every backend. holder 0: nobody. TL_NETWORK when the server
// never answered, which is not the same as nobody.
static uint8_t findHolder(const char* value, int* holder) {
  bool unanswered = false;
  *holder = 0;
  if (spoolmanTagResolves(value, &unanswered, holder) && *holder > 0) return TL_NONE;
  *holder = 0;
  return unanswered ? TL_NETWORK : TL_NONE;
}

// The binding and its records, the end of a link and of a move.
static uint8_t finishBind(const char* value) {
  int held_by = 0;
  const uint8_t r = bindToSpool(s_spool_id, value, &held_by);
  if (r == TL_HELD || r == TL_ON_FILAMENT) s_report.other_spool = held_by;
  if (r == TL_OK) s_linked_spool = s_spool_id;
  return r;
}

// The write itself stays tag_write.cpp's: parked there as the page always
// parked it, and reported through its own state. TL_NONE hands the page over
// to that state.
static uint8_t handToWrite() {
  if (!tagWriteRequest(s_spool_id, (TagFormat)s_fmt, true)) return TL_WRITE_REFUSED;
  logSDf("TagLink: tag %s is free for spool %d, write handed on", s_uid, s_spool_id);
  return TL_NONE;
}

// Takes the tag on the reader off holder, through the unlink More Info uses.
// That one reads the bindings the last lookup captured, which belong to the
// spool the scale shows and to no other. A Bambu tag goes with every binding
// of its spool: the other chip carries the same tray uuid, and left behind it
// would keep finding the spool the tag was just taken off.
static uint8_t unlinkHolder(int holder, bool bambu, const char* value) {
  if (!sm_found || sm_id != holder) return TL_NOT_SHOWN;
  unlinkTagOnReader(holder, bambu);
  if (tagBindingFailedOnNetwork()) return TL_NETWORK;
  // The kept list still has the spool as bound, as after More Info's unlink.
  spoolCacheSetBound(holder, false);
  // The unlink reports no server answer of its own, so the server is asked
  // whether it still finds the spool. Moved on regardless, the link below
  // would only run into the same holder again.
  int still = 0;
  if (findHolder(value, &still) == TL_NONE && still == holder) {
    logSDf("TagLink: spool %d still found by tag %s after the unlink", holder, value);
    return TL_UNLINK_FAILED;
  }
  logSDf("TagLink: tag %s taken off spool %d", value, holder);
  return TL_UNLINKED;
}

static uint8_t runLink() {
  const int id = s_spool_id;
  uint8_t r = tagStillHere();
  if (r != TL_NONE) return r;
  char value[40];
  const bool bambu = bindingValue(value, sizeof(value));

  // Refused here; the page asks whether to move it and answers with a move.
  int holder = 0;
  r = findHolder(value, &holder);
  if (r != TL_NONE) return r;
  if (holder == id) return TL_ALREADY;
  if (holder > 0) { s_report.other_spool = holder; return TL_HELD; }

  // Asked once on the page, the way the device's own link asks; the answer
  // comes back as a second request with force set.
  if (bambu && !s_force && bambuMismatch(id)) return TL_MISMATCH;
  return finishBind(value);
}

// A write that links never writes another spool's tag: asked first, because
// the link after the write cannot take the tag back off the reader's data.
static uint8_t runWrite() {
  uint8_t r = tagStillHere();
  if (r != TL_NONE) return r;
  char value[40];
  bindingValue(value, sizeof(value));
  int holder = 0;
  r = findHolder(value, &holder);
  if (r != TL_NONE) return r;
  if (holder > 0 && holder != s_spool_id) { s_report.other_spool = holder; return TL_HELD; }
  return handToWrite();
}

static uint8_t runMove() {
  uint8_t r = tagStillHere();
  if (r != TL_NONE) return r;
  char value[40];
  const bool bambu = bindingValue(value, sizeof(value));
  int holder = 0;
  r = findHolder(value, &holder);
  if (r != TL_NONE) return r;
  if (holder == s_spool_id && !s_write) return TL_ALREADY;
  // The answer was about from_spool. A third spool is a new question.
  if (holder > 0 && holder != s_from && holder != s_spool_id) {
    s_report.other_spool = holder;
    return TL_HELD;
  }
  // Before anything is undone: a "no" to this must leave the tag where it was.
  if (bambu && !s_write && !s_force && bambuMismatch(s_spool_id)) return TL_MISMATCH;
  if (holder == s_from) {
    s_report.other_spool = holder;
    r = unlinkHolder(holder, bambu, value);
    if (r != TL_UNLINKED) return r;
    s_report.unlinked = true;
  }
  r = s_write ? handToWrite() : finishBind(value);
  // Off the old spool and on no new one: the scale looks the tag up again
  // rather than go on showing the spool it was taken off.
  if (s_report.unlinked && r != TL_OK && r != TL_NONE) tagLookupForget();
  return r;
}

static uint8_t runUnlink() {
  uint8_t r = tagStillHere();
  if (r != TL_NONE) return r;
  char value[40];
  const bool bambu = bindingValue(value, sizeof(value));
  int holder = 0;
  r = findHolder(value, &holder);
  if (r != TL_NONE) return r;
  if (holder <= 0) return TL_NOT_LINKED;
  s_report.other_spool = holder;
  r = unlinkHolder(holder, bambu, value);
  // The next poll looks the tag up again, as after More Info's unlink, so the
  // scale stops showing a spool the tag no longer belongs to.
  if (r == TL_UNLINKED) tagLookupForget();
  return r;
}

static uint8_t runJob() {
  switch (s_job) {
    case TLJ_MOVE:   return runMove();
    case TLJ_UNLINK: return runUnlink();
    case TLJ_WRITE:  return runWrite();
    default:         return runLink();
  }
}

// The binding itself, shared by the page's link and the link a tag write asks
// for: the same write the device's link flow ends in, and the same records
// kept afterwards.
static uint8_t bindToSpool(int id, const char* value, int* held_by) {
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
      *held_by = sm_tag_conflict_spool;
      return TL_HELD;
    }
    // Spoolman 0.27 binds tags to filaments too. No move from here: the page
    // names the filament, and Spoolman is where it is let go.
    if (sm_tag_conflict_filament > 0) {
      *held_by = sm_tag_conflict_filament;
      sm_tag_conflict_filament = 0;
      return TL_ON_FILAMENT;
    }
    return tagBindingFailedOnNetwork() ? TL_NETWORK : TL_FAILED;
  }

  // What doLinkPatch() does after its write, so the next list and the next
  // lookup know the tag the way the device's own link would have left them.
  if (!tagFieldSelected().is_native) spoolCacheSetBound(id, true);
  const char* linked[3] = { value, tagNativeUid(value), g_tag.uid_str };
  uidIndexNote(linked, 3);
  return TL_OK;
}

int tagLinkAfterWrite(int spool_id, const char* uid) {
  // -1 is the HTTP client's "connection refused", the code a link that never
  // reached the server has always reported here.
  if (spool_id <= 0 || !uid || !uid[0] || !wifi_ok) return -1;
  int held_by = 0;
  const uint8_t r = bindToSpool(spool_id, uid, &held_by);
  logSDf("TagLink: written tag %s to spool %d -> result %u%s", uid, spool_id,
         (unsigned)r, held_by ? " (held elsewhere)" : "");
  switch (r) {
    case TL_OK:      return 200;
    case TL_HELD:    return 409;
    case TL_NETWORK: return -1;
    // patchSpoolTag() logged the server's own code; the page only needs to
    // know that the server said no.
    default:         return 400;
  }
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

  s_report.code = runJob();
  // For "changed" that is the new tag, which is the one the message is about.
  snprintf(s_answered_uid, sizeof(s_answered_uid), "%s", tag_present ? g_tag.uid_str : "");
  logSDf("TagLink: %s of tag %s, spool %d -> result %u, other spool %d",
         JOB_NAME[s_job < sizeof(JOB_NAME) / sizeof(JOB_NAME[0]) ? s_job : 0], s_uid, s_spool_id,
         (unsigned)s_report.code, s_report.other_spool);
}
