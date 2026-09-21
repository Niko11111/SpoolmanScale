#include "services/uid_index.h"

#include <Arduino.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/tag_field.h"     // LAST_DRIED_FIELD

namespace {

// FNV-1a, 64 bit. Two identifiers landing on one value is harmless here: it
// reads as "may be bound" and the real scan runs.
const uint64_t FNV_OFFSET = 14695981039346656037ULL;
const uint64_t FNV_PRIME  = 1099511628211ULL;

// The two fields of FilaMan's Bambu Lab plugin, as mapSpool() names them.
// spoolTagRank() compares them anchored at the front, against the eight
// digits of a chip uid, so that front goes in as a form of its own.
const char   CHIP_FIELD_1[]  = "bambu_tag1";
const char   CHIP_FIELD_2[]  = "bambu_tag2";
const size_t CHIP_PREFIX_HEX = 8;

enum State : uint8_t { IDX_NONE, IDX_BUILDING, IDX_READY };

State          s_state     = IDX_NONE;
uint64_t*      s_ids       = nullptr;
size_t         s_n         = 0;          // sorted and unique once IDX_READY
size_t         s_bytes     = 0;          // what the block takes in PSRAM
int            s_active    = 0;
int            s_archived  = 0;
uint32_t       s_filled_ms = 0;
bool           s_has_stamp = false;
InventoryStamp s_stamp     = { -1, 0 };

// The server the identifiers came from. An address or backend change drops
// them even if somebody forgot to say so.
char    s_key[96] = "";
uint8_t s_mode    = 0;

// Where uidIndexAsk() puts a reason that needs numbers in it.
char s_why[64] = "";

// Set from any task, acted on by the loop. The reason is a string literal, so
// the pointer is all that crosses over.
volatile bool        s_forget     = false;
const char* volatile s_forget_why = nullptr;

void release() {
  if (s_ids) { free(s_ids); s_ids = nullptr; }
  s_n         = 0;
  s_bytes     = 0;
  s_active    = 0;
  s_archived  = 0;
  s_filled_ms = 0;
  s_has_stamp = false;
  s_state     = IDX_NONE;
}

void drop(const char* why) {
  logSDf("uid index: %u ids dropped (%s)", (unsigned)s_n, why ? why : "forgotten");
  release();
  s_forget = false;
}

// Counts on the first walk over a list and stores on the second, so the block
// can be taken at exactly the size it needs.
struct Sink {
  uint64_t* out;
  size_t    cap;
  size_t    n;
  void emit(uint64_t h) {
    if (out && n < cap) out[n] = h;
    n++;
  }
};

// Hash over the hex digits between `b` and `e`, uppercase, at most `limit` of
// them. The same reduction tagUidNormalize() makes, without the buffer.
// *digits gets how many there were in all.
uint64_t hashHex(const char* b, const char* e, size_t limit, size_t* digits) {
  uint64_t h = FNV_OFFSET;
  size_t   d = 0;
  for (const char* p = b; p < e; p++) {
    if (!isxdigit((unsigned char)*p)) continue;
    if (d < limit) {
      h ^= (uint8_t)toupper((unsigned char)*p);
      h *= FNV_PRIME;
    }
    d++;
  }
  *digits = d;
  return h;
}

void emitForm(const char* b, const char* e, Sink& sink) {
  size_t d = 0;
  const uint64_t h = hashHex(b, e, SIZE_MAX, &d);
  if (d >= UID_INDEX_ID_MIN_HEX && d <= UID_INDEX_ID_MAX_HEX) sink.emit(h);
}

// Every form a stored value can be matched in: as a whole, and entry by entry
// where it is a list. Both for every value, because a field nobody agreed on
// may hold either and spoolTagRank() tries both on it.
void emitValue(const char* raw, bool chip_field, Sink& sink) {
  if (!raw || !raw[0]) return;
  const char* end = raw + strlen(raw);

  emitForm(raw, end, sink);

  if (memchr(raw, ',', (size_t)(end - raw))) {
    const char* seg = raw;
    while (seg < end) {
      const char* stop = (const char*)memchr(seg, ',', (size_t)(end - seg));
      if (!stop) stop = end;
      emitForm(seg, stop, sink);
      seg = (stop < end) ? stop + 1 : end;
    }
  }

  if (chip_field) {
    size_t d = 0;
    const uint64_t h = hashHex(raw, end, CHIP_PREFIX_HEX, &d);
    if (d >= CHIP_PREFIX_HEX) sink.emit(h);
  }
}

void walk(JsonArrayConst spools, bool archived_only, Sink& sink,
          int* active, int* archived) {
  for (JsonObjectConst spool : spools) {
    const bool is_archived = spool["archived"] | false;
    if (archived_only && !is_archived) continue;
    if (is_archived) (*archived)++; else (*active)++;

    for (JsonObjectConst t : spool["tags"].as<JsonArrayConst>())
      emitValue(t["uid"] | "", false, sink);

    for (JsonPairConst kv : spool["extra"].as<JsonObjectConst>()) {
      const char* key = kv.key().c_str();
      if (!key) continue;
      // The one key spoolTagRank() passes over as well: a date, not a tag.
      if (strcmp(key, LAST_DRIED_FIELD) == 0) continue;
      if (!kv.value().is<const char*>()) continue;
      const bool chip_field = strcmp(key, CHIP_FIELD_1) == 0 ||
                              strcmp(key, CHIP_FIELD_2) == 0;
      emitValue(kv.value().as<const char*>(), chip_field, sink);
    }
  }
}

bool sameServer() {
  const char* base = backendBaseUrl();
  if (!base) base = "";
  return s_mode == (uint8_t)backendMode() &&
         strncmp(s_key, base, sizeof(s_key) - 1) == 0;
}

int cmpId(const void* a, const void* b) {
  const uint64_t x = *(const uint64_t*)a;
  const uint64_t y = *(const uint64_t*)b;
  return (x > y) - (x < y);
}

void giveUp(const char* why) {
  logSDf("uid index: %s, none kept", why);
  release();
}

}  // namespace

void uidIndexBegin() {
  release();
  // Whatever was to be forgotten is gone with the line above. A forget that
  // arrives from here on is about the index being built, and stays.
  s_forget = false;
  s_state  = IDX_BUILDING;
}

void uidIndexAdd(JsonArrayConst spools, bool archived_only) {
  if (s_state != IDX_BUILDING) return;

  Sink count = { nullptr, 0, 0 };
  int active = 0, archived = 0;
  walk(spools, archived_only, count, &active, &archived);
  s_active   += active;
  s_archived += archived;
  if (count.n == 0) return;

  const size_t total = s_n + count.n;
  if (total > UID_INDEX_MAX_IDS) {
    giveUp("more identifiers than it holds");
    return;
  }

  // A fresh block of the right size and a copy, never a realloc: it would
  // have to grow between the two large documents of the scan.
  uint64_t* blk = (uint64_t*)heap_caps_malloc(total * sizeof(uint64_t), MALLOC_CAP_SPIRAM);
  if (!blk) {
    giveUp("no PSRAM");
    return;
  }
  if (s_ids) {
    memcpy(blk, s_ids, s_n * sizeof(uint64_t));
    free(s_ids);
  }
  s_ids   = blk;
  s_bytes = total * sizeof(uint64_t);

  Sink store = { s_ids + s_n, count.n, 0 };
  int a = 0, z = 0;
  walk(spools, archived_only, store, &a, &z);
  s_n += (store.n < count.n) ? store.n : count.n;
}

void uidIndexCommit(const InventoryStamp* stamp) {
  if (s_state != IDX_BUILDING) return;

  // The same test the list cache makes, for the same reason: a stamp that
  // counted other spools than these vouches for a set this index is not of.
  if (stamp && stamp->count != s_active) {
    logSDf("uid index: the stamp counted %d spools, the scan saw %d, none kept",
           stamp->count, s_active);
    release();
    return;
  }

  if (s_n > 1) {
    qsort(s_ids, s_n, sizeof(uint64_t), cmpId);
    size_t w = 1;
    for (size_t r = 1; r < s_n; r++)
      if (s_ids[r] != s_ids[w - 1]) s_ids[w++] = s_ids[r];
    s_n = w;
  }

  const char* base = backendBaseUrl();
  snprintf(s_key, sizeof(s_key), "%s", base ? base : "");
  s_mode      = (uint8_t)backendMode();
  s_filled_ms = millis();
  if (!s_filled_ms) s_filled_ms = 1;
  s_has_stamp = (stamp != nullptr);
  if (stamp) s_stamp = *stamp;
  s_state = IDX_READY;

  if (s_has_stamp)
    logSDf("uid index: %u ids from %d active + %d archived spools, %u B, stamp %d/%d",
           (unsigned)s_n, s_active, s_archived, (unsigned)s_bytes,
           s_stamp.count, s_stamp.witness_id);
  else
    logSDf("uid index: %u ids from %d active + %d archived spools, %u B, blind",
           (unsigned)s_n, s_active, s_archived, (unsigned)s_bytes);
}

UidIndexReply uidIndexAsk(const char* const* ids, uint8_t count,
                          const InventoryStamp* stamp) {
  UidIndexReply r = { UID_INDEX_SILENT, 0, 0, "" };

  if (s_state != IDX_READY) { r.why = "no index"; return r; }
  r.ids   = (int)s_n;
  r.age_s = (millis() - s_filled_ms) / 1000UL;
  if (s_forget)      { r.why = s_forget_why ? s_forget_why : "forgotten"; return r; }
  if (!sameServer()) { r.why = "other server"; return r; }
  if (millis() - s_filled_ms > UID_INDEX_MAX_AGE_MS) { r.why = "too old"; return r; }

  if ((stamp != nullptr) != s_has_stamp) {
    r.why = s_has_stamp ? "no stamp this time" : "a stamp where there was none";
    return r;
  }
  if (stamp && (stamp->count != s_stamp.count || stamp->witness_id != s_stamp.witness_id)) {
    snprintf(s_why, sizeof(s_why), "stamp %d/%d is now %d/%d", s_stamp.count,
             s_stamp.witness_id, stamp->count, stamp->witness_id);
    r.why = s_why;
    return r;
  }

  bool asked_any = false;
  for (uint8_t i = 0; i < count; i++) {
    const char* id = ids[i];
    if (!id || !id[0]) continue;
    size_t d = 0;
    const uint64_t h = hashHex(id, id + strlen(id), SIZE_MAX, &d);
    // Nothing of that length is ever taken in, so not finding it says nothing.
    if (d < UID_INDEX_ID_MIN_HEX || d > UID_INDEX_ID_MAX_HEX) {
      r.answer = UID_INDEX_MAY_HOLD;
      r.why    = "an identifier is outside the lengths it holds";
      return r;
    }
    asked_any = true;
    if (s_n && bsearch(&h, s_ids, s_n, sizeof(uint64_t), cmpId)) {
      r.answer = UID_INDEX_MAY_HOLD;
      r.why    = "an identifier is in the index";
      return r;
    }
  }
  if (!asked_any) { r.why = "no identifier to ask for"; return r; }

  r.answer = UID_INDEX_ABSENT;
  return r;
}

void uidIndexForget(const char* why) {
  s_forget_why = why;
  s_forget     = true;
}

void uidIndexTick() {
  if (s_state == IDX_NONE) {
    s_forget = false;
    return;
  }
  if (s_state == IDX_BUILDING) {
    // A lookup runs from start to end inside one loop pass, so an index still
    // open here belongs to one that left early: a spool found after all, a
    // failed request, an archive pass that stood aside for a question.
    if (sd_verbose)
      logSDf("[verbose] uid index: the scan did not finish, none kept (%d active seen)",
             s_active);
    release();
    return;
  }
  if (s_forget) { drop(s_forget_why); return; }
  if (millis() - s_filled_ms > UID_INDEX_MAX_AGE_MS) drop("too old");
}
