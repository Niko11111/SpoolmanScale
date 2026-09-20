#include "services/spool_cache.h"

#include <Arduino.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/spool_color.h"   // SPOOL_COLOR_HEX_MAX

namespace {

// What stands in extra[bound_key] of a bound spool on the way back out. It
// only has to be non-empty for the link flow's test; it is spelled so that
// nobody who meets it in a log takes it for a UID.
const char SPOOL_CACHE_BOUND_MARK[] = "~cached~";

// One spool, as much of it as the link flow's filter and its rows read.
//
// THE RULE: whatever linkFilterVerdict() in ui/spool_flow.cpp reads has to be
// in here and has to be written back by spoolCacheToJson(). A field missing
// here makes the kept list filter differently from the downloaded one, and
// spools vanish from the second list that were in the first.
//
// The tag fields themselves are deliberately not kept, only whether any of
// them holds something. Their values decide what a write does, and a value
// that may be half an hour old must not be what a write is built on.
struct CachedSpool {
  int   id;                              //   0
  // The filter sees at most 47 characters of the name from here, where it
  // sees all of it in a download. 29 was the longest in 281 real spools.
  char  name[48];                        //   4  filament.name
  char  vendor[32];                      //  52  filament.vendor.name
  // 24, not the 16 the list row has: "PETG Translucent" is 16 characters and
  // Translucent is a subtype the filter matches on. Cut to 15 it would not.
  char  material[24];                    //  84  filament.material
  // FilaMan and BamBuddy only. Their lists are built field by field and never
  // pass through the Spoolman read filter, so the subtype test does see this.
  // 32, because 16 was one short on the first real library it met:
  // "silk-multi-color" came back out as "silk-multi-colo". Harmless there, but
  // a "silk-translucent" cut the same way no longer says Translucent.
  char  subgroup[32];                    // 108  filament.material_subgroup
  // As it stood in the document, without a '#': both readers put their own
  // in front, and a second one would make every colour compare as far away.
  char  color_hex[SPOOL_COLOR_HEX_MAX];  // 140  filament.color_hex
  bool  bound;                           // 150  some tag field holds something
  // The row of a spool without a name shows "?", one with an empty name shows
  // nothing. Kept apart so the second list reads like the first.
  bool  name_missing;                    // 151
  float remaining;                       // 152  remaining_weight
  // NAN where the filament has no weight: the row then falls back to 1000 g,
  // and a 0 written back would be read as a weight.
  float total;                           // 156  filament.weight
  int   filament_id;                     // 160  filament.id
  float spool_weight;                    // 164  spool_weight
};
static_assert(sizeof(CachedSpool) == 168, "CachedSpool grew, the numbers in the header are off");

CachedSpool*   s_rows      = nullptr;
int            s_count     = 0;
uint32_t       s_filled_ms = 0;          // never 0 while there are rows
time_t         s_filled_at = 0;
bool           s_has_stamp = false;
InventoryStamp s_stamp     = { -1, 0 };

// The server the rows came from. An address or backend change drops them even
// if somebody forgot to say so; a spool id means a different spool over there.
char    s_key[96] = "";
uint8_t s_mode    = 0;

// Set from any task, acted on by the loop. The reason is a string literal, so
// the pointer is all that crosses over.
volatile bool        s_forget     = false;
const char* volatile s_forget_why = nullptr;

void release() {
  if (s_rows) { free(s_rows); s_rows = nullptr; }
  s_count     = 0;
  s_filled_ms = 0;
  s_filled_at = 0;
  s_has_stamp = false;
  s_forget    = false;
}

void drop(const char* why) {
  if (!s_rows) { s_forget = false; return; }
  logSDf("spool cache: %d rows dropped (%s)", s_count, why ? why : "forgotten");
  release();
}

uint32_t ageLimitMs() { return s_has_stamp ? SPOOL_CACHE_MAX_AGE_MS : SPOOL_CACHE_BLIND_MS; }

bool sameServer() {
  const char* base = backendBaseUrl();
  if (!base) base = "";
  return s_mode == (uint8_t)backendMode() &&
         strncmp(s_key, base, sizeof(s_key) - 1) == 0;
}

void copyStr(char* dst, size_t n, JsonVariantConst v) {
  snprintf(dst, n, "%s", v | "");
}

// Forces the pointer overload. Handed the array itself, ArduinoJson 7.4 takes
// a char[N] for a string literal: it would keep the address instead of a copy
// and take all N-1 bytes for the length, whatever follows the terminator.
inline const char* str(const char* s) { return s; }

CachedSpool* rowById(int spool_id) {
  if (!s_rows || s_forget) return nullptr;
  for (int i = 0; i < s_count; i++)
    if (s_rows[i].id == spool_id) return &s_rows[i];
  return nullptr;
}

}  // namespace

void spoolCacheFill(JsonArrayConst spools, SpoolBoundFn is_bound,
                    const InventoryStamp* stamp) {
  // Always a fresh block of exactly the right size, never a realloc: a block
  // that lives for half an hour and grows in place would fragment the PSRAM
  // between the large JSON documents that come and go around it.
  release();
  if (!is_bound) return;

  int n = 0;
  for (JsonObjectConst spool : spools)
    if (!(spool["archived"] | false)) n++;

  if (n == 0) return;
  // The stamp counted the very spools this list holds. A different number
  // means the two do not describe the same set - a spool added between the
  // two requests, or a list that is not the inventory at all - and a stamp
  // vouching for some other list is worse than no copy.
  if (stamp && stamp->count != n) {
    logSDf("spool cache: the stamp counted %d spools, the list has %d, not kept",
           stamp->count, n);
    return;
  }
  if (n > SPOOL_CACHE_MAX) {
    logSDf("spool cache: %d spools, more than %d, not kept", n, SPOOL_CACHE_MAX);
    return;
  }

  // PSRAM or nothing. The list of a single link may fall back to internal RAM
  // because it is gone in a minute; this block is not, and the free bytes in
  // there belong to LVGL and the TLS buffers.
  s_rows = (CachedSpool*)heap_caps_malloc((size_t)n * sizeof(CachedSpool), MALLOC_CAP_SPIRAM);
  if (!s_rows) {
    logSDf("spool cache: no PSRAM for %d rows, not kept", n);
    return;
  }

  for (JsonObjectConst spool : spools) {
    // No field for it in the row, and every row goes back out as active. No
    // backend sends archived spools with an active list today, but two of the
    // three build their list themselves and this does not depend on it.
    if (spool["archived"] | false) continue;
    if (s_count >= n) break;

    CachedSpool& r = s_rows[s_count++];
    JsonObjectConst fil = spool["filament"];
    r.id           = spool["id"] | 0;
    r.name_missing = fil["name"].isNull();
    copyStr(r.name,      sizeof(r.name),      fil["name"]);
    copyStr(r.vendor,    sizeof(r.vendor),    fil["vendor"]["name"]);
    copyStr(r.material,  sizeof(r.material),  fil["material"]);
    copyStr(r.subgroup,  sizeof(r.subgroup),  fil["material_subgroup"]);
    copyStr(r.color_hex, sizeof(r.color_hex), fil["color_hex"]);
    r.bound        = is_bound(spool);
    r.remaining    = spool["remaining_weight"] | 0.0f;
    r.total        = fil["weight"].is<float>() ? fil["weight"].as<float>() : NAN;
    r.filament_id  = fil["id"] | 0;
    r.spool_weight = spool["spool_weight"] | 0.0f;
  }

  const char* base = backendBaseUrl();
  snprintf(s_key, sizeof(s_key), "%s", base ? base : "");
  s_mode      = (uint8_t)backendMode();
  s_filled_ms = millis();
  if (!s_filled_ms) s_filled_ms = 1;
  // With the 0: without it the call waits up to five seconds for a clock that
  // was never set.
  struct tm ti;
  s_filled_at = getLocalTime(&ti, 0) ? time(nullptr) : 0;
  s_has_stamp = (stamp != nullptr);
  if (stamp) s_stamp = *stamp;

  const unsigned kb = (unsigned)(((size_t)s_count * sizeof(CachedSpool) + 512) / 1024);
  if (s_has_stamp)
    logSDf("spool cache: %d rows, %u kB, stamp %d/%d", s_count, kb,
           s_stamp.count, s_stamp.witness_id);
  else
    logSDf("spool cache: %d rows, %u kB, blind", s_count, kb);
}

bool spoolCacheUsable(const InventoryStamp* stamp) {
  if (!s_rows) { s_forget = false; return false; }
  if (s_forget)      { drop(s_forget_why); return false; }
  if (!sameServer()) { drop("other server"); return false; }
  if (millis() - s_filled_ms > ageLimitMs()) { drop("too old"); return false; }

  if ((stamp != nullptr) != s_has_stamp) {
    drop(s_has_stamp ? "no stamp this time" : "a stamp where there was none");
    return false;
  }
  if (stamp && (stamp->count != s_stamp.count || stamp->witness_id != s_stamp.witness_id)) {
    char why[64];
    snprintf(why, sizeof(why), "stamp %d/%d is now %d/%d", s_stamp.count,
             s_stamp.witness_id, stamp->count, stamp->witness_id);
    drop(why);
    return false;
  }
  return true;
}

bool spoolCacheToJson(JsonDocument& doc, const char* bound_key) {
  if (!s_rows || s_forget || s_count <= 0 || !bound_key || !bound_key[0]) return false;

  doc.clear();
  JsonArray out = doc.to<JsonArray>();
  for (int i = 0; i < s_count; i++) {
    const CachedSpool& r = s_rows[i];
    JsonObject o = out.add<JsonObject>();
    o["id"]               = r.id;
    o["remaining_weight"] = r.remaining;
    o["spool_weight"]     = r.spool_weight;
    if (r.bound) o["extra"][str(bound_key)] = SPOOL_CACHE_BOUND_MARK;

    JsonObject f = o["filament"].to<JsonObject>();
    f["id"] = r.filament_id;
    if (!r.name_missing) f["name"]              = str(r.name);
    f["material"]                               = str(r.material);
    if (r.subgroup[0])   f["material_subgroup"] = str(r.subgroup);
    if (!isnan(r.total)) f["weight"]            = r.total;
    f["color_hex"]                              = str(r.color_hex);
    if (r.vendor[0])     f["vendor"]["name"]    = str(r.vendor);
  }

  if (doc.overflowed()) {
    logSDf("spool cache: no memory to hand out %d rows, downloading instead", s_count);
    doc.clear();
    return false;
  }
  logSDf("spool cache: %d rows served, %lu s old%s", s_count,
         (unsigned long)((millis() - s_filled_ms) / 1000UL), s_has_stamp ? "" : ", blind");
  return true;
}

void spoolCacheSetBound(int spool_id, bool bound) {
  CachedSpool* r = rowById(spool_id);
  if (r) r->bound = bound;
}

void spoolCacheSetRemaining(int spool_id, float remaining) {
  CachedSpool* r = rowById(spool_id);
  if (r) r->remaining = remaining;
}

void spoolCacheForget(const char* why) {
  s_forget_why = why;
  s_forget     = true;
}

void spoolCacheTick() {
  if (!s_rows) { s_forget = false; return; }
  if (s_forget) { drop(s_forget_why); return; }
  if (millis() - s_filled_ms > ageLimitMs()) drop("too old");
}

int spoolCacheRows() { return (s_rows && !s_forget) ? s_count : 0; }

uint32_t spoolCacheAgeMs() { return (s_rows && s_filled_ms) ? millis() - s_filled_ms : 0; }

time_t spoolCacheFilledAt() { return (s_rows && !s_forget) ? s_filled_at : 0; }
