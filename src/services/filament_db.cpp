#include "filament_db.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "../app/backend_switch.h"
#include "../hardware/sd_logger.h"
#include "backend.h"
#include "backend_api.h"
#include "text_util.h"

// The task, on the terms of the backend job (backend_job.cpp): core 0, below
// the loop, its stack from the heap and a floor checked before it is taken.
#define FDB_STACK_BYTES   16384
#define FDB_PRIORITY      1
#define FDB_CORE          0
#define FDB_MIN_HEAP      60000
// The index is the whole database; read again after this long.
#define FDB_INDEX_MAX_AGE_MS  (24UL * 60UL * 60UL * 1000UL)

// ---- storage, in PSRAM while the picker is open -------------------

static FdbMaker* s_makers  = nullptr;
static FdbPair*  s_pairs   = nullptr;
static FdbEntry* s_entries = nullptr;
static FdbCore*  s_cores   = nullptr;
static int       s_maker_n = 0;
static int       s_pair_n  = 0;
static int       s_entry_n = 0;
static int       s_core_n  = 0;
// The backend generation under which the server said it has no database.
static bool      s_missing     = false;
static uint32_t  s_missing_gen = 0;
static bool      s_index_ok   = false;
static uint32_t  s_index_gen  = 0;
static uint32_t  s_index_ms   = 0;

// ---- the job --------------------------------------------------------

static volatile FdbState s_state = FDB_IDLE;
static volatile size_t   s_bytes = 0;
static FdbJob   s_job  = FDB_JOB_NONE;
static int      s_code = 0;
static uint32_t s_gen  = 0;
// Copies of what the job works with: the loop may rewrite the originals
// while the task reads them.
static char     s_base[96]     = "";
static char     s_maker[32]    = "";
static char     s_material[17] = "";

template <typename T>
static T* psramArray(T* p, size_t n) {
  if (p) return p;
  void* m = heap_caps_calloc(n, sizeof(T), MALLOC_CAP_SPIRAM);
  if (!m) m = calloc(n, sizeof(T));
  return (T*)m;
}

static void freeIndex() {
  heap_caps_free(s_makers);
  heap_caps_free(s_pairs);
  heap_caps_free(s_cores);
  s_makers = nullptr;
  s_pairs = nullptr;
  s_cores = nullptr;
  s_maker_n = s_pair_n = s_core_n = 0;
  s_index_ok = false;
}

static void freeEntries() {
  heap_caps_free(s_entries);
  s_entries = nullptr;
  s_entry_n = 0;
}

void fdbReleaseEntries() {
  if (s_state == FDB_RUNNING) return;   // the task may still write into them
  freeEntries();
}

// ---- filling --------------------------------------------------------

static int findMaker(const char* name) {
  for (int i = 0; i < s_maker_n; i++)
    if (strcasecmp(s_makers[i].name, name) == 0) return i;
  return -1;
}

static int addMaker(const char* name) {
  const int i = findMaker(name);
  if (i >= 0 || s_maker_n >= FDB_MAKERS_MAX) return i;
  FdbMaker& m = s_makers[s_maker_n];
  snprintf(m.name, sizeof(m.name), "%s", name);
  m.count = 0;
  m.owned = false;
  m.pairs_known = false;
  return s_maker_n++;
}

void fdbMakerAdd(const char* maker, uint16_t count) {
  if (!s_makers || !maker || !maker[0]) return;
  const int mi = addMaker(maker);
  if (mi >= 0) s_makers[mi].count = count;
}

void fdbIndexAdd(const char* maker, const char* material) {
  if (!s_makers || !s_pairs || !maker || !maker[0] || !material || !material[0]) return;
  const int mi = addMaker(maker);
  if (mi < 0) return;
  // A maker that came without its materials keeps the database's own count;
  // fdbTake() marks it once they are in.
  if (s_job == FDB_JOB_INDEX) {
    s_makers[mi].count++;
    s_makers[mi].pairs_known = true;
  }
  for (int i = 0; i < s_pair_n; i++) {
    if (s_pairs[i].maker == mi && strcasecmp(s_pairs[i].material, material) == 0) {
      s_pairs[i].count++;
      return;
    }
  }
  if (s_pair_n >= FDB_PAIRS_MAX) return;
  FdbPair& p = s_pairs[s_pair_n++];
  p.maker = (uint16_t)mi;
  snprintf(p.material, sizeof(p.material), "%s", material);
  p.count = 1;
}

static uint16_t addCounts(uint16_t a, uint16_t b) {
  const uint32_t sum = (uint32_t)a + b;
  return sum > UINT16_MAX ? UINT16_MAX : (uint16_t)sum;
}

void fdbPairAdd(const char* maker, const char* material, uint16_t count) {
  if (!s_makers || !s_pairs || !maker || !maker[0] || !material || !material[0]) return;
  const int mi = addMaker(maker);
  if (mi < 0) return;
  s_makers[mi].pairs_known = true;
  s_makers[mi].count = addCounts(s_makers[mi].count, count);
  for (int i = 0; i < s_pair_n; i++) {
    if (s_pairs[i].maker == mi && strcasecmp(s_pairs[i].material, material) == 0) {
      s_pairs[i].count = addCounts(s_pairs[i].count, count);
      return;
    }
  }
  if (s_pair_n >= FDB_PAIRS_MAX) return;
  FdbPair& p = s_pairs[s_pair_n++];
  p.maker = (uint16_t)mi;
  snprintf(p.material, sizeof(p.material), "%s", material);
  p.count = count;
}

void fdbMarkOwned(const char* maker) {
  if (!s_makers || !maker) return;
  const int i = findMaker(maker);
  if (i >= 0) s_makers[i].owned = true;
}

bool fdbEntryAdd(const FdbEntry& e) {
  if (!s_entries || s_entry_n >= FDB_ENTRIES_MAX) return false;
  s_entries[s_entry_n++] = e;
  return true;
}

bool fdbEntryListed(const FdbEntry& e) {
  for (int i = 0; s_entries && i < s_entry_n; i++)
    if (s_entries[i].weight_g == e.weight_g && strcmp(s_entries[i].name, e.name) == 0) return true;
  return false;
}

volatile size_t* fdbBytesCounter() { return &s_bytes; }

int fdbIndexSnapshot(const FdbMaker** makers, const FdbPair** pairs, int* pair_n) {
  if (!s_makers || !s_pairs) return 0;
  *makers = s_makers;
  *pairs  = s_pairs;
  *pair_n = s_pair_n;
  return s_maker_n;
}

bool fdbIndexRestore(const FdbMaker* makers, int maker_n, const FdbPair* pairs, int pair_n) {
  if (!s_makers || !s_pairs || maker_n > FDB_MAKERS_MAX || pair_n > FDB_PAIRS_MAX) return false;
  // A pair pointing past the makers would index out of the array later.
  for (int i = 0; i < pair_n; i++)
    if (pairs[i].maker >= maker_n) return false;
  memcpy(s_makers, makers, sizeof(FdbMaker) * (size_t)maker_n);
  memcpy(s_pairs, pairs, sizeof(FdbPair) * (size_t)pair_n);
  for (int i = 0; i < maker_n; i++) {
    s_makers[i].owned = false;
    s_makers[i].pairs_known = true;   // a stored index holds every pair
    s_makers[i].name[sizeof(s_makers[i].name) - 1] = '\0';
  }
  for (int i = 0; i < pair_n; i++) s_pairs[i].material[sizeof(s_pairs[i].material) - 1] = '\0';
  s_maker_n = maker_n;
  s_pair_n  = pair_n;
  return true;
}

// ---- sorting, once a load is in --------------------------------------

// A-Z, case aside. The pairs point at makers by index, so they are moved to
// the new positions too. Insertion sort: a database has a hundred makers.
static void sortMakers() {
  FdbMaker* old = (FdbMaker*)malloc(sizeof(FdbMaker) * (size_t)s_maker_n);
  uint16_t* order = (uint16_t*)malloc(sizeof(uint16_t) * (size_t)s_maker_n);
  uint16_t* new_of_old = (uint16_t*)malloc(sizeof(uint16_t) * (size_t)s_maker_n);
  if (old && order && new_of_old) {
    memcpy(old, s_makers, sizeof(FdbMaker) * (size_t)s_maker_n);
    for (int i = 0; i < s_maker_n; i++) {
      int j = i - 1;
      while (j >= 0 && strcasecmp(old[order[j]].name, old[i].name) > 0) { order[j + 1] = order[j]; j--; }
      order[j + 1] = (uint16_t)i;
    }
    for (int k = 0; k < s_maker_n; k++) {
      s_makers[k] = old[order[k]];
      new_of_old[order[k]] = (uint16_t)k;
    }
    for (int i = 0; i < s_pair_n; i++) s_pairs[i].maker = new_of_old[s_pairs[i].maker];
  }
  free(old);
  free(order);
  free(new_of_old);
}

static int byEntryName(const void* a, const void* b) {
  const FdbEntry* x = (const FdbEntry*)a;
  const FdbEntry* y = (const FdbEntry*)b;
  const int c = strcasecmp(x->name, y->name);
  return c ? c : (int)x->weight_g - (int)y->weight_g;
}

// ---- the task ---------------------------------------------------------

static void runJob() {
  if (s_job == FDB_JOB_INDEX) {
    s_code = backendFdbLoadIndex(s_base);
    return;
  }
  if (s_job == FDB_JOB_PAIRS) {
    s_code = backendFdbLoadPairs(s_base, s_maker);
    return;
  }
  s_code = backendFdbLoadEntries(s_base, s_maker, s_material);
}

static const char* jobName(FdbJob job) {
  return job == FDB_JOB_INDEX ? "index" : job == FDB_JOB_PAIRS ? "materials" : "entries";
}

static void fdbTask(void* arg) {
  (void)arg;
  const uint32_t t0 = millis();
  runJob();
  logSDf("Filament DB: %s done in %lu ms, code=%d, %u bytes, %d makers, %d pairs, %d entries, stack left %u",
         jobName(s_job), (unsigned long)(millis() - t0), s_code,
         (unsigned)s_bytes, s_maker_n, s_pair_n, s_entry_n,
         (unsigned)uxTaskGetStackHighWaterMark(NULL));
  __sync_synchronize();   // the results before the state, see backend_job.cpp
  s_state = FDB_DONE;
  vTaskDelete(NULL);
}

static bool startTask(FdbJob job) {
  if (s_state != FDB_IDLE) return false;
  if (ESP.getFreeHeap() < FDB_MIN_HEAP) {
    logSDf("Filament DB: postponed, heap %u", (unsigned)ESP.getFreeHeap());
    return false;
  }
  s_job   = job;
  s_code  = 0;
  s_bytes = 0;
  s_gen   = backendGeneration();
  snprintf(s_base, sizeof(s_base), "%s", backendBaseUrl());
  s_state = FDB_RUNNING;   // before the task exists: it may finish at once
  if (xTaskCreatePinnedToCore(fdbTask, "filamentdb", FDB_STACK_BYTES, nullptr,
                              FDB_PRIORITY, nullptr, FDB_CORE) != pdPASS) {
    s_state = FDB_IDLE;
    logSD("Filament DB: task creation failed");
    return false;
  }
  return true;
}

bool fdbStartIndex() {
  if (s_state != FDB_IDLE) return false;
  freeIndex();
  s_makers = psramArray(s_makers, FDB_MAKERS_MAX);
  s_pairs  = psramArray(s_pairs, FDB_PAIRS_MAX);
  if (!s_makers || !s_pairs) { freeIndex(); logSD("Filament DB: no memory for the index"); return false; }
  return startTask(FDB_JOB_INDEX);
}

bool fdbStartEntries(const char* maker, const char* material) {
  if (s_state != FDB_IDLE || !maker || !material) return false;
  freeEntries();
  s_entries = psramArray(s_entries, FDB_ENTRIES_MAX);
  if (!s_entries) { logSD("Filament DB: no memory for the list"); return false; }
  snprintf(s_maker, sizeof(s_maker), "%s", maker);
  snprintf(s_material, sizeof(s_material), "%s", material);
  return startTask(FDB_JOB_ENTRIES);
}

// The pairs of the makers looked at before are dropped when the next one
// might not fit: a maker of the FilamentDB has up to 40 materials.
#define FDB_PAIRS_ROOM  64

static void dropLoadedPairs() {
  for (int i = 0; i < s_maker_n; i++) s_makers[i].pairs_known = false;
  s_pair_n = 0;
}

bool fdbStartPairs(const char* maker) {
  if (s_state != FDB_IDLE || !maker || !s_index_ok) return false;
  if (s_pair_n > FDB_PAIRS_MAX - FDB_PAIRS_ROOM) dropLoadedPairs();
  snprintf(s_maker, sizeof(s_maker), "%s", maker);
  return startTask(FDB_JOB_PAIRS);
}

FdbState fdbState() { return s_state; }
FdbJob   fdbJob()   { return s_job; }
size_t   fdbBytes() { return s_bytes; }
int      fdbResultCode() { return s_code; }
bool     fdbResultCurrent() { return s_gen == backendGeneration(); }

bool fdbOffered() {
  if (!backendCanBrowseFilamentDb()) return false;
  return !(s_missing && s_missing_gen == backendGeneration());
}

void fdbTake() {
  if (s_state != FDB_DONE) return;
  const bool ok = s_code == 200 && fdbResultCurrent();
  if (s_code == 404 || s_code == 405) { s_missing = true; s_missing_gen = s_gen; }
  if (s_job == FDB_JOB_PAIRS) {
    // The maker counts as looked at even without a material of 1.75 mm; a
    // failure leaves it to be asked again.
    const int mi = findMaker(s_maker);
    if (ok && mi >= 0) s_makers[mi].pairs_known = true;
  } else if (s_job == FDB_JOB_INDEX) {
    if (ok) {
      sortMakers();
      s_index_ok  = true;
      s_index_gen = s_gen;
      s_index_ms  = millis();
    } else {
      freeIndex();
    }
  } else if (ok) {
    qsort(s_entries, (size_t)s_entry_n, sizeof(FdbEntry), byEntryName);
  } else {
    freeEntries();
  }
  s_job   = FDB_JOB_NONE;
  s_state = FDB_IDLE;
}

bool fdbIndexReady() {
  return s_index_ok && s_index_gen == backendGeneration() &&
         millis() - s_index_ms < FDB_INDEX_MAX_AGE_MS;
}

// ---- reading ------------------------------------------------------------

int             fdbMakerCount()      { return s_index_ok ? s_maker_n : 0; }
const FdbMaker* fdbMaker(int i)      { return (s_index_ok && i >= 0 && i < s_maker_n) ? &s_makers[i] : nullptr; }
const FdbPair*  fdbPair(int i)       { return (s_index_ok && i >= 0 && i < s_pair_n) ? &s_pairs[i] : nullptr; }
int             fdbEntryCount()      { return s_entries ? s_entry_n : 0; }
const FdbEntry* fdbEntry(int i)      { return (s_entries && i >= 0 && i < s_entry_n) ? &s_entries[i] : nullptr; }

bool fdbMakerHasPairs(int maker) {
  const FdbMaker* m = fdbMaker(maker);
  return m && m->pairs_known;
}

int fdbPairsOf(int maker, uint16_t* out, int out_max) {
  int n = 0;
  for (int i = 0; i < s_pair_n && n < out_max; i++)
    if (s_pairs[i].maker == maker) out[n++] = (uint16_t)i;
  // Most filaments first: PLA ahead of PVA. Insertion sort, a maker has a few.
  for (int i = 1; i < n; i++) {
    const uint16_t v = out[i];
    int j = i - 1;
    while (j >= 0 && s_pairs[out[j]].count < s_pairs[v].count) { out[j + 1] = out[j]; j--; }
    out[j + 1] = v;
  }
  return n;
}

// ---- the name on the screen ------------------------------------------------

// UTF-8 sequences the fonts cannot draw, and what stands in for them. The
// fonts have ASCII, the German and the French letters (lang.h); SpoolmanDB
// names use a few more.
struct GlyphSwap { const char* from; const char* to; };
static const GlyphSwap GLYPH_SWAPS[] = {
  { "\xE2\x84\xA2", "" },    // ™
  { "\xC2\xAE", "" },         // ®
  { "\xC2\xA0", " " },        // no-break space
  { "\xC3\xA1", "a" }, { "\xC3\xAD", "i" }, { "\xC3\xB3", "o" },
  { "\xC3\xBA", "u" }, { "\xC3\xB1", "n" },
};
#define FDB_FORMERLY  "(Formerly "

static void swapGlyphs(const char* in, char* out, size_t out_size) {
  size_t o = 0;
  while (*in && o + 1 < out_size) {
    bool swapped = false;
    for (const GlyphSwap& g : GLYPH_SWAPS) {
      const size_t n = strlen(g.from);
      if (strncmp(in, g.from, n) != 0) continue;
      for (const char* t = g.to; *t && o + 1 < out_size; t++) out[o++] = *t;
      in += n;
      swapped = true;
      break;
    }
    if (!swapped) out[o++] = *in++;
  }
  out[o] = '\0';
}

// Removes the characters from "from" up to "to", in place.
static void cutSpan(char* from, const char* to) {
  memmove(from, to, strlen(to) + 1);
}

// Drops every occurrence of word that stands as words of its own.
static void dropWords(char* text, const char* word) {
  const size_t n = strlen(word);
  for (char* p = text; n && (p = strcasestr(p, word)) != nullptr; ) {
    const bool starts = p == text || p[-1] == ' ';
    const bool ends = p[n] == '\0' || p[n] == ' ';
    if (starts && ends) cutSpan(p, p + n);
    else p += n;
  }
}

// Drops the "(Formerly ...)" note.
static void dropFormerly(char* text) {
  char* f = strcasestr(text, FDB_FORMERLY);
  const char* close = f ? strchr(f, ')') : nullptr;
  if (f && close) cutSpan(f, close + 1);
}

// Single spaces, none at either end.
static void squeezeSpaces(char* text) {
  char* o = text;
  for (const char* p = text; *p; p++) {
    if (*p == ' ' && (o == text || o[-1] == ' ')) continue;
    *o++ = *p;
  }
  while (o > text && o[-1] == ' ') o--;
  *o = '\0';
}

void fdbDisplayName(const char* name, const char* maker, const char* material,
                    char* out, size_t out_size) {
  if (!out || !out_size) return;
  swapGlyphs(name ? name : "", out, out_size);
  char shown[FDB_NAME_MAX];
  snprintf(shown, sizeof(shown), "%s", out);
  dropFormerly(shown);
  dropWords(shown, maker ? maker : "");
  dropWords(shown, material ? material : "");
  squeezeSpaces(shown);
  // A name that was nothing but maker and material keeps them.
  if (shown[0]) snprintf(out, out_size, "%s", shown);
}

void fdbEntryDisplayName(const FdbEntry& e, const char* maker, const char* material,
                         char* out, size_t out_size) {
  const size_t at = e.color_at < strlen(e.name) ? e.color_at : 0;
  fdbDisplayName(e.name + at, maker, material, out, out_size);
}

// The FilamentDB's line in front of the colour: "Panchroma Matte - " and
// "   Other    - " leave "Panchroma Matte" and "Other".
static void linePrefix(const FdbEntry& e, char* out, size_t out_size) {
  out[0] = '\0';
  if (e.color_at == 0 || e.color_at >= sizeof(e.name)) return;
  char head[FDB_NAME_MAX];
  snprintf(head, sizeof(head), "%.*s", (int)e.color_at, e.name);
  char* dash = strstr(head, " - ");
  if (dash) *dash = '\0';
  squeezeSpaces(head);
  char* start = head;
  while (*start == ' ') start++;
  swapGlyphs(start, out, out_size);
}

// "high-speed-matte" as "High Speed Matte".
static void slugWords(const char* slug, char* out, size_t out_size) {
  size_t o = 0;
  bool word_start = true;
  for (const char* p = slug; *p && o + 1 < out_size; p++) {
    const char c = *p == '-' || *p == '_' ? ' ' : *p;
    out[o++] = word_start && c >= 'a' && c <= 'z' ? (char)(c - 'a' + 'A') : c;
    word_start = c == ' ';
  }
  out[o] = '\0';
  squeezeSpaces(out);
}

#define FDB_LINE_OTHER  "---other---"

void fdbLineName(const FdbEntry& e, const char* other_text, char* out, size_t out_size) {
  if (!out || !out_size) return;
  if (strcmp(e.line, FDB_LINE_OTHER) == 0) { snprintf(out, out_size, "%s", other_text); return; }
  linePrefix(e, out, out_size);
  if (!out[0]) slugWords(e.line, out, out_size);
}

// ---- the input for a new spool -------------------------------------------

void fdbEntryToInput(const FdbEntry& e, const char* maker, const char* material,
                     TagCreateInput* in) {
  memset(in, 0, sizeof(*in));
  snprintf(in->vendor, sizeof(in->vendor), "%s", maker);
  snprintf(in->material, sizeof(in->material), "%s", material);
  snprintf(in->db_id, sizeof(in->db_id), "%s", e.id);
  snprintf(in->db_name, sizeof(in->db_name), "%s", e.name);
  snprintf(in->subtype, sizeof(in->subtype), "%s", e.line);
  snprintf(in->db_line, sizeof(in->db_line), "%s", e.line);
  // The colour's name as the database spells it, for a filament made from
  // the entry: the end of a FilamentDB designation, a whole SpoolmanDB name.
  const size_t at = e.color_at < strlen(e.name) ? e.color_at : 0;
  snprintf(in->db_color_name, sizeof(in->db_color_name), "%s", e.name + at);
  snprintf(in->db_color_hex, sizeof(in->db_color_hex), "%s", e.db_hex);
  // A clear filament names no hue, the way a clear Bambu tag is read.
  in->clear = e.family == CF_CLEAR;
  for (uint8_t i = 0; !in->clear && i < e.ncolors && i < TAG_CREATE_COLOURS; i++)
    tagCreateAddColor(in, (uint32_t)strtoul(e.hex[i], nullptr, 16));
  in->color_kind = e.kind;
  // BamBuddy's colour with its alpha; a clear filament is 00000000.
  if (in->clear) snprintf(in->rgba, sizeof(in->rgba), "00000000");
  else           snprintf(in->rgba, sizeof(in->rgba), "%sFF", in->color_hex);
  // What the card shows: the material, then the database's own name.
  snprintf(in->product, sizeof(in->product), "%s", material);
  char shown[sizeof(e.name)];
  fdbEntryDisplayName(e, maker, material, shown, sizeof(shown));
  utf8Cut(shown, sizeof(in->color_name) - 1, in->color_name, sizeof(in->color_name));
  in->net_weight_g   = e.weight_g;
  in->spool_weight_g = e.spool_weight_g;
  in->diameter_mm    = FDB_DIAMETER_MM;
  in->temp_max       = e.extruder_temp;
  in->db_density     = e.density;
  in->db_bed_temp    = e.bed_temp;
  in->names_known    = true;
}

// ---- empty spools ------------------------------------------------------------

// The catalog spells the maker in front, " - " before the kind of spool:
// "Sunlu - Plastic", "Sunlu 250g - Plastic". Case aside: "ProtoPasta" in the
// catalog is "Protopasta" in the colours.
#define FDB_CORE_KIND_SEP  " - "

static bool coreOfMaker(const FdbCore& c, const char* maker) {
  const size_t n = maker ? strlen(maker) : 0;
  return n && strncasecmp(c.name, maker, n) == 0 && c.name[n] == ' ';
}

bool fdbCoreAdd(const char* name, uint16_t weight_g, int id) {
  if (!name || !name[0] || weight_g == 0) return true;
  s_cores = psramArray(s_cores, FDB_CORES_MAX);
  if (!s_cores || s_core_n >= FDB_CORES_MAX) return false;
  FdbCore& c = s_cores[s_core_n++];
  snprintf(c.name, sizeof(c.name), "%s", name);
  c.weight_g   = weight_g;
  c.id         = id;
  c.last_spool = 0;
  return true;
}

static FdbCore* coreFor(const char* brand, int catalog_id, int core_weight_g) {
  for (int i = 0; s_cores && i < s_core_n; i++) {
    FdbCore& c = s_cores[i];
    if (catalog_id > 0 ? c.id == catalog_id : (coreOfMaker(c, brand) && c.weight_g == core_weight_g))
      return &c;
  }
  return nullptr;
}

void fdbCoreNoteOwned(const char* brand, int catalog_id, int core_weight_g, int spool_id) {
  FdbCore* c = coreFor(brand, catalog_id, core_weight_g);
  if (c && spool_id > c->last_spool) c->last_spool = spool_id;
}

int fdbCoreChoices(const char* maker, const FdbCore** out, int out_max) {
  int n = 0, used = -1;
  for (int i = 0; s_cores && i < s_core_n && n < out_max; i++) {
    if (!coreOfMaker(s_cores[i], maker)) continue;
    out[n] = &s_cores[i];
    if (out[n]->last_spool > 0 && (used < 0 || out[n]->last_spool > out[used]->last_spool)) used = n;
    n++;
  }
  // The one the inventory used last goes first, the rest keep the
  // catalog's order.
  for (int i = used; i > 0; i--) {
    const FdbCore* t = out[i];
    out[i] = out[i - 1];
    out[i - 1] = t;
  }
  return n;
}

void fdbCoreShortName(const FdbCore& c, const char* maker, char* out, size_t out_size) {
  if (!out || !out_size) return;
  const char* rest = coreOfMaker(c, maker) ? c.name + strlen(maker) : c.name;
  char head[FDB_CORE_NAME_MAX];
  snprintf(head, sizeof(head), "%s", rest);
  char* sep = strstr(head, FDB_CORE_KIND_SEP);
  const char* kind = sep ? sep + strlen(FDB_CORE_KIND_SEP) : "";
  if (sep) *sep = '\0';
  squeezeSpaces(head);
  const char* size = head[0] == ' ' ? head + 1 : head;
  snprintf(out, out_size, "%s%s%s", size, size[0] && kind[0] ? " " : "", kind);
}
