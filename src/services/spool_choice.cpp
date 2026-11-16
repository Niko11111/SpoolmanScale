#include "services/spool_choice.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "services/spool_catalog_data.h"
#include "services/tare_chain.h"

// A name compared by its letters and digits only, lower case: "Bambu Lab",
// "BambuLab" and "bambu-lab" are one maker.
#define SPOOL_NAME_KEY_MAX  SPOOL_CHOICE_NAME_MAX
// The fields of the NVS line, separated by '|': weight, source, kind, net,
// catalog id, name.
#define SPOOL_TEXT_FIELDS   6

void spoolChoiceClear(SpoolChoice* c) {
  if (c) memset(c, 0, sizeof(*c));
}

bool spoolChoiceActive(const SpoolChoice& c) { return c.weight_g > 0; }

bool spoolChoiceSame(const SpoolChoice& a, const SpoolChoice& b) {
  return a.weight_g == b.weight_g && a.kind == b.kind && strcmp(a.name, b.name) == 0;
}

int spoolChoiceTare(const SpoolChoice& c, int chain_g, uint8_t* from, TareQuality* quality) {
  if (!spoolChoiceActive(c)) return chain_g;
  // Written to the spool itself, and as good as a stored weight: someone
  // looked it up or weighed it for this very spool.
  if (from) *from = TARE_SPOOL;
  if (quality) *quality = TARE_Q_KNOWN;
  return c.weight_g;
}

int spoolCatalogMakerCount() { return SPOOL_CATALOG_MAKER_COUNT; }

const char* spoolCatalogMakerName(int maker) {
  if (maker < 0 || maker >= SPOOL_CATALOG_MAKER_COUNT) return "";
  return SPOOL_CATALOG_MAKERS[maker].name;
}

int spoolCatalogSpoolCount(int maker) {
  if (maker < 0 || maker >= SPOOL_CATALOG_MAKER_COUNT) return 0;
  return SPOOL_CATALOG_MAKERS[maker].count;
}

bool spoolCatalogChoice(int maker, int k, SpoolChoice* out) {
  if (!out || k < 0 || k >= spoolCatalogSpoolCount(maker)) return false;
  const SpoolCatalogSpool& s = SPOOL_CATALOG_SPOOLS[SPOOL_CATALOG_MAKERS[maker].first + k];
  spoolChoiceClear(out);
  out->weight_g = s.weight_g;
  out->net_g    = s.net_g;
  out->kind     = s.kind;
  out->source   = SCS_CATALOG;
  snprintf(out->name, sizeof(out->name), "%s", SPOOL_CATALOG_MAKERS[maker].name);
  return true;
}

static void nameKey(const char* name, char* key, size_t key_size) {
  size_t n = 0;
  for (; name && *name && n + 1 < key_size; name++) {
    if (isalnum((unsigned char)*name)) key[n++] = (char)tolower((unsigned char)*name);
  }
  key[n] = '\0';
}

int spoolCatalogFindMaker(const char* name) {
  char want[SPOOL_NAME_KEY_MAX], have[SPOOL_NAME_KEY_MAX];
  nameKey(name, want, sizeof(want));
  if (!want[0]) return -1;
  for (int i = 0; i < SPOOL_CATALOG_MAKER_COUNT; i++) {
    nameKey(SPOOL_CATALOG_MAKERS[i].name, have, sizeof(have));
    if (strcmp(want, have) == 0) return i;
  }
  return -1;
}

void spoolRecentPush(SpoolChoice list[SPOOL_RECENT_MAX], const SpoolChoice& c) {
  if (!list || !spoolChoiceActive(c)) return;
  SpoolChoice kept[SPOOL_RECENT_MAX];
  int n = 0;
  kept[n++] = c;
  for (int i = 0; i < SPOOL_RECENT_MAX && n < SPOOL_RECENT_MAX; i++) {
    if (spoolChoiceActive(list[i]) && !spoolChoiceSame(list[i], c)) kept[n++] = list[i];
  }
  for (int i = 0; i < SPOOL_RECENT_MAX; i++) {
    if (i < n) list[i] = kept[i];
    else       spoolChoiceClear(&list[i]);
  }
}

bool spoolChoiceEncode(const SpoolChoice& c, char* out, size_t out_size) {
  if (!out || out_size == 0) return false;
  // '|' separates the fields: a name that holds one would not come back.
  if (strchr(c.name, '|')) { out[0] = '\0'; return false; }
  const int n = snprintf(out, out_size, "%u|%u|%u|%u|%d|%s", (unsigned)c.weight_g,
                         (unsigned)c.source, (unsigned)c.kind, (unsigned)c.net_g, c.catalog_id, c.name);
  return n > 0 && (size_t)n < out_size;
}

// One number up to the next '|': false when there is none, or anything else.
static bool takeNumber(const char** p, long* value) {
  char* end = nullptr;
  *value = strtol(*p, &end, 10);
  if (end == *p || *end != '|') return false;
  *p = end + 1;
  return true;
}

bool spoolChoiceDecode(const char* text, SpoolChoice* out) {
  if (!text || !out) return false;
  long v[SPOOL_TEXT_FIELDS - 1];
  const char* p = text;
  for (int i = 0; i < SPOOL_TEXT_FIELDS - 1; i++) {
    if (!takeNumber(&p, &v[i])) return false;
  }
  if (v[0] <= 0 || v[0] > UINT16_MAX || v[3] < 0 || v[3] > UINT16_MAX) return false;
  if (v[1] < SCS_CATALOG || v[1] > SCS_SERVER || v[2] < SPOOL_KIND_ANY || v[2] > SPOOL_KIND_METAL) return false;
  spoolChoiceClear(out);
  out->weight_g   = (uint16_t)v[0];
  out->source     = (uint8_t)v[1];
  out->kind       = (uint8_t)v[2];
  out->net_g      = (uint16_t)v[3];
  out->catalog_id = (int)v[4];
  snprintf(out->name, sizeof(out->name), "%s", p);
  return true;
}

bool spoolMineValid(const char* name, int weight_g) {
  if (!name || !name[0] || strlen(name) >= SPOOL_CHOICE_NAME_MAX) return false;
  if (strpbrk(name, "|\n\r")) return false;
  return weight_g >= SPOOL_MINE_MIN_G && weight_g <= SPOOL_MINE_MAX_G;
}

bool spoolMineMake(const char* name, int weight_g, SpoolChoice* out) {
  if (!out || !spoolMineValid(name, weight_g)) return false;
  spoolChoiceClear(out);
  out->weight_g = (uint16_t)weight_g;
  out->source   = SCS_MINE;
  snprintf(out->name, sizeof(out->name), "%s", name);
  return true;
}

bool spoolMineEncode(const SpoolChoice* list, int n, char* out, size_t out_size) {
  if (!out || out_size == 0) return false;
  out[0] = '\0';
  size_t used = 0;
  char line[SPOOL_CHOICE_TEXT_MAX];
  for (int i = 0; list && i < n && i < SPOOL_MINE_MAX; i++) {
    if (!spoolChoiceEncode(list[i], line, sizeof(line))) return false;
    const int w = snprintf(out + used, out_size - used, "%s%s", used ? "\n" : "", line);
    if (w < 0 || (size_t)w >= out_size - used) return false;
    used += (size_t)w;
  }
  return true;
}

int spoolMineDecode(const char* text, SpoolChoice out[SPOOL_MINE_MAX]) {
  int n = 0;
  char line[SPOOL_CHOICE_TEXT_MAX];
  for (const char* p = text; p && *p && n < SPOOL_MINE_MAX;) {
    const char* end = strchr(p, '\n');
    const size_t len = end ? (size_t)(end - p) : strlen(p);
    if (len < sizeof(line)) {
      memcpy(line, p, len);
      line[len] = '\0';
      if (spoolChoiceDecode(line, &out[n]) && out[n].source == SCS_MINE) n++;
    }
    p = end ? end + 1 : p + len;
  }
  return n;
}

static bool startsWithMaker(const char* name, const char* maker) {
  char n[SPOOL_NAME_KEY_MAX], m[SPOOL_NAME_KEY_MAX];
  nameKey(name, n, sizeof(n));
  nameKey(maker, m, sizeof(m));
  return m[0] && strncmp(n, m, strlen(m)) == 0;
}

static bool listed(const SpoolChoice* list, int n, const SpoolChoice& c) {
  for (int i = 0; i < n; i++)
    if (spoolChoiceSame(list[i], c)) return true;
  return false;
}

int spoolServerPick(const SpoolChoice* all, int n, const char* maker, SpoolChoice* out, int max) {
  int k = 0;
  // Two passes: the card's maker, then everyone else.
  for (int pass = 0; pass < 2; pass++) {
    for (int i = 0; all && i < n && k < max; i++) {
      if (!spoolChoiceActive(all[i]) || startsWithMaker(all[i].name, maker) != (pass == 0)) continue;
      if (!listed(out, k, all[i])) out[k++] = all[i];
    }
  }
  return k;
}
