#include "tag_db_match.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define TAG_DB_PERCENT  100

// The largest difference of the three channels of two "RRGGBB" colours.
static int channelDiff(const char* a, const char* b) {
  const unsigned long x = strtoul(a, nullptr, 16), y = strtoul(b, nullptr, 16);
  int worst = 0;
  for (int shift = 0; shift <= 16; shift += 8) {
    const int d = abs((int)((x >> shift) & 0xFF) - (int)((y >> shift) & 0xFF));
    if (d > worst) worst = d;
  }
  return worst;
}

static bool colorDiffers(const TagCreateInput& in, const TagDbEntry& db) {
  if (in.clear || in.color_count != 1 || !db.color_hex[0]) return false;
  return channelDiff(in.color_hex, db.color_hex) > TAG_DB_COLOR_DIFF;
}

static bool addDiff(TagDbDiff* out, int out_max, int* n, uint8_t field, int tag_value, int db_value) {
  if (*n >= out_max) return false;
  TagDbDiff& d = out[(*n)++];
  memset(&d, 0, sizeof(d));
  d.field = field;
  d.tag_value = tag_value;
  d.db_value = db_value;
  return true;
}

static void compareNumber(int tag_value, int db_value, int limit, uint8_t field,
                          TagDbDiff* out, int out_max, int* n) {
  if (tag_value <= 0 || db_value <= 0 || abs(tag_value - db_value) < limit) return;
  addDiff(out, out_max, n, field, tag_value, db_value);
}

int tagDbCompare(const TagCreateInput& in, const TagDbEntry& db, TagDbDiff* out, int out_max) {
  int n = 0;
  if (colorDiffers(in, db) && addDiff(out, out_max, &n, TDF_COLOR, 0, 0)) {
    snprintf(out[n - 1].tag_hex, sizeof(out[n - 1].tag_hex), "%s", in.color_hex);
    snprintf(out[n - 1].db_hex, sizeof(out[n - 1].db_hex), "%s", db.color_hex);
  }
  compareNumber(in.temp_min, db.nozzle_min, TAG_DB_NOZZLE_DIFF_C, TDF_NOZZLE_MIN, out, out_max, &n);
  compareNumber(in.temp_max, db.nozzle_max, TAG_DB_NOZZLE_DIFF_C, TDF_NOZZLE_MAX, out, out_max, &n);
  // Ten per cent of the tag's weight: 100 g on a 1 kg spool.
  const int weight_limit = in.net_weight_g * TAG_DB_WEIGHT_DIFF_PCT / TAG_DB_PERCENT;
  compareNumber(in.net_weight_g, db.net_weight_g, weight_limit > 0 ? weight_limit : 1, TDF_WEIGHT,
                out, out_max, &n);
  return n;
}

void tagDbFill(TagCreateInput* in, const TagDbEntry& db) {
  snprintf(in->db_id, sizeof(in->db_id), "%s", db.id);
  snprintf(in->db_name, sizeof(in->db_name), "%s", db.name);
  snprintf(in->db_color_name, sizeof(in->db_color_name), "%s", db.color_name);
  snprintf(in->db_line, sizeof(in->db_line), "%s", db.line);
  // The material stays the tag's: a key that names another one (Tough+ Cyan
  // is in the FilamentDB once as PLA, once as PLA+) is not taken over.
  if (strcasecmp(db.material_key, in->material) == 0)
    snprintf(in->db_material_key, sizeof(in->db_material_key), "%s", db.material_key);
  // The database's spelling of the colour only when it is the tag's colour.
  const bool same_color = !colorDiffers(*in, db) && in->color_count == 1 && db.color_raw[0];
  if (same_color)    snprintf(in->db_color_hex, sizeof(in->db_color_hex), "%s", db.color_raw);
  else if (in->clear) snprintf(in->db_color_hex, sizeof(in->db_color_hex), "%s", in->rgba);
  else               snprintf(in->db_color_hex, sizeof(in->db_color_hex), "%s", in->color_hex);
  in->db_density  = db.density;
  in->db_bed_temp = db.bed_temp;
  if (in->net_weight_g <= 0) in->net_weight_g = db.net_weight_g;
  if (in->temp_min <= 0)     in->temp_min = db.nozzle_min;
  if (in->temp_max <= 0)     in->temp_max = db.nozzle_max;
}

void tagDbTake(TagCreateInput* in, const TagDbDiff& diff) {
  switch (diff.field) {
    case TDF_COLOR:
      snprintf(in->colors_hex[0], sizeof(in->colors_hex[0]), "%s", diff.db_hex);
      snprintf(in->color_hex, sizeof(in->color_hex), "%s", diff.db_hex);
      snprintf(in->rgba, sizeof(in->rgba), "%sFF", diff.db_hex);
      snprintf(in->db_color_hex, sizeof(in->db_color_hex), "%s", diff.db_hex);
      break;
    case TDF_NOZZLE_MIN: in->temp_min = diff.db_value;     break;
    case TDF_NOZZLE_MAX: in->temp_max = diff.db_value;     break;
    case TDF_WEIGHT:     in->net_weight_g = diff.db_value; break;
    default: break;
  }
}
