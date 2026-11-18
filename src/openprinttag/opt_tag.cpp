#include "opt_tag.h"

#include <stdio.h>
#include <string.h>

#include "openprinttag/cbor_reader.h"

namespace {

// Capability container of a Type 5 tag (NFC Forum T5T): magic, version and
// access, size in units of 8 bytes, features.
constexpr uint8_t CC_MAGIC        = 0xE1;
constexpr size_t  CC_SIZE_AT      = 2;
constexpr size_t  CC_SIZE_UNIT    = 8;
// TLV blocks after the CC.
constexpr uint8_t TLV_NULL        = 0x00;
constexpr uint8_t TLV_NDEF        = 0x03;
constexpr uint8_t TLV_TERMINATOR  = 0xFE;
constexpr uint8_t TLV_LONG_LENGTH = 0xFF;   // then two bytes, big endian
// NDEF record header flags.
constexpr uint8_t NDEF_ME   = 0x40;
constexpr uint8_t NDEF_SR   = 0x10;
constexpr uint8_t NDEF_IL   = 0x08;
constexpr uint8_t NDEF_TNF  = 0x07;
constexpr uint8_t TNF_MIME  = 0x02;
const char OPT_MIME[] = "application/vnd.openprinttag";
// Meta region keys.
constexpr int64_t META_MAIN_OFFSET = 0;
constexpr int64_t META_MAIN_SIZE   = 1;
constexpr int64_t META_AUX_OFFSET  = 2;
constexpr int64_t META_AUX_SIZE    = 3;
constexpr size_t  REGION_MAX       = 512;   // the format's limit for one region
// Aux keys.
constexpr int64_t AUX_CONSUMED  = 0;
constexpr int64_t AUX_WORKGROUP = 1;
constexpr float   DIAMETER_DEFAULT_MM = 1.75f;
constexpr uint8_t RGB_BYTES  = 3;
constexpr uint8_t RGBA_BYTES = 4;
constexpr uint8_t ALPHA_OPAQUE = 0xFF;
constexpr int64_t SECONDS_PER_DAY = 86400;
constexpr int64_t DAYS_0000_03_01_TO_1970 = 719468;   // the algorithm counts from March, year 0
constexpr int64_t DAYS_PER_ERA = 146097;              // 400 Gregorian years

// Main region keys.
enum MainKey : int64_t {
  K_GTIN = 4, K_INSTANCE_ID = 5, K_MATERIAL_CLASS = 8, K_MATERIAL_TYPE = 9,
  K_MATERIAL_NAME = 10, K_BRAND = 11, K_MANUFACTURED = 14, K_NOMINAL_WEIGHT = 16,
  K_ACTUAL_WEIGHT = 17, K_CONTAINER_WEIGHT = 18, K_PRIMARY_COLOR = 19,
  K_SECONDARY_LAST = 24, K_TAGS = 28, K_DENSITY = 29, K_DIAMETER = 30,
  K_MIN_NOZZLE = 33, K_PRINT_MIN = 34, K_PRINT_MAX = 35, K_PREHEAT = 36,
  K_BED_MIN = 37, K_BED_MAX = 38, K_ABBREVIATION = 52, K_NOMINAL_LENGTH = 53,
  K_ACTUAL_LENGTH = 54, K_DRY_TEMP = 57, K_DRY_TIME = 58,
};

const char* const MATERIAL_TYPES[] = {
  "PLA", "PETG", "TPU", "ABS", "ASA", "PC", "PCTG", "PP", "PA6", "PA11",
  "PA12", "PA66", "CPE", "TPE", "HIPS", "PHA", "PET", "PEI", "PBT", "PVB",
  "PVA", "PEKK", "PEEK", "BVOH", "TPC", "PPS", "PPSU", "PVC", "PEBA", "PVDF",
  "PPA", "PCL", "PES", "PMMA", "POM", "PPE", "PS", "PSU", "TPI", "SBS",
  "OBC", "EVA", "PA612",
};
constexpr int MATERIAL_TYPE_COUNT = sizeof(MATERIAL_TYPES) / sizeof(MATERIAL_TYPES[0]);

struct Region {
  size_t offset;
  size_t size;
  bool present;
};

}  // namespace

static void clearTag(OptTag* t) {
  memset(t, 0, sizeof(*t));
  t->material_class = -1;
  t->material_type = -1;
  t->nominal_weight_g = t->actual_weight_g = t->container_weight_g = -1.0f;
  t->density = t->nominal_length_mm = t->actual_length_mm = t->min_nozzle_mm = -1.0f;
  t->diameter_mm = DIAMETER_DEFAULT_MM;
  t->consumed_g = -1.0f;
}

size_t optMemorySize(const uint8_t cc[OPT_CC_BYTES]) {
  if (cc[0] != CC_MAGIC) return 0;
  return (size_t)cc[CC_SIZE_AT] * CC_SIZE_UNIT;
}

// ---- main region --------------------------------------------------------

static float* numberField(OptTag& t, int64_t key) {
  switch (key) {
    case K_NOMINAL_WEIGHT:   return &t.nominal_weight_g;
    case K_ACTUAL_WEIGHT:    return &t.actual_weight_g;
    case K_CONTAINER_WEIGHT: return &t.container_weight_g;
    case K_DENSITY:          return &t.density;
    case K_DIAMETER:         return &t.diameter_mm;
    case K_MIN_NOZZLE:       return &t.min_nozzle_mm;
    case K_NOMINAL_LENGTH:   return &t.nominal_length_mm;
    case K_ACTUAL_LENGTH:    return &t.actual_length_mm;
    default:                 return nullptr;
  }
}

static int16_t* smallIntField(OptTag& t, int64_t key) {
  switch (key) {
    case K_MATERIAL_CLASS: return &t.material_class;
    case K_MATERIAL_TYPE:  return &t.material_type;
    case K_PRINT_MIN:      return &t.print_min_c;
    case K_PRINT_MAX:      return &t.print_max_c;
    case K_PREHEAT:        return &t.preheat_c;
    case K_BED_MIN:        return &t.bed_min_c;
    case K_BED_MAX:        return &t.bed_max_c;
    case K_DRY_TEMP:       return &t.dry_c;
    default:               return nullptr;
  }
}

static char* textField(OptTag& t, int64_t key, size_t* cap) {
  switch (key) {
    case K_BRAND:         *cap = sizeof(t.brand);         return t.brand;
    case K_MATERIAL_NAME: *cap = sizeof(t.material_name); return t.material_name;
    case K_ABBREVIATION:  *cap = sizeof(t.abbreviation);  return t.abbreviation;
    case K_INSTANCE_ID:   *cap = sizeof(t.instance_id);   return t.instance_id;
    default:              return nullptr;
  }
}

static void readColor(CborReader& r, OptTag& t, int64_t key) {
  uint8_t rgba[RGBA_BYTES];
  size_t n = 0;
  if (!cborBytes(r, rgba, sizeof(rgba), &n) || n < RGB_BYTES) return;
  if (n == RGB_BYTES) rgba[3] = ALPHA_OPAQUE;
  // Secondaries go after the primary, in their order; the primary always first.
  const size_t slot = (size_t)(key - K_PRIMARY_COLOR);
  if (slot >= OPT_COLORS_MAX) return;
  memcpy(t.colors[slot], rgba, RGBA_BYTES);
  if (t.color_count < slot + 1) t.color_count = (uint8_t)(slot + 1);
}

static void readTags(CborReader& r, OptTag& t) {
  CborContainer a;
  if (!cborArrayBegin(r, &a)) return;
  while (cborArrayNext(r, a)) {
    int64_t v = 0;
    if (cborInt(r, &v) && v >= 0 && v <= UINT16_MAX && t.tag_count < OPT_TAGS_MAX) {
      t.tags[t.tag_count++] = (uint16_t)v;
    }
  }
}

static void readOtherMain(CborReader& r, OptTag& t, int64_t key) {
  int64_t v = 0;
  switch (key) {
    case K_GTIN:
      if (cborInt(r, &v) && v > 0) t.gtin = (uint64_t)v;
      return;
    case K_MANUFACTURED:
      if (cborInt(r, &v)) t.manufactured = v;
      return;
    case K_DRY_TIME:
      if (cborInt(r, &v) && v >= 0 && v <= INT32_MAX) t.dry_minutes = (int32_t)v;
      return;
    case K_TAGS:
      readTags(r, t);
      return;
    default:
      if (key >= K_PRIMARY_COLOR && key <= K_SECONDARY_LAST) readColor(r, t, key);
      else cborSkip(r);
  }
}

static void readMainField(CborReader& r, OptTag& t, int64_t key) {
  size_t cap = 0;
  double d = 0;
  int64_t v = 0;
  if (float* f = numberField(t, key)) {
    if (cborNumber(r, &d)) *f = (float)d;
  } else if (int16_t* i = smallIntField(t, key)) {
    if (cborInt(r, &v) && v >= INT16_MIN && v <= INT16_MAX) *i = (int16_t)v;
  } else if (char* s = textField(t, key, &cap)) {
    cborText(r, s, cap);
  } else {
    readOtherMain(r, t, key);
  }
}

static bool readMain(const uint8_t* p, size_t n, OptTag& t) {
  CborReader r = cborReader(p, n);
  CborContainer m;
  if (!cborMapBegin(r, &m)) return false;
  int64_t key = 0;
  while (cborMapNextKey(r, m, &key)) readMainField(r, t, key);
  return !r.bad;
}

// ---- aux region ---------------------------------------------------------

static void readAux(const uint8_t* p, size_t n, OptTag& t) {
  CborReader r = cborReader(p, n);
  CborContainer m;
  if (!cborMapBegin(r, &m)) return;
  int64_t key = 0;
  double d = 0;
  while (cborMapNextKey(r, m, &key)) {
    if (key == AUX_CONSUMED && cborNumber(r, &d)) t.consumed_g = (float)d;
    else if (key == AUX_WORKGROUP) cborText(r, t.workgroup, sizeof(t.workgroup));
    else cborSkip(r);
  }
}

// ---- payload: meta and the regions it points to -------------------------

struct Meta {
  int64_t main_offset, main_size, aux_offset, aux_size;   // -1 not given
  size_t end;                                             // where the meta map ends
};

static bool readMeta(const uint8_t* p, size_t n, Meta* meta) {
  *meta = Meta{-1, -1, -1, -1, 0};
  CborReader r = cborReader(p, n);
  CborContainer m;
  if (!cborMapBegin(r, &m)) return false;
  int64_t key = 0;
  int64_t v = 0;
  while (cborMapNextKey(r, m, &key)) {
    int64_t* slot = key == META_MAIN_OFFSET ? &meta->main_offset
                  : key == META_MAIN_SIZE   ? &meta->main_size
                  : key == META_AUX_OFFSET  ? &meta->aux_offset
                  : key == META_AUX_SIZE    ? &meta->aux_size : nullptr;
    if (slot && cborInt(r, &v) && v >= 0) *slot = v;
    else if (!slot) cborSkip(r);
  }
  meta->end = r.pos;
  return !r.bad;
}

// A region without a size runs to the next region's start or the payload's end.
static Region region(int64_t offset, int64_t size, int64_t other_offset, size_t payload_len) {
  Region g = {0, 0, false};
  if (offset < 0 || (size_t)offset >= payload_len) return g;
  g.offset = (size_t)offset;
  size_t end = payload_len;
  if (other_offset > offset && (size_t)other_offset < end) end = (size_t)other_offset;
  if (size >= 0 && (size_t)(offset + size) <= payload_len) end = (size_t)(offset + size);
  g.size = end - g.offset;
  if (g.size > REGION_MAX) g.size = REGION_MAX;
  g.present = true;
  return g;
}

OptResult optDecodePayload(const uint8_t* p, size_t len, OptTag* out) {
  clearTag(out);
  Meta meta;
  if (!readMeta(p, len, &meta)) return OPT_BAD_PAYLOAD;
  const int64_t main_at = meta.main_offset >= 0 ? meta.main_offset : (int64_t)meta.end;
  const Region main = region(main_at, meta.main_size, meta.aux_offset, len);
  if (!main.present || !readMain(p + main.offset, main.size, *out)) return OPT_BAD_PAYLOAD;
  const Region aux = region(meta.aux_offset, meta.aux_size, main_at, len);
  if (aux.present) readAux(p + aux.offset, aux.size, *out);
  return OPT_OK;
}

// ---- NDEF: the record in the message -------------------------------------

// Walks the records of one NDEF message for the OpenPrintTag MIME record.
static bool findRecord(const uint8_t* m, size_t len, const uint8_t** payload, size_t* plen) {
  size_t at = 0;
  const size_t mime_len = sizeof(OPT_MIME) - 1;
  while (at + 3 <= len) {
    const uint8_t hdr = m[at];
    const size_t type_len = m[at + 1];
    size_t pos = at + 2;
    size_t payload_len = 0;
    const size_t len_bytes = (hdr & NDEF_SR) ? 1 : 4;
    if (pos + len_bytes > len) return false;
    for (size_t i = 0; i < len_bytes; i++) payload_len = (payload_len << 8) | m[pos++];
    const size_t id_len = (hdr & NDEF_IL) ? m[pos++] : 0;
    if (pos > len || len - pos < type_len + id_len || len - pos - type_len - id_len < payload_len) return false;
    const bool match = (hdr & NDEF_TNF) == TNF_MIME && type_len == mime_len &&
                       memcmp(m + pos, OPT_MIME, mime_len) == 0;
    pos += type_len + id_len;
    if (match) {
      *payload = m + pos;
      *plen = payload_len;
      return true;
    }
    if (hdr & NDEF_ME) return false;
    at = pos + payload_len;
  }
  return false;
}

// The NDEF TLV after the CC: its value's start and length.
static bool findNdefTlv(const uint8_t* mem, size_t len, size_t* at, size_t* tlv_len) {
  size_t pos = OPT_CC_BYTES;
  while (pos < len) {
    const uint8_t type = mem[pos++];
    if (type == TLV_NULL) continue;
    if (type == TLV_TERMINATOR || pos >= len) return false;
    size_t n = mem[pos++];
    if (n == TLV_LONG_LENGTH) {
      if (pos + 2 > len) return false;
      n = ((size_t)mem[pos] << 8) | mem[pos + 1];
      pos += 2;
    }
    if (n > len - pos) return false;
    if (type == TLV_NDEF) {
      *at = pos;
      *tlv_len = n;
      return true;
    }
    pos += n;
  }
  return false;
}

OptResult optDecodeMemory(const uint8_t* mem, size_t len, OptTag* out) {
  clearTag(out);
  if (len < OPT_CC_BYTES || optMemorySize(mem) == 0) return OPT_NO_CC;
  size_t at = 0;
  size_t n = 0;
  if (!findNdefTlv(mem, len, &at, &n)) return OPT_NO_NDEF;
  const uint8_t* payload = nullptr;
  size_t plen = 0;
  if (!findRecord(mem + at, n, &payload, &plen)) return OPT_NO_RECORD;
  return optDecodePayload(payload, plen, out);
}

// ---- reading the result -------------------------------------------------

const char* optResultName(OptResult r) {
  switch (r) {
    case OPT_OK:          return "ok";
    case OPT_NO_CC:       return "no NDEF capability container";
    case OPT_NO_NDEF:     return "no NDEF message";
    case OPT_NO_RECORD:   return "no OpenPrintTag record";
    case OPT_BAD_PAYLOAD: return "unreadable OpenPrintTag data";
    default:              return "?";
  }
}

const char* optMaterialTypeName(int material_type) {
  if (material_type < 0 || material_type >= MATERIAL_TYPE_COUNT) return nullptr;
  return MATERIAL_TYPES[material_type];
}

const char* optMaterialAbbr(const OptTag& t) {
  if (t.abbreviation[0]) return t.abbreviation;
  const char* name = optMaterialTypeName(t.material_type);
  return name ? name : "";
}

float optFullWeightG(const OptTag& t) {
  return t.actual_weight_g >= 0 ? t.actual_weight_g : t.nominal_weight_g;
}

float optRemainingG(const OptTag& t) {
  const float full = optFullWeightG(t);
  if (full < 0) return -1.0f;
  if (t.consumed_g < 0) return full;
  const float left = full - t.consumed_g;
  return left > 0 ? left : 0.0f;
}

// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
void optFormatDate(int64_t unix_s, char* out, size_t cap) {
  if (cap == 0) return;
  out[0] = '\0';
  if (unix_s <= 0) return;
  const int64_t days = unix_s / SECONDS_PER_DAY + DAYS_0000_03_01_TO_1970;
  const int64_t era = days / DAYS_PER_ERA;
  const int64_t doe = days - era * DAYS_PER_ERA;
  const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const int64_t mp = (5 * doy + 2) / 153;
  const int64_t day = doy - (153 * mp + 2) / 5 + 1;
  const int64_t month = mp < 10 ? mp + 3 : mp - 9;
  const int64_t year = yoe + era * 400 + (month <= 2 ? 1 : 0);
  snprintf(out, cap, "%04d-%02d-%02d", (int)year, (int)month, (int)day);
}
