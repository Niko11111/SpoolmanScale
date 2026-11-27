#include "tag_create_record.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

// The maker's own short form on its tags, and the name the filament
// databases know it by.
struct MakerAlias {
  const char* on_tag;
  const char* name;
};
static const MakerAlias MAKER_ALIASES[] = {
  { "AC", "Anycubic" },   // original ACE tags, 19.11.2026
};

// What an ACE record without a brand, and a Snapmaker tag without a vendor
// block, are filed under.
#define TAG_RECORD_ANYCUBIC   "Anycubic"
#define TAG_RECORD_SNAPMAKER  "Snapmaker"
// An OpenSpool record without a brand.
#define TAG_RECORD_GENERIC    "Generic"
// What the Snapmaker decoder writes for a material id it does not know.
#define TAG_RECORD_UNKNOWN    "Unknown"
// The SKU buildAce() writes: "SM" and the spool id.
#define TAG_RECORD_OWN_SKU    "SM"
// The largest spool id read out of such a SKU.
#define TAG_RECORD_SPOOL_ID_MAX  2147483647L

static bool allDigits(const char* s) {
  if (!s || !*s) return false;
  for (; *s; s++) if (!isdigit((unsigned char)*s)) return false;
  return true;
}

// The digits behind "SM" of an ACE record this scale wrote, or null.
static const char* ownSkuDigits(const TagRecord& r) {
  if (!r.fmt || strcmp(r.fmt, "ACE") != 0 || !r.sku) return nullptr;
  const size_t n = strlen(TAG_RECORD_OWN_SKU);
  if (strncmp(r.sku, TAG_RECORD_OWN_SKU, n) != 0 || !allDigits(r.sku + n)) return nullptr;
  return r.sku + n;
}

bool tagRecordIsOwn(const TagRecord& r) {
  if (r.fmt && strcmp(r.fmt, "ACE") == 0) return ownSkuDigits(r) != nullptr;
  return r.spool_id > 0;
}

int tagRecordOwnSpoolId(const TagRecord& r) {
  if (!tagRecordIsOwn(r)) return 0;
  const char* digits = ownSkuDigits(r);
  if (!digits) return r.spool_id;
  // A spool id beyond what an int holds is no spool of any backend.
  const long id = strtol(digits, nullptr, 10);
  return (id > 0 && id <= TAG_RECORD_SPOOL_ID_MAX) ? (int)id : 0;
}

void tagCreateMakerName(const char* brand, char* out, size_t out_size) {
  if (!out || !out_size) return;
  out[0] = '\0';
  if (!brand) return;
  for (const MakerAlias& a : MAKER_ALIASES) {
    if (strcasecmp(brand, a.on_tag) == 0) { snprintf(out, out_size, "%s", a.name); return; }
  }
  snprintf(out, out_size, "%s", brand);
}

bool tagCreateVendorIs(const char* name, const char* vendor) {
  if (!name || !vendor || !vendor[0]) return false;
  if (strcasecmp(name, vendor) == 0) return true;
  return strlen(vendor) == TAG_RECORD_BRAND_MAX &&
         strncasecmp(name, vendor, TAG_RECORD_BRAND_MAX) == 0;
}

void tagCreateMaterialAndLine(const char* name, TagCreateInput* in) {
  in->material[0] = in->product[0] = in->subtype[0] = '\0';
  if (!name) return;
  while (*name == ' ') name++;
  snprintf(in->product, sizeof(in->product), "%s", name);
  // The first word is the base; "PLA-CF" holds no space and stays whole.
  const char* space = strchr(name, ' ');
  const size_t head = space ? (size_t)(space - name) : strlen(name);
  snprintf(in->material, sizeof(in->material), "%.*s", (int)head, name);
  if (!space) return;
  while (*space == ' ') space++;
  snprintf(in->subtype, sizeof(in->subtype), "%s", space);
}

// What every one of these formats shares: no names, no empty spool.
static void foreignDefaults(TagCreateInput* in) {
  in->names_known = false;
  in->names_optional = true;
  in->spool_weight_g = 0;
  in->spool_weight_default = false;
  in->diameter_mm = TAG_CREATE_DIAMETER_MM;
}

bool tagCreateFromRecord(const TagRecord& r, TagCreateInput* in) {
  if (!in || !r.fmt) return false;
  const bool ace = strcmp(r.fmt, "ACE") == 0;
  if (!ace && strcmp(r.fmt, "OpenSpool") != 0) return false;
  // A record of this scale's own is taken too: its spool may be gone, and the
  // card offers linking that spool again beside it (unknown_spool_popup.cpp).
  if (!r.material || !r.material[0]) return false;

  foreignDefaults(in);
  tagCreateMakerName(r.brand, in->vendor, sizeof(in->vendor));
  if (!in->vendor[0])
    snprintf(in->vendor, sizeof(in->vendor), "%s", ace ? TAG_RECORD_ANYCUBIC : TAG_RECORD_GENERIC);
  tagCreateMaterialAndLine(r.material, in);
  in->net_weight_g = r.weight_g;
  if (r.dia_x100 > 0) in->diameter_mm = r.dia_x100 / 100.0f;
  in->temp_min = r.et_lo;
  in->temp_max = r.et_hi;
  return true;
}

bool tagCreateFromSnapmaker(const char* vendor, const char* material, TagCreateInput* in) {
  if (!in || !material || !material[0]) return false;
  if (tagCreateStartsWithWord(material, TAG_RECORD_UNKNOWN)) return false;
  foreignDefaults(in);
  snprintf(in->vendor, sizeof(in->vendor), "%s",
           vendor && vendor[0] ? vendor : TAG_RECORD_SNAPMAKER);
  tagCreateMaterialAndLine(material, in);
  return true;
}
