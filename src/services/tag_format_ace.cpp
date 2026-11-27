// The Anycubic ACE record: the fields every record is built from out of a
// backend spool, and the ACE page layout written from them.
#include "tag_write.h"

#include <ArduinoJson.h>
#include <stdio.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "services/material_family.h"
#include "services/spool_temp_rules.h"
#include "services/tag_write_internal.h"

using namespace tagw;

// The family table lives in services/material_family.cpp, shared with the
// main screen's guide value. Density is only used to estimate the length.
#define MAT_DENSITY_FALLBACK  1.24f


void tagw::buildAce(JsonObjectConst sp, AceFields *f) {
  memset(f, 0, sizeof(*f));
  // The spool's own material name goes on the tag, not the family it belongs
  // to. Writing the family made a TPE-83A spool arrive as "PLA", and a reader
  // has no way of telling that apart from a spool that really is PLA.
  const char *material = sp["filament"]["material"] | "PLA";
  if (!material[0]) material = "PLA";
  snprintf(f->material, sizeof(f->material), "%s", material);

  float density = MAT_DENSITY_FALLBACK;
  const MatFamily* fam = matchFamily(material);
  SpoolTempRange fam_nozzle = {0, 0}, fam_bed = {0, 0};
  if (fam) {
    fam_nozzle = {fam->et_lo, fam->et_hi};
    fam_bed = {fam->bed_lo, fam->bed_hi};
    density = fam->density;
  }
  // What the user entered in the backend is what they print at, so it goes
  // on the tag before the family's textbook range.
  JsonObjectConst fil = sp["filament"];
  const SpoolTempRange nozzle = spoolTempTagEnds(
      spoolTempRange(fil["x_extruder_temp_min"] | 0, fil["settings_extruder_temp"] | 0),
      fam_nozzle);
  const SpoolTempRange bed = spoolTempTagEnds(
      spoolTempRange(0, fil["settings_bed_temp"] | 0), fam_bed);
  f->et_lo = (uint16_t)nozzle.lo;  f->et_hi = (uint16_t)nozzle.hi;
  f->bed_lo = (uint16_t)bed.lo;    f->bed_hi = (uint16_t)bed.hi;
  // Zero, and the preview shows a dash. A reader can ignore a missing
  // temperature; a wrong one it cannot.
  if (!nozzle.hi)
    logSDf("tag: material '%s' has no temperature in the backend and is in no "
           "known family, none written", material);

  unsigned r = 0, g = 0, b = 0;
  const char *c = sp["filament"]["color_hex"] | "";
  if (*c == '#') c++;
  if (strlen(c) >= 6) sscanf(c, "%02x%02x%02x", &r, &g, &b);
  f->r = (uint8_t)r; f->g = (uint8_t)g; f->b = (uint8_t)b;

  const float net = sp["filament"]["weight"] | 0.0f;
  f->weight_g = (uint16_t)(net > 0 ? net : 1000);

  f->dia_x100 = 175;
  const float radius_cm = (f->dia_x100 / 100.0f) / 20.0f;
  const float area = 3.14159265f * radius_cm * radius_cm;
  f->length_m = (uint16_t)((f->weight_g / density) / area / 100.0f);

  snprintf(f->brand, sizeof(f->brand), "%s", sp["filament"]["vendor"]["name"] | "Generic");
  // Always the backend spool id. The ACE does not validate the SKU and hands
  // the decoded contents to Klipper without a UID, so this is the only field
  // that can point back at the spool record.
  snprintf(f->sku, sizeof(f->sku), "SM%d", (int)(sp["id"] | 0));
}

void tagw::aceToInfo(const AceFields *f, TagInfo *ti) {
  memset(ti, 0, sizeof(*ti));
  snprintf(ti->fmt, sizeof(ti->fmt), "ACE");
  snprintf(ti->sku, sizeof(ti->sku), "%s", f->sku);
  snprintf(ti->brand, sizeof(ti->brand), "%s", f->brand);
  snprintf(ti->material, sizeof(ti->material), "%s", f->material);
  ti->has_color = true;
  ti->r = f->r; ti->g = f->g; ti->b = f->b;
  ti->et_lo = f->et_lo; ti->et_hi = f->et_hi;
  ti->bed_lo = f->bed_lo; ti->bed_hi = f->bed_hi;
  ti->dia_x100 = f->dia_x100; ti->length_m = f->length_m;
  ti->weight_g = f->weight_g;
}

// One format for both sides, so the page can compare them as plain strings.
void tagw::describeAce(const AceFields *f, char *out, size_t out_len) {
  snprintf(out, out_len, "ACE: %s %s, #%02X%02X%02X, %ug, SKU %s",
           f->brand, f->material, f->r, f->g, f->b,
           (unsigned)f->weight_g, f->sku);
}

// What writeAce() puts on the tag: the magic page twice, three texts of five
// pages each, the colour and four pairs of numbers.
#define ACE_PAGES_WRITTEN  (2 + 3 * 5 + 1 + 4)

bool tagw::writeAce(const AceFields *f) {
  const uint8_t magic[4] = { 0x7B, 0x00, 0x65, 0x00 };
  const uint8_t color[4] = { 0xFF, f->b, f->g, f->r };
  const uint8_t zero[4]  = { 0, 0, 0, 0 };
  progressBegin(ACE_PAGES_WRITTEN);
  // The magic page goes last, and is blanked first. The magic used to be
  // written before the fields, so a spool lifted mid-write left a tag that
  // announced an ACE record over whatever the pages held before - and the
  // next scan showed that as a plausible spool. Blank until the last page,
  // it reads as empty instead.
  return wrPage(ACE_P_MAGIC, zero)
      && wrText(ACE_P_SKU, f->sku)
      && wrText(ACE_P_BRAND, f->brand)
      && wrText(ACE_P_MATERIAL, f->material)
      && wrPage(ACE_P_COLOR, color)
      && wrU16Pair(ACE_P_EXTRUDER, f->et_lo, f->et_hi)
      && wrU16Pair(ACE_P_BED, f->bed_lo, f->bed_hi)
      && wrU16Pair(ACE_P_DIALEN, f->dia_x100, f->length_m)
      && wrU16Pair(ACE_P_WEIGHT, f->weight_g, 0)
      && wrPage(ACE_P_MAGIC, magic)
      && rdPageIs(ACE_P_MAGIC, magic)
      && rdPageIs(ACE_P_COLOR, color);
}
