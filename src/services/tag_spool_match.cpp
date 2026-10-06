#include "services/tag_spool_match.h"

#include <cstdio>
#include <cstring>
#include <strings.h>

#include "app/app_state.h"
#include "app_config.h"
#include "bambu/bambu_catalog.h"
#include "bambu/material_match.h"
#include "hardware/sd_logger.h"
#include "services/spool_color.h"

// A Bambu support tag names what it holds up: "Support for PLA", "Support
// For PLA/PETG", "Support for ABS", "Support For PA/PET". Spoolman keeps the
// same filament as that base with "-S": PLA-S, ABS-S, PA-S. So a support
// spool whose base is one of the tag's matches; for "PLA/PETG" either does.
// "Support W" and "Support G" name no base, and any support spool may carry
// them - the same as the link list, which keeps every "-S" spool for a
// support tag.
static bool supportSpoolMatches(const char* tag_material, const char* spool_material) {
  if (!isSupportSpoolmanMat(spool_material)) return false;
  const size_t base_len = strlen(spool_material) - 2;   // without the "-S"
  const char* p = tag_material + 7;                     // past "Support"
  while (*p == ' ') p++;
  if (strncasecmp(p, "for ", 4) != 0) return true;
  p += 4;
  while (*p) {
    while (*p == ' ' || *p == '/') p++;
    const char* start = p;
    while (*p && *p != ' ' && *p != '/') p++;
    const size_t len = (size_t)(p - start);
    if (len && len == base_len && strncasecmp(start, spool_material, len) == 0) return true;
  }
  return false;
}

TagSpoolVerdict tagSpoolCompare(const char* tag_material, const char* tag_color_hex,
                                const char* spool_material, const char* spool_name,
                                const char* spool_vendor, const char* spool_color_hex,
                                bool article_match) {
  TagSpoolVerdict v;
  if (article_match) return v;
  if (!tag_material)    tag_material = "";
  if (!tag_color_hex)   tag_color_hex = "";
  if (!spool_material)  spool_material = "";
  if (!spool_name)      spool_name = "";
  if (!spool_vendor)    spool_vendor = "";
  if (!spool_color_hex) spool_color_hex = "";

  if (isSupportMaterial(tag_material)) {
    // Three characters of "Support for PLA" against "PLA-S" never agree, so
    // a support tag was a mismatch with every spool, its own included.
    if (spool_material[0]) v.material = !supportSpoolMatches(tag_material, spool_material);
  } else if (strlen(tag_material) >= 3 && strlen(spool_material) >= 3) {
    v.material = (strncasecmp(tag_material, spool_material, 3) != 0);
    // The tag writes "Tough+", a library "Tough Plus" or leaves it to the name
    // ("PLA" with "PLA Tough+"), and bambuSubtypeMatches() reads them as one.
    char subkw[16];
    if (!v.material && extractBambuSubtype(tag_material, subkw, sizeof(subkw))) {
      v.material = !bambuSubtypeMatches(spool_material, subkw) &&
                   !bambuSubtypeMatches(spool_name, subkw);
    }
  }

  // The tag's hex is empty for a clear filament, and a spool stored as
  // 00000000 names no hue either: neither can be held against the other.
  char spool_hex[SPOOL_COLOR_HEX_MAX + 1];
  snprintf(spool_hex, sizeof(spool_hex), "%s%s",
           spool_color_hex[0] == '#' ? "" : "#", spool_color_hex);
  SpoolColor sc;
  if (tag_color_hex[0] == '#' && spoolColorParse(spool_hex, &sc) && spoolColorNamesHue(sc)) {
    v.color = colorDistance(tag_color_hex, spool_hex) > TAG_SPOOL_COLOR_DIST_MAX;
  }

  // A spool without a maker says nothing about it.
  v.vendor = spool_vendor[0] && strncasecmp(spool_vendor, "Bambu", 5) != 0;
  return v;
}

void tagSpoolTagArticle(char* out, size_t out_size) {
  if (!out || !out_size) return;
  out[0] = '\0';
  if (strlen(g_tag.tray_uuid) != 32) return;
  BambuCatalogHit hit;
  if (bambuCatalogFind(g_tag.material_id, g_tag.material_variant_id, g_tag.color, &hit))
    snprintf(out, out_size, "%s", hit.article);
}

TagSpoolVerdict tagSpoolCompareTag(JsonObjectConst spool) {
  JsonObjectConst fil = spool["filament"];
  char tag_article[16];
  tagSpoolTagArticle(tag_article, sizeof(tag_article));
  const char* spool_article = fil["article_number"] | "";
  const bool article_match = tag_article[0] && strcasecmp(tag_article, spool_article) == 0;
  return tagSpoolCompare(g_tag.material, g_tag.color_hex,
                         fil["material"] | "", fil["name"] | "",
                         fil["vendor"]["name"] | "", fil["color_hex"] | "",
                         article_match);
}

static TagSpoolVerdict s_lookup;
static char s_lookup_material[24] = "";
static char s_lookup_color[SPOOL_COLOR_HEX_MAX] = "";
static char s_lookup_vendor[32] = "";
static int  s_lookup_id = 0;
static bool s_show_spool = false;

void tagSpoolLookupClear() {
  s_lookup = TagSpoolVerdict();
  s_lookup_id = 0;
  s_show_spool = false;
  s_lookup_material[0] = s_lookup_color[0] = s_lookup_vendor[0] = '\0';
}

void tagSpoolLookupNote(JsonObjectConst spool, int spool_id) {
  // The same spool read again - after a weight was written, say - keeps the
  // side the user picked; the screen is showing it.
  const bool keep_view = s_show_spool && spool_id == s_lookup_id;
  tagSpoolLookupClear();
  if (strlen(g_tag.tray_uuid) != 32) return;
  s_lookup_id = spool_id;
  JsonObjectConst fil = spool["filament"];
  snprintf(s_lookup_material, sizeof(s_lookup_material), "%s", fil["material"] | "");
  snprintf(s_lookup_vendor,   sizeof(s_lookup_vendor),   "%s", fil["vendor"]["name"] | "");
  const char* col = fil["color_hex"] | "";
  snprintf(s_lookup_color, sizeof(s_lookup_color), "%s%s", col[0] && col[0] != '#' ? "#" : "", col);
  s_lookup = tagSpoolCompareTag(spool);
  s_show_spool = keep_view && s_lookup.any();
  if (s_lookup.any()) {
    char why[32];
    tagSpoolVerdictText(s_lookup, why, sizeof(why));
    logSDf("Tag vs spool %d: %sdiffer (tag '%s' %s, spool '%s' %s)", spool_id, why,
           g_tag.material, g_tag.color_hex, s_lookup_material, s_lookup_color);
  }
}

bool tagSpoolLookupDiffers()                   { return s_lookup.any(); }
const TagSpoolVerdict& tagSpoolLookupVerdict() { return s_lookup; }
const char* tagSpoolLookupMaterial()           { return s_lookup_material; }
const char* tagSpoolLookupColor()              { return s_lookup_color; }
const char* tagSpoolLookupVendor()             { return s_lookup_vendor; }
bool tagSpoolLookupShowsSpool()                { return s_show_spool; }
void tagSpoolLookupToggleView()                { if (s_lookup.any()) s_show_spool = !s_show_spool; }

void tagSpoolVerdictText(const TagSpoolVerdict& v, char* out, size_t out_size) {
  if (!out || !out_size) return;
  snprintf(out, out_size, "%s%s%s",
           v.material ? "material " : "", v.color ? "color " : "", v.vendor ? "vendor" : "");
}
