#include "tag_create_bambu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../app/app_state.h"
#include "../app_config.h"
#include "../bambu/bambu_catalog.h"

// The tray UUID of block 9, the mark of a Bambu tag read in full.
#define BAMBU_TRAY_UUID_LEN  32
// Bambu's plain line. The filament databases leave the word out: SpoolmanDB
// calls PLA Basic Black just "Black", next to "Tough+ Black".
#define BAMBU_PLAIN_LINE     "Basic"

// The base type: block 2 when it read, otherwise the material up to its
// first separator ("PETG HF" -> "PETG").
static void baseMaterial(char* out, size_t out_size) {
  if (g_tag.filament_type[0]) { snprintf(out, out_size, "%s", g_tag.filament_type); return; }
  size_t head = 0;
  while (g_tag.material[head] && g_tag.material[head] != ' ' && g_tag.material[head] != '-') head++;
  if (head >= out_size) head = out_size - 1;
  memcpy(out, g_tag.material, head);
  out[head] = '\0';
}

// A gradient or dual colour spool as the catalog knows it: every colour (the
// tag holds two of Dawn Radiance's four) and how they lie on the spool.
static void catalogColors(TagCreateInput* in, const BambuCatalogHit& hit) {
  if (hit.ncol < 2) return;
  in->color_count = 0;
  for (uint8_t i = 0; i < hit.ncol; i++) tagCreateAddColor(in, hit.rgba[i] >> 8);
  in->color_kind = hit.kind == BCK_GRADIENT ? TCK_GRADIENT
                 : hit.kind == BCK_DUAL     ? TCK_DUAL : TCK_SINGLE;
}

// Article number and colour name, which the tag holds only as codes.
static void catalogNames(TagCreateInput* in) {
  BambuCatalogHit hit;
  in->names_known = bambuCatalogFind(g_tag.material_id, g_tag.material_variant_id,
                                     g_tag.color, &hit);
  if (!in->names_known) {
    snprintf(in->product, sizeof(in->product), "%s", g_tag.material);
    return;
  }
  snprintf(in->product, sizeof(in->product), "%s", hit.product);
  snprintf(in->article, sizeof(in->article), "%s", hit.article);
  snprintf(in->color_name, sizeof(in->color_name), "%s", hit.color_name);
  snprintf(in->color_name_en, sizeof(in->color_name_en), "%s", hit.color_name_en);
  catalogColors(in, hit);
}

bool tagCreateBambuFromCatalog(TagCreateInput* in) {
  if (!in || in->clear || !in->color_hex[0]) return false;
  BambuCatalogHit hit;
  const uint32_t rgb = (uint32_t)strtoul(in->color_hex, nullptr, 16);
  if (!bambuCatalogFindByLook(in->product, rgb, in->color_name_en, &hit)) return false;
  snprintf(in->article, sizeof(in->article), "%s", hit.article);
  snprintf(in->color_name, sizeof(in->color_name), "%s", hit.color_name);
  snprintf(in->color_name_en, sizeof(in->color_name_en), "%s", hit.color_name_en);
  catalogColors(in, hit);
  in->names_known = true;
  return true;
}

bool tagCreateInputFromBambu(TagCreateInput* in) {
  if (strlen(g_tag.tray_uuid) != BAMBU_TRAY_UUID_LEN || !g_tag.material[0]) return false;

  // Bambu tags carry no vendor string (see BAMBU_VENDOR_NAME).
  snprintf(in->vendor, sizeof(in->vendor), "%s", g_tag.vendor[0] ? g_tag.vendor : BAMBU_VENDOR_NAME);
  snprintf(in->link_id, sizeof(in->link_id), "%s", g_tag.tray_uuid);
  snprintf(in->plain_line, sizeof(in->plain_line), "%s", BAMBU_PLAIN_LINE);
  baseMaterial(in->material, sizeof(in->material));
  tagCreateColorsFromTag(in);
  catalogNames(in);
  tagCreateSplitProduct(in);
  in->net_weight_g   = (int)(g_tag.spool_weight + 0.5f);
  in->spool_weight_g = BAMBU_CORE_WEIGHT_G;
  in->diameter_mm    = g_tag.diameter_mm;
  in->temp_min       = g_tag.temp_min;
  in->temp_max       = g_tag.temp_max;
  return true;
}
