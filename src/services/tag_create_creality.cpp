#include "tag_create_creality.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "../app/app_state.h"

// The product without the material word: "Hyper PLA" and "PLA" leave
// "Hyper", "PLA-CF" stays as it is when the material is "PLA-CF". Creality
// puts the line in front of the material, where tagCreateSplitProduct()
// expects it behind.
static void lineFromProduct(TagCreateInput* in) {
  in->subtype[0] = '\0';
  const char* p = in->product;
  const size_t n = strlen(in->material);
  if (!n || !p[0]) return;
  char out[sizeof(in->subtype)] = "";
  size_t o = 0;
  while (*p) {
    while (*p == ' ') p++;
    const char* w = p;
    while (*p && *p != ' ') p++;
    const size_t len = (size_t)(p - w);
    if (!len) break;
    if (len == n && strncasecmp(w, in->material, n) == 0) continue;
    if (o && o + 1 < sizeof(out)) out[o++] = ' ';
    for (size_t i = 0; i < len && o + 1 < sizeof(out); i++) out[o++] = w[i];
  }
  out[o] = '\0';
  snprintf(in->subtype, sizeof(in->subtype), "%s", out);
}

bool tagCreateInputFromCreality(TagCreateInput* in) {
  if (strcmp(g_tag.decoder, "Creality") != 0 || !g_tag.material[0]) return false;

  snprintf(in->vendor, sizeof(in->vendor), "%s", g_tag.vendor[0] ? g_tag.vendor : "Creality");
  snprintf(in->material, sizeof(in->material), "%s", g_tag.material);
  // detailed_filament holds the product ("Hyper PLA"), or "Creality ID 01001"
  // for an id the table on the scale does not know; that one names nothing a
  // database could match, so the material stands in for it.
  if (g_tag.detailed_filament[0] && strncmp(g_tag.detailed_filament, "Creality ID", 11) != 0) {
    snprintf(in->product, sizeof(in->product), "%s", g_tag.detailed_filament);
  } else {
    snprintf(in->product, sizeof(in->product), "%s", g_tag.material);
  }
  lineFromProduct(in);
  // The tag is found again by its UID, like every other 4 byte MIFARE tag
  // (copy_flow.cpp: anything that is not a 32 character tray uuid).
  snprintf(in->link_id, sizeof(in->link_id), "%s", g_tag.uid_str);
  tagCreateColorsFromTag(in);
  in->net_weight_g   = (int)(g_tag.spool_weight + 0.5f);
  // Unknown: a CFS tag says nothing about the empty spool, and the record
  // sits on third party spools as well.
  in->spool_weight_g = 0;
  in->diameter_mm    = g_tag.diameter_mm > 0.0f ? g_tag.diameter_mm : TAG_CREATE_DIAMETER_MM;
  in->temp_min       = g_tag.temp_min;
  in->temp_max       = g_tag.temp_max;
  return true;
}
