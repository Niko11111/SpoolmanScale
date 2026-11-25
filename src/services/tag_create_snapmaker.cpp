#include "tag_create_snapmaker.h"

#include <stdio.h>
#include <string.h>

#include "../app/app_state.h"
#include "tag_create_record.h"
#include "tag_write.h"

// The cache tells a Snapmaker tag from Bambu and Creality (infoFromMifare());
// the decoder itself leaves no mark of its own in g_tag.
static bool snapmakerOnReader() {
  if (strlen(g_tag.uid_str) != TAG_UID_STR_LEN_MIFARE) return false;
  if (strcmp(tagCachedUid(), g_tag.uid_str) != 0) return false;
  const TagInfo* ti = tagCachedInfo();
  return ti && strcmp(ti->fmt, "Snapmaker") == 0;
}

bool tagCreateInputFromSnapmaker(TagCreateInput* in) {
  if (!snapmakerOnReader()) return false;
  if (!tagCreateFromSnapmaker(g_tag.vendor, g_tag.material, in)) return false;
  // Found again by its UID, like every other 4 byte MIFARE tag.
  snprintf(in->link_id, sizeof(in->link_id), "%s", g_tag.uid_str);
  tagCreateColorsFromTag(in);
  in->net_weight_g = g_tag.spool_weight > 0 ? (int)(g_tag.spool_weight + 0.5f) : 0;
  in->temp_min     = g_tag.temp_min;
  in->temp_max     = g_tag.temp_max;
  return true;
}
