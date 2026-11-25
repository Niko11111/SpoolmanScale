#include "tag_create_ntag.h"

#include <stdio.h>
#include <string.h>

#include "../app/app_state.h"
#include "tag_create_record.h"
#include "tag_write.h"

// The record in the cache is the one of the tag on the reader: the cache
// keeps its last description, and the scan path does not clear it in step
// with g_tag.
static const TagInfo* recordOnReader() {
  if (strlen(g_tag.uid_str) != TAG_UID_STR_LEN_NTAG) return nullptr;
  if (strcmp(tagCachedUid(), g_tag.uid_str) != 0) return nullptr;
  const TagInfo* ti = tagCachedInfo();
  return ti && ti->fmt[0] ? ti : nullptr;
}

static TagRecord recordOf(const TagInfo* ti) {
  const TagRecord r = { ti->fmt, ti->brand, ti->material, ti->sku, ti->spool_id,
                        ti->et_lo, ti->et_hi, ti->dia_x100, ti->weight_g };
  return r;
}

bool tagOwnSpoolOnReader(TagOwnSpool* out) {
  const TagInfo* ti = recordOnReader();
  if (!ti || !out) return false;
  out->spool_id = tagRecordOwnSpoolId(recordOf(ti));
  if (out->spool_id <= 0) return false;
  out->brand = ti->brand;
  out->material = ti->material;
  out->color_hex[0] = '\0';
  if (ti->has_color)
    snprintf(out->color_hex, sizeof(out->color_hex), "#%02X%02X%02X", ti->r, ti->g, ti->b);
  return true;
}

bool tagCreateInputFromNtag(TagCreateInput* in) {
  const TagInfo* ti = recordOnReader();
  if (!ti) return false;
  if (!tagCreateFromRecord(recordOf(ti), in)) return false;
  // Found again by its UID, as every NTAG is.
  snprintf(in->link_id, sizeof(in->link_id), "%s", g_tag.uid_str);
  if (ti->has_color) {
    const uint32_t rgb = ((uint32_t)ti->r << 16) | ((uint32_t)ti->g << 8) | ti->b;
    snprintf(in->rgba, sizeof(in->rgba), "%06XFF", (unsigned)rgb);
    tagCreateAddColor(in, rgb);
  }
  return true;
}
