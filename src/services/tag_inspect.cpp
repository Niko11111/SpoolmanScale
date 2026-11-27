// What lies on the reader, as the tag page, the tag view and FilaMan's scan
// see it: the description cached from the loop, the JSON the web page reads,
// and the preview a write is compared against. It reads, never writes.
#include "tag_write.h"

#include <ArduinoJson.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "app/app_state.h"
#include "bambu/bambu_catalog.h"
#include "bambu/bambu_scan.h"
#include "bambu/bambu_tag.h"
#include "bambu/material_match.h"
#include "openprinttag/opt_scan.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/material_family.h"
#include "services/spool_color.h"
#include "services/tag_field.h"
#include "services/tag_uid.h"
#include "services/tag_write_internal.h"

using namespace tagw;

static char      cached_uid[26] = "";
static char      cached_kind[34] = "";
// The same statement as a number, because cached_kind is English prose and the
// web page is translated. 0 nothing, 1 MIFARE Classic read-only, 2 NTAG.
static uint8_t   cached_kindcode = TAG_KIND_NONE;
static char      cached_content[128] = "";
static char      cached_raw[512] = "";
static TagInfo   cached_info;
static uint16_t  cached_bytes = 0;
static bool      cache_dirty = false;

const char* tagCachedUid()     { return cached_uid; }
const char* tagCachedKind()    { return cached_kind; }
const char* tagCachedContent() { return cached_content; }
const char* tagCachedRaw()     { return cached_raw; }
const TagInfo* tagCachedInfo() { return &cached_info; }
uint16_t tagCachedBytes()      { return cached_bytes; }
uint8_t  tagCachedKindCode()   { return cached_kindcode; }

// "blank" and "unknown" are answers, not records: one says the pages are
// empty, the other that they hold something no format claims. Neither has a
// brand or a material to show, and both are asked about in three places.
//
// A MIFARE tag never counts. Its fields are cached for the pages that show
// them, but scanTick() would otherwise answer FilaMan for a Bambu tag from
// here rather than from g_tag: "PETG Basic" instead of "PETG", black for a
// clear filament, and no spool id.
bool tagCachedHasRecord() {
  return cached_kindcode == TAG_KIND_NTAG &&
         cached_info.fmt[0] && strcmp(cached_info.fmt, "blank") != 0 &&
         strcmp(cached_info.fmt, "unknown") != 0;
}

void tagw::tagCacheMarkDirty() { cache_dirty = true; }

// snprintf returns the length it *would* have written, so adding that up walks
// the cursor past the end of the buffer the moment anything is truncated:
// out + n then points outside it and out_len - n underflows to a huge size_t.
// This returns what was actually written instead.
//
// The buffers callers pass are big enough for real field sizes, so this was
// latent rather than live - but it is ten appends in a row in tagInfoJson()
// and the same shape again in scanTick(), and the data comes off a tag.
size_t tagw::appendf(char *out, size_t out_len, size_t n, const char *fmt, ...) {
  if (out_len == 0) return 0;
  if (n >= out_len - 1) return out_len - 1;   // already full, nothing more fits
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(out + n, out_len - n, fmt, ap);
  va_end(ap);
  return strnlen(out, out_len);
}

// Every text field here came off a tag or out of a tag's own JSON, so a
// quotation mark in a brand name is a thing that can arrive. Unescaped it
// made the reply malformed, and the tag page then stopped updating with no
// message: r.json() throws and the poll dies.
//
// readText() already drops anything outside 0x20..0x7E, so a quote and a
// backslash are the whole set.
static void jesc(const char *in, char *out, size_t out_len) {
  size_t j = 0;
  for (const char *p = in ? in : ""; *p && j + 2 < out_len; p++) {
    if (*p == '"' || *p == '\\') out[j++] = '\\';
    out[j++] = *p;
  }
  out[j] = '\0';
}

void tagInfoJson(const TagInfo *ti, char *out, size_t out_len) {
  char e[40];
  jesc(ti->fmt, e, sizeof(e));
  snprintf(out, out_len, "{\"fmt\":\"%s\"", e);
  size_t n = strnlen(out, out_len);
  if (ti->brand[0]) {
    jesc(ti->brand, e, sizeof(e));
    n = appendf(out, out_len, n, ",\"brand\":\"%s\"", e);
  }
  if (ti->material[0]) {
    jesc(ti->material, e, sizeof(e));
    n = appendf(out, out_len, n, ",\"material\":\"%s\"", e);
  }
  if (ti->spool_id > 0) n = appendf(out, out_len, n, ",\"spool_id\":%d", ti->spool_id);
  if (ti->proto[0]) {
    jesc(ti->proto, e, sizeof(e));
    n = appendf(out, out_len, n, ",\"proto\":\"%s\"", e);
  }
  if (ti->version[0]) {
    jesc(ti->version, e, sizeof(e));
    n = appendf(out, out_len, n, ",\"version\":\"%s\"", e);
  }
  if (ti->tray_uuid[0]) {
    jesc(ti->tray_uuid, e, sizeof(e));
    n = appendf(out, out_len, n, ",\"tray_uuid\":\"%s\"", e);
  }
  if (ti->prod_date[0]) {
    jesc(ti->prod_date, e, sizeof(e));
    n = appendf(out, out_len, n, ",\"prod_date\":\"%s\"", e);
  }
  if (ti->sku[0]) {
    jesc(ti->sku, e, sizeof(e));
    n = appendf(out, out_len, n, ",\"sku\":\"%s\"", e);
  }
  if (ti->has_color)   n = appendf(out, out_len, n, ",\"color\":\"#%02X%02X%02X\"",
                                   ti->r, ti->g, ti->b);
  if (ti->et_hi)       n = appendf(out, out_len, n, ",\"nozzle\":\"%u-%u\"",
                                   (unsigned)ti->et_lo, (unsigned)ti->et_hi);
  if (ti->bed_hi)      n = appendf(out, out_len, n, ",\"bed\":\"%u-%u\"",
                                   (unsigned)ti->bed_lo, (unsigned)ti->bed_hi);
  if (ti->weight_g)    n = appendf(out, out_len, n, ",\"weight\":%u", (unsigned)ti->weight_g);
  if (ti->dia_x100)    n = appendf(out, out_len, n, ",\"dia\":\"%u.%02u\"",
                                   (unsigned)(ti->dia_x100 / 100), (unsigned)(ti->dia_x100 % 100));
  if (ti->length_m)    n = appendf(out, out_len, n, ",\"len\":%u", (unsigned)ti->length_m);
  if (ti->code[0]) {
    jesc(ti->code, e, sizeof(e));
    n = appendf(out, out_len, n, ",\"code\":\"%s\"", e);
  }
  if (ti->dry_c)       n = appendf(out, out_len, n, ",\"dry_c\":%u,\"dry_h\":%u",
                                   (unsigned)ti->dry_c, (unsigned)ti->dry_h);
  if (ti->has_color2)  n = appendf(out, out_len, n, ",\"color2\":\"#%02X%02X%02X\"",
                                   ti->r2, ti->g2, ti->b2);
  if (ti->color_name[0]) {
    char en[100];
    jesc(ti->color_name, en, sizeof(en));
    n = appendf(out, out_len, n, ",\"cname\":\"%s\"", en);
  }
  if (ti->article[0]) {
    jesc(ti->article, e, sizeof(e));
    n = appendf(out, out_len, n, ",\"article\":\"%s\"", e);
  }
  appendf(out, out_len, n, "}");
}

// The pages of an ACE record. False when one of the number pages did not
// read: a zero colour and weight would describe a black spool of 0 g, and a
// new spool could be created from that.
static bool readAceFields(AceFields *f) {
  memset(f, 0, sizeof(*f));
  readText(ACE_P_SKU, f->sku, sizeof(f->sku));
  readText(ACE_P_BRAND, f->brand, sizeof(f->brand));
  readText(ACE_P_MATERIAL, f->material, sizeof(f->material));
  uint8_t col[4] = {0}, wt[4] = {0}, ext[4] = {0}, bed[4] = {0}, dl[4] = {0};
  if (!nfcReadNtagPage(ACE_P_COLOR, col) || !nfcReadNtagPage(ACE_P_WEIGHT, wt) ||
      !nfcReadNtagPage(ACE_P_EXTRUDER, ext) || !nfcReadNtagPage(ACE_P_BED, bed) ||
      !nfcReadNtagPage(ACE_P_DIALEN, dl)) {
    logSD("Tag: an ACE number page did not read, the record is not taken");
    return false;
  }
  f->r = col[3]; f->g = col[2]; f->b = col[1];
  f->weight_g = rdU16(wt);
  f->et_lo = rdU16(ext);     f->et_hi = rdU16(ext + 2);
  f->bed_lo = rdU16(bed);    f->bed_hi = rdU16(bed + 2);
  f->dia_x100 = rdU16(dl);   f->length_m = rdU16(dl + 2);
  return true;
}

// Page 31 is the filament on a full spool, as buildAce() writes it and as an
// original Anycubic tag holds it (1000 g on a 1 kg spool, 19.11.2026).
static void aceRawJson(const AceFields &f) {
  snprintf(cached_raw, sizeof(cached_raw),
    "{\"format\":\"Anycubic ACE\",\"sku\":\"%s\",\"brand\":\"%s\",\"material\":\"%s\","
    "\"color\":\"#%02X%02X%02X\",\"weight_g\":%u,\"nozzle\":\"%u-%u\","
    "\"bed\":\"%u-%u\",\"diameter_mm\":\"%u.%02u\",\"length_m\":%u}",
    f.sku, f.brand, f.material, f.r, f.g, f.b, f.weight_g,
    f.et_lo, f.et_hi, f.bed_lo, f.bed_hi,
    (unsigned)(f.dia_x100 / 100), (unsigned)(f.dia_x100 % 100), (unsigned)f.length_m);
}

// false when a page read came back short: the caller must not cache that.
static bool tagDescribe(char *out, size_t out_len, TagInfo *ti) {
  out[0] = 0;
  if (ti) memset(ti, 0, sizeof(*ti));
  uint8_t p4[4] = {0};
  if (!nfcReadNtagPage(4, p4)) return false;

  if (p4[0] == 0x7B && p4[1] == 0x00 && p4[2] == 0x65 && p4[3] == 0x00) {
    AceFields f;
    if (!readAceFields(&f)) return false;
    describeAce(&f, out, out_len);
    if (ti) aceToInfo(&f, ti);
    aceRawJson(f);
    return f.material[0] && f.brand[0];
  }

  char json[224];
  json[0] = 0;
  if (readOpenSpool(json, sizeof(json))) {
    snprintf(cached_raw, sizeof(cached_raw), "%s", json);
    describeOpenSpool(json, out, out_len, ti);
    return true;
  }
  if (json[0]) {
    snprintf(cached_raw, sizeof(cached_raw), "%s", json);
  }
  if (p4[0] == 0x03 && !json[0]) return false;

  // A page that will not read is not an empty page. Reporting blank here let
  // a badly seated tag look erased, and the result was cached as trusted.
  bool blank = true;
  for (int pg = 5; pg <= 8 && blank; pg++) {
    uint8_t d[4] = {0};
    if (!nfcReadNtagPage(pg, d)) return false;
    for (int i = 0; i < 4; i++) if (d[i]) { blank = false; break; }
  }
  snprintf(out, out_len, "%s", blank ? "blank" : "unrecognised data");
  if (ti) snprintf(ti->fmt, sizeof(ti->fmt), "%s", blank ? "blank" : "unknown");
  if (blank) {
    snprintf(cached_raw, sizeof(cached_raw),
      "{\"format\":\"NTAG\",\"uid\":\"%s\",\"state\":\"blank\",\"user_bytes\":%u}",
      g_tag.uid_str, (unsigned)cached_bytes);
  } else if (!cached_raw[0]) {
    uint8_t p5[4] = {0}, p6[4] = {0}, p7[4] = {0};
    nfcReadNtagPage(5, p5); nfcReadNtagPage(6, p6); nfcReadNtagPage(7, p7);
    snprintf(cached_raw, sizeof(cached_raw),
      "{\"format\":\"NTAG\",\"uid\":\"%s\",\"state\":\"unrecognised data\","
      "\"p4_p7_hex\":\"%02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X\"}",
      g_tag.uid_str,
      p4[0], p4[1], p4[2], p4[3],
      p5[0], p5[1], p5[2], p5[3],
      p6[0], p6[1], p6[2], p6[3],
      p7[0], p7[1], p7[2], p7[3]);
  }
  return true;
}

bool tagPreview(int spool_id, TagFormat fmt, char *out, size_t out_len,
                char *linked, size_t linked_len, TagInfo *info, uint16_t *need) {
  out[0] = 0;
  linked[0] = 0;
  if (info) memset(info, 0, sizeof(*info));
  if (need) *need = 0;
  if (spool_id <= 0) return false;

  JsonDocument doc;
  if (backendGetSpoolJson(backendBaseUrl(), spool_id, doc) != 200 || doc.isNull())
    return false;
  JsonObjectConst sp = doc.as<JsonObjectConst>();

  // Which tag the spool already carries, and only when that is a *different*
  // tag than the one on the reader. The caller warns that writing here makes
  // the old binding stale, and a warning about the tag lying in front of the
  // user is how that warning stopped meaning anything.
  //
  // Every source, not just extra.tag: nfc_id, card_uids and Spoolman's own
  // relation bind a spool just as well. Normalised on the way out, because
  // extra fields arrive JSON encoded and still carry their quotes, and because
  // a UID is written with or without colons depending on who wrote it.
  linked[0] = 0;
  {
    #define TAG_UID_NORM_MAX 48
    JsonObjectConst extra = sp["extra"];
    JsonArrayConst  tags  = sp["tags"];
    const char* here = cached_uid;
    // A Bambu spool is bound by the tray uuid both of its chips carry, not by
    // the chip on the reader. Checked as well, or the page calls the very tag
    // lying there "another tag" - and the link button would ask to replace it.
    const char* tray = (tag_present && strlen(g_tag.tray_uuid) == 32) ? g_tag.tray_uuid : "";
    auto isHere = [&](const char* raw) {
      return raw[0] && ((here[0] && cardUidsContain(raw, here)) ||
                        (tray[0] && cardUidsContain(raw, tray)));
    };
    bool bound_here = false;

    for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT && !bound_here; i++) {
      if (isHere(extra[tagFieldSpec(i).key] | "")) bound_here = true;
    }
    if (!bound_here && !tags.isNull()) {
      for (JsonObjectConst t : tags) {
        if (isHere(t["uid"] | "")) { bound_here = true; break; }
      }
    }

    if (!bound_here) {
      char norm[TAG_UID_NORM_MAX];
      for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT && !linked[0]; i++) {
        tagUidNormalize(extra[tagFieldSpec(i).key] | "", norm, sizeof(norm));
        if (norm[0]) snprintf(linked, linked_len, "%s", norm);
      }
      if (!linked[0] && !tags.isNull()) {
        for (JsonObjectConst t : tags) {
          tagUidNormalize(t["uid"] | "", norm, sizeof(norm));
          if (norm[0]) { snprintf(linked, linked_len, "%s", norm); break; }
        }
      }
    }
  }

  if (fmt == TAG_FMT_ERASE) {
    snprintf(out, out_len, "blank");
    if (info) snprintf(info->fmt, sizeof(info->fmt), "blank");
    return true;
  }
  AceFields f;
  buildAce(sp, &f);
  if (info) {
    aceToInfo(&f, info);
    if (TAG_FMT_IS_NDEF(fmt)) {
      // OpenSpool carries neither the SKU nor the spool geometry.
      snprintf(info->fmt, sizeof(info->fmt), "%s",
               fmt == TAG_FMT_FILAMAN ? "FilaMan" : "OpenSpool");
      info->sku[0] = 0;
      info->bed_lo = info->bed_hi = 0;
      info->dia_x100 = info->length_m = info->weight_g = 0;
      info->spool_id = spool_id;
      snprintf(info->proto, sizeof(info->proto), "%s", fmt == TAG_FMT_FILAMAN ? "filaman" : "openspool");
      snprintf(info->version, sizeof(info->version), "1.0");
    }
  }
  if (TAG_FMT_IS_NDEF(fmt)) {
    // Measured on the record that would really be written, not estimated. The
    // brand name alone moves this by a dozen bytes, which is the difference
    // between fitting an NTAG213 and not.
    if (need) {
      char json[224];
      const int n = buildOpenSpoolJson(&f, spool_id, fmt, json, sizeof(json));
      if (n > 0) *need = (uint16_t)tagNdefSizeFor((size_t)n);
    }
    snprintf(out, out_len, "%s: %s %s, #%02X%02X%02X, %u-%uC",
             fmt == TAG_FMT_FILAMAN ? "FilaMan" : "OpenSpool",
             f.brand, f.material, f.r, f.g, f.b,
             (unsigned)f.et_lo, (unsigned)f.et_hi);
    return true;
  }
  if (need) *need = ACE_BYTES;
  describeAce(&f, out, out_len);
  return true;
}

// The threshold the link flow and the remote link popup already judge a colour
// pair by, so the same two spools are called a mismatch everywhere.
#define TAG_MISMATCH_COLOR_DIST  120

bool tagDiffersFromSpool(int spool_id, TagFormat fmt, TagInfo *want) {
  if (!want || spool_id <= 0) return false;
  if (!tagCachedHasRecord()) return false;

  char out[128], linked[26];
  if (!tagPreview(spool_id, fmt, out, sizeof(out), linked, sizeof(linked), want))
    return false;

  const TagInfo *have = &cached_info;

  // Family against family where both are known, so "PLA" and "PLA Basic" agree
  // and asking about that would be asking about nothing. Where either side is
  // outside the family list, the names themselves decide - two unknowns are
  // only the same filament if they are spelled the same.
  if (have->material[0] && want->material[0]) {
    const MatFamily* fh = matchFamily(have->material);
    const MatFamily* fw = matchFamily(want->material);
    const bool differs = (fh && fw)
                       ? (fh != fw)
                       : (strcasecmp(have->material, want->material) != 0);
    if (differs) return true;
  }

  // "Generic" is buildAce()'s stand-in for a spool with no vendor. Treating it
  // as a brand would report every tag that names one as a mismatch.
  if (have->brand[0] && want->brand[0] && strcasecmp(want->brand, "Generic") != 0 &&
      strcasecmp(have->brand, want->brand) != 0) return true;

  if (have->has_color && want->has_color && (want->r || want->g || want->b)) {
    char a[8], b[8];
    snprintf(a, sizeof(a), "#%02X%02X%02X", have->r, have->g, have->b);
    snprintf(b, sizeof(b), "#%02X%02X%02X", want->r, want->g, want->b);
    if (colorDistance(a, b) > TAG_MISMATCH_COLOR_DIST) return true;
  }

  return false;
}

// How many reads in a row may describe nothing before a tag is left alone.
static constexpr uint8_t TAG_UNREADABLE_LIMIT = 3;

// Printable ASCII only, up to the first byte that is not. jesc() relies on
// that, and readText() guarantees it for an NTAG; the MIFARE decoders copy
// sector bytes as they come, and one control character in the reply made the
// tag page's r.json() throw.
static void copyPrintable(char *out, size_t out_len, const char *in) {
  size_t j = 0;
  for (const char *p = in; *p && j + 1 < out_len; p++) {
    if (*p < 0x20 || *p > 0x7E) break;
    out[j++] = *p;
  }
  out[j] = '\0';
}

// What a MIFARE tag holds, out of what the main flow already decoded into
// g_tag, so the tag page and the tag view can show a Bambu or Snapmaker tag
// the way they show an NTAG record. Nothing here touches the reader.
//
// Bambu is told from Snapmaker by the blocks that read with Bambu's keys: the
// Snapmaker decoder starts from a cleared g_tag and fills none of them.
static void infoFromMifare(TagInfo *ti) {
  memset(ti, 0, sizeof(*ti));
  const bool bambu = countBambuDataBlocksRead(g_tag) > 0;
  if (!bambu && !g_tag.material[0] && !g_tag.vendor[0]) {
    snprintf(ti->fmt, sizeof(ti->fmt), "unsupported");
    return;
  }
  const bool creality = !bambu && !strcmp(g_tag.decoder, "Creality");
  snprintf(ti->fmt, sizeof(ti->fmt), "%s", bambu ? "Bambu" : creality ? "Creality" : "Snapmaker");
  // Most Bambu tags carry no vendor string, but a tag that reads with the
  // Bambu keys can only be theirs - the answer scanTick() gives as well.
  copyPrintable(ti->brand, sizeof(ti->brand),
                g_tag.vendor[0] ? g_tag.vendor : (bambu ? "Bambu Lab" : ""));
  copyPrintable(ti->material, sizeof(ti->material), g_tag.material);
  // The Snapmaker decoder puts the UID there, which says nothing new.
  if (bambu) copyPrintable(ti->tray_uuid, sizeof(ti->tray_uuid), g_tag.tray_uuid);
  copyPrintable(ti->prod_date, sizeof(ti->prod_date), g_tag.production_date);
  // color_hex decides, not color.valid: it is empty for a clear filament,
  // which names no hue and would otherwise be drawn as black.
  if (g_tag.color.valid && g_tag.color_hex[0]) {
    ti->has_color = true;
    ti->r = (uint8_t)(g_tag.color.rgb >> 16);
    ti->g = (uint8_t)(g_tag.color.rgb >> 8);
    ti->b = (uint8_t)g_tag.color.rgb;
  }
  if (g_tag.temp_min > 0) ti->et_lo = (uint16_t)g_tag.temp_min;
  if (g_tag.temp_max > 0) ti->et_hi = (uint16_t)g_tag.temp_max;
  if (g_tag.spool_weight > 0) ti->weight_g = (uint16_t)g_tag.spool_weight;
  if (creality) {
    // Its length and numbers; the diameter is not on the tag, the scan only
    // assumes 1.75 mm for the CFS.
    if (g_tag.length_m > 0) ti->length_m = (uint16_t)g_tag.length_m;
    copyPrintable(ti->code, sizeof(ti->code), g_tag.material_id);
    copyPrintable(ti->serial, sizeof(ti->serial), g_tag.serial);
    copyPrintable(ti->batch, sizeof(ti->batch), g_tag.batch);
  }
  if (!bambu) return;
  if (g_tag.diameter_mm > 0) ti->dia_x100 = (uint16_t)lroundf(g_tag.diameter_mm * 100.0f);
  if (g_tag.length_m > 0)    ti->length_m = (uint16_t)g_tag.length_m;
  if (g_tag.material_id[0]) {
    snprintf(ti->code, sizeof(ti->code), g_tag.material_variant_id[0] ? "%s / %s" : "%s",
             g_tag.material_id, g_tag.material_variant_id);
  }
  if (g_tag.dry_temp_c > 0) {
    ti->dry_c = (uint16_t)g_tag.dry_temp_c;
    ti->dry_h = (uint16_t)g_tag.dry_hours;
  }
  if (g_tag.color_count >= 2 && g_tag.color2.valid) {
    ti->has_color2 = true;
    ti->r2 = (uint8_t)(g_tag.color2.rgb >> 16);
    ti->g2 = (uint8_t)(g_tag.color2.rgb >> 8);
    ti->b2 = (uint8_t)g_tag.color2.rgb;
  }
  BambuCatalogHit hit;
  if (bambuCatalogFind(g_tag.material_id, g_tag.material_variant_id, g_tag.color, &hit)) {
    snprintf(ti->color_name, sizeof(ti->color_name), "%s", hit.color_name);
    snprintf(ti->article, sizeof(ti->article), "%s", hit.article);
  }
}

// Uses what the main NFC poll already found. Selecting the tag again here
// would compete with that poll, and the loser gets nothing back.
//
// force skips the retry gap, for the one caller that runs immediately after a
// poll and needs the answer in the same pass rather than half a second later.
void tagw::refreshCache(bool force) {
  static unsigned long last_ms = 0;
  static char last_uid[26] = "";
  static uint8_t unreadable = 0;   // reads in a row that described nothing

  if (!tag_present) {
    cached_uid[0] = 0; cached_kind[0] = 0; cached_content[0] = 0;
    cached_raw[0] = 0;
    cached_bytes = 0;
    cached_kindcode = TAG_KIND_NONE;
    memset(&cached_info, 0, sizeof(cached_info));
    last_uid[0] = 0;
    unreadable = 0;
    return;
  }

  const bool is_ntag = strlen(g_tag.uid_str) == TAG_UID_STR_LEN_NTAG;
  snprintf(cached_uid, sizeof(cached_uid), "%s", g_tag.uid_str);
  // The branches below for other tags overwrite cached_info: an NTAG that
  // comes back after one of them is read again, not taken for described.
  if (!is_ntag) last_uid[0] = 0;

  if (strlen(g_tag.uid_str) == TAG_UID_STR_LEN_VICINITY) {
    // What the scan path decoded (openprinttag/opt_scan.cpp); nothing is read here.
    snprintf(cached_kind, sizeof(cached_kind), "ISO 15693, read-only");
    cached_kindcode = TAG_KIND_VICINITY;
    cached_content[0] = 0;
    cached_bytes = 0;
    optFillTagInfo(&cached_info);
    if (optTagOnReader()) optSummaryJson(cached_raw, sizeof(cached_raw));
    else cached_raw[0] = 0;
    return;
  }

  if (!is_ntag) {
    snprintf(cached_kind, sizeof(cached_kind), "MIFARE Classic, read-only");
    cached_kindcode = TAG_KIND_MIFARE;
    cached_content[0] = 0;
    cached_bytes = 0;
    // On every pass: the main poll fills g_tag over several passes while its
    // retries run, and this is a copy of a few strings, not a read.
    infoFromMifare(&cached_info);
    const char *chex = g_tag.color_hex[0] == '#' ? g_tag.color_hex + 1 : g_tag.color_hex;
    if (!strcmp(cached_info.fmt, "Bambu")) {
      char c2[SPOOL_COLOR_HEX_MAX] = "";
      if (g_tag.color_count >= 2) spoolColorFormat(g_tag.color2, c2, sizeof(c2));
      snprintf(cached_raw, sizeof(cached_raw),
        "{\"format\":\"Bambu Lab\",\"uid\":\"%s\",\"tray_uuid\":\"%s\",\"vendor\":\"%s\","
        "\"material\":\"%s\",\"type\":\"%s\",\"material_id\":\"%s\",\"variant_id\":\"%s\","
        "\"color\":\"#%s\",\"colors\":%d,\"color2\":\"%s\",\"nozzle\":\"%d-%d\","
        "\"spool_weight_g\":%.0f,\"diameter_mm\":%.2f,\"length_m\":%d,"
        "\"dry_c\":%d,\"dry_h\":%d,\"production_date\":\"%s\",\"blocks_read\":%d}",
        g_tag.uid_str, g_tag.tray_uuid, g_tag.vendor, g_tag.material,
        g_tag.filament_type, g_tag.material_id, g_tag.material_variant_id,
        chex, (int)g_tag.color_count, c2, g_tag.temp_min, g_tag.temp_max,
        (double)g_tag.spool_weight, (double)g_tag.diameter_mm, g_tag.length_m,
        g_tag.dry_temp_c, g_tag.dry_hours,
        g_tag.production_date, countBambuDataBlocksRead(g_tag));
    } else if (!strcmp(cached_info.fmt, "Creality")) {
      snprintf(cached_raw, sizeof(cached_raw),
        "{\"format\":\"Creality CFS\",\"uid\":\"%s\",\"vendor\":\"%s\",\"filament\":\"%s\","
        "\"filament_id\":\"%s\",\"material\":\"%s\",\"color\":\"#%s\",\"nozzle\":\"%d-%d\","
        "\"weight_g\":%.0f,\"serial\":\"%s\",\"date\":\"%s\"}",
        g_tag.uid_str, g_tag.vendor, g_tag.detailed_filament, g_tag.material_id,
        g_tag.material, chex, g_tag.temp_min, g_tag.temp_max,
        (double)g_tag.spool_weight, g_tag.serial, g_tag.production_date);
    } else if (!strcmp(cached_info.fmt, "Snapmaker")) {
      snprintf(cached_raw, sizeof(cached_raw),
        "{\"format\":\"Snapmaker\",\"uid\":\"%s\",\"material\":\"%s\",\"color\":\"#%s\","
        "\"nozzle\":\"%d-%d\",\"spool_weight_g\":%.0f}",
        g_tag.uid_str, g_tag.material, chex,
        g_tag.temp_min, g_tag.temp_max, (double)g_tag.spool_weight);
    } else {
      snprintf(cached_raw, sizeof(cached_raw),
        "{\"format\":\"MIFARE Classic\",\"uid\":\"%s\",\"type\":\"Read-only / Unregistered\",\"sectors\":16,\"blocks\":64}",
        g_tag.uid_str);
    }
    return;
  }

  const bool uid_changed = strcmp(last_uid, g_tag.uid_str) != 0;
  const bool changed = uid_changed || cache_dirty;
  // What the cache holds describes the tag before this one: kept, a failed
  // first read would show the old record under the new UID.
  if (uid_changed) {
    unreadable = 0;
    cached_raw[0] = 0;
    cached_content[0] = 0;
    memset(&cached_info, 0, sizeof(cached_info));
  }
  if (!changed && cached_content[0]) return;
  // A blank NTAG, or one written by something this firmware does not know,
  // never yields a description. Returning only on content meant such a tag had
  // its pages read again every 500 ms for as long as it lay there, next to the
  // main poll and on the same reader. A few tries cover a read that merely
  // failed, then it is left alone until the tag changes or is written to.
  if (!changed && unreadable >= TAG_UNREADABLE_LIMIT) return;
  // Retry gap after a failed read. A forced read has just been handed a freshly
  // selected tag, so there is nothing to back off from.
  if (!force && millis() - last_ms < 500) return;
  last_ms = millis();
  if (changed) snprintf(last_uid, sizeof(last_uid), "%s", g_tag.uid_str);

  const uint16_t bytes = tagUserBytes();
  cached_bytes = bytes;
  cached_kindcode = TAG_KIND_NTAG;
  if (bytes) snprintf(cached_kind, sizeof(cached_kind), "NTAG, writable, %u bytes",
                      (unsigned)bytes);
  else       snprintf(cached_kind, sizeof(cached_kind), "NTAG, writable");

  // A page read that loses the reader returns a short or empty result, so keep
  // the last good description rather than blanking the page.
  char tmp[128];
  TagInfo ti;
  if (tagDescribe(tmp, sizeof(tmp), &ti) && tmp[0]) {
    snprintf(cached_content, sizeof(cached_content), "%s", tmp);
    // Every field, once per tag: a tag that was on the reader only once
    // (another maker's spool at a fair stand) can be read back from the log.
    if (changed) logSDf("Tag: record %s", cached_raw[0] ? cached_raw : tmp);
    cached_info = ti;
    cache_dirty = false;
    unreadable = 0;
  } else if (unreadable < TAG_UNREADABLE_LIMIT && ++unreadable >= TAG_UNREADABLE_LIMIT &&
             cache_dirty) {
    // Written or erased, and nothing readable came back since. What the cache
    // still holds describes the tag as it was before, so it goes rather than
    // being shown as current, and the retrying ends here as well.
    cached_content[0] = 0;
    cached_raw[0] = 0;
    memset(&cached_info, 0, sizeof(cached_info));
    cache_dirty = false;
  }
}

void tagReadInfoNow() { refreshCache(true); }
