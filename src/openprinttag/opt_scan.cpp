#include "openprinttag/opt_scan.h"

#include <Arduino.h>
#include <initializer_list>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "openprinttag/opt_sim.h"
#include "services/tag_write.h"

namespace {

constexpr size_t   ISO15693_BLOCK = 4;
// The head read first: the CC and the start of the TLVs (8 blocks, one READ
// MULTIPLE).
constexpr uint8_t  HEAD_BLOCKS = 8;
constexpr size_t   HEAD_BYTES = HEAD_BLOCKS * ISO15693_BLOCK;
// What is kept and read at most: the format's tags are 304 to 316 bytes, and
// every region is at most 512 bytes. A CC declaring more is cut, and logged.
constexpr size_t   MEM_MAX = 512;
// A read that has not finished by then is given up (the tag left mid-read);
// the next poll tries again, at most READ_RETRIES times for one UID before
// the tag counts as a plain ISO 15693 tag until it is put down again. A spool
// set down off centre takes a few polls to settle (some 3 s at 500 ms).
constexpr uint32_t READ_BUDGET_MS = 1500;
constexpr uint8_t  READ_RETRIES = 5;
constexpr uint8_t  READ_CHUNK_BLOCKS = 16;   // per call; the driver splits further
constexpr int      MINUTES_PER_HOUR = 60;
constexpr float    MM_PER_M = 1000.0f;
constexpr size_t   DUMP_BYTES_PER_LINE = 32;
const char OPT_DECODER[] = "OPT";

struct ReadReport {
  size_t bytes;        // read
  size_t wanted;       // what the CC and the TLV said
  uint32_t ms;
  int failed_block;    // -1 none
  bool cut;            // the tag declares more than MEM_MAX
};

}  // namespace

static uint8_t    s_mem[MEM_MAX];
static ReadReport s_report = {};
static OptTag     s_tag = {};
static OptResult  s_result = OPT_NO_CC;
static char       s_uid[OPT_UID_STR_LEN + 1] = "";
static uint8_t    s_uid_wire[OPT_UID_BYTES] = {0};
static uint8_t    s_retries = 0;        // reads that broke off in a row
static uint8_t    s_retries_used = 0;   // by the last finished read, for the debug route
static bool       s_read_ok = false;

const OptTag& optLastTag() { return s_tag; }

// Blocks [from, to) into s_mem, within the time budget.
static bool readBlocks(uint16_t from, uint16_t to, uint32_t t0) {
  for (uint16_t b = from; b < to; b += READ_CHUNK_BLOCKS) {
    if (millis() - t0 > READ_BUDGET_MS) {
      s_report.failed_block = b;
      return false;
    }
    const uint16_t n = (to - b) < READ_CHUNK_BLOCKS ? (to - b) : READ_CHUNK_BLOCKS;
    if (!nfcReadVicinityBlocks((uint8_t)b, n, s_mem + (size_t)b * ISO15693_BLOCK)) {
      s_report.failed_block = b;
      return false;
    }
    s_report.bytes = (size_t)(b + n) * ISO15693_BLOCK;
  }
  return true;
}

// The CC and the first TLVs, then up to the end of the NDEF message.
static bool readMemory() {
  const uint32_t t0 = millis();
  s_report = ReadReport{0, 0, 0, -1, false};
  memset(s_mem, 0, sizeof(s_mem));
  const size_t simulated = optSimMemory(s_uid_wire, s_mem, sizeof(s_mem));
  if (simulated) {
    s_report.bytes = s_report.wanted = simulated;
    return true;
  }
  bool ok = readBlocks(0, HEAD_BLOCKS, t0);
  if (ok) {
    size_t want = optBytesNeeded(s_mem, HEAD_BYTES);
    s_report.cut = want > MEM_MAX;
    if (want > MEM_MAX) want = MEM_MAX;
    s_report.wanted = want;
    const uint16_t blocks = (uint16_t)((want + ISO15693_BLOCK - 1) / ISO15693_BLOCK);
    if (blocks > HEAD_BLOCKS) ok = readBlocks(HEAD_BLOCKS, blocks, t0);
  }
  s_report.ms = millis() - t0;
  return ok;
}

static void dumpMemory(const char* why) {
  const size_t n = s_report.bytes;
  for (size_t at = 0; at < n; at += DUMP_BYTES_PER_LINE) {
    char hex[DUMP_BYTES_PER_LINE * 2 + 1];
    size_t used = 0;
    for (size_t i = at; i < n && i < at + DUMP_BYTES_PER_LINE; i++) {
      used += (size_t)snprintf(hex + used, sizeof(hex) - used, "%02X", s_mem[i]);
    }
    logSDf("OPT raw %03u (%s): %s", (unsigned)at, why, hex);
  }
}

static void logRead(bool ok) {
  char broke[32] = "";
  if (!ok) snprintf(broke, sizeof(broke), ", broke off at block %d", s_report.failed_block);
  logSDf("OPT: %s read %u of %u bytes in %lu ms%s, CC %02X %02X %02X %02X", s_uid,
         (unsigned)s_report.bytes, (unsigned)s_report.wanted, (unsigned long)s_report.ms,
         broke, s_mem[0], s_mem[1], s_mem[2], s_mem[3]);
  if (s_report.cut) logSDf("OPT: %s declares more than %u bytes, read the first %u", s_uid,
                           (unsigned)MEM_MAX, (unsigned)MEM_MAX);
}

static void fillColor(const OptTag& t) {
  if (t.color_count == 0) return;
  const uint8_t* c = t.colors[0];
  snprintf(g_tag.color_hex, sizeof(g_tag.color_hex), "#%02X%02X%02X", c[0], c[1], c[2]);
  g_tag.color = spoolColorFromRgba(c[0], c[1], c[2], c[3]);
  g_tag.color_count = 1;
  if (t.color_count >= 2) {
    const uint8_t* c2 = t.colors[1];
    g_tag.color2 = spoolColorFromRgba(c2[0], c2[1], c2[2], c2[3]);
    g_tag.color_count = 2;
  }
}

// g_tag the way creality_scan.cpp fills it: the base material, the product,
// the maker, looked up by UID.
static void fillGTag(const OptTag& t) {
  memset(&g_tag, 0, sizeof(g_tag));
  snprintf(g_tag.uid_str, sizeof(g_tag.uid_str), "%s", s_uid);
  snprintf(g_tag.decoder, sizeof(g_tag.decoder), "%s", OPT_DECODER);
  snprintf(g_tag.material, sizeof(g_tag.material), "%s", optMaterialAbbr(t));
  snprintf(g_tag.filament_type, sizeof(g_tag.filament_type), "%s", optMaterialAbbr(t));
  snprintf(g_tag.detailed_filament, sizeof(g_tag.detailed_filament), "%s", t.material_name);
  snprintf(g_tag.vendor, sizeof(g_tag.vendor), "%s", t.brand);
  snprintf(g_tag.short_uid, sizeof(g_tag.short_uid), "%s", t.instance_id);
  fillColor(t);
  g_tag.temp_min = t.print_min_c;
  g_tag.temp_max = t.print_max_c;
  const float full = optFullWeightG(t);
  g_tag.spool_weight = full > 0 ? full : 0;
  g_tag.diameter_mm = t.diameter_mm;
  g_tag.dry_temp_c = t.dry_c;
  g_tag.dry_hours = (t.dry_minutes + MINUTES_PER_HOUR / 2) / MINUTES_PER_HOUR;
  const float length = t.actual_length_mm > 0 ? t.actual_length_mm : t.nominal_length_mm;
  if (length > 0) g_tag.length_m = (int)lroundf(length / MM_PER_M);
  optFormatDate(t.manufactured, g_tag.production_date, sizeof(g_tag.production_date));
  snprintf(g_tag.tray_uuid, sizeof(g_tag.tray_uuid), "%s", s_uid);
}

// An ISO 15693 tag without an OpenPrintTag: shown and looked up by its UID,
// like a plain card.
static void fillUidOnly() {
  memset(&g_tag, 0, sizeof(g_tag));
  snprintf(g_tag.uid_str, sizeof(g_tag.uid_str), "%s", s_uid);
}

static void startTag(const uint8_t uid_wire[OPT_UID_BYTES], const char* uid_str) {
  if (strcmp(uid_str, s_uid) == 0) return;
  snprintf(s_uid, sizeof(s_uid), "%s", uid_str);
  memcpy(s_uid_wire, uid_wire, OPT_UID_BYTES);
  s_retries = 0;
  s_read_ok = false;
  logSDf("OPT: ISO 15693 tag %s (wire order %02X %02X .. %02X)%s", s_uid, uid_wire[0],
         uid_wire[1], uid_wire[OPT_UID_BYTES - 1],
         uid_wire[OPT_UID_BYTES - 1] == 0xE0 ? "" : ", UID does not start with E0");
}

OptScanResult optScanTag(const uint8_t uid_wire[OPT_UID_BYTES], const char* uid_str) {
  startTag(uid_wire, uid_str);
  const bool ok = readMemory();
  logRead(ok);
  if (!ok && ++s_retries <= READ_RETRIES) return OPT_SCAN_RETRY;
  // Finished, one way or the other: the same tag put down again gets its retries anew.
  s_retries_used = s_retries;
  s_retries = 0;
  s_read_ok = ok;
  s_result = optDecodeMemory(s_mem, s_report.bytes, &s_tag);
  logSDf("OPT: %s decode: %s", s_uid, optResultName(s_result));
  const bool decoded = s_result == OPT_OK && optMaterialAbbr(s_tag)[0];
  // Always, once per placement, while no real tag has been on the bench: the
  // first ones are read at a fair without WiFi, so the verbose switch is out
  // of reach and the dump is all there is to read back at home.
  dumpMemory(decoded ? "decoded" : optResultName(s_result));
  if (!decoded) {
    fillUidOnly();
    return OPT_SCAN_OTHER;
  }
  char line[240];
  optSummary(s_tag, line, sizeof(line));
  logSDf("OPT: %s", line);
  fillGTag(s_tag);
  return OPT_SCAN_DECODED;
}

bool optTagOnReader() {
  return tag_present && strcmp(g_tag.decoder, OPT_DECODER) == 0 && g_tag.material[0] &&
         strlen(g_tag.uid_str) == OPT_UID_STR_LEN;
}

// ---- what the tag page and the debug route show --------------------------

void optFillTagInfo(TagInfo* ti) {
  memset(ti, 0, sizeof(*ti));
  if (!optTagOnReader()) {
    snprintf(ti->fmt, sizeof(ti->fmt), "%s", s_result == OPT_OK ? "unsupported" : "unknown");
    return;
  }
  const OptTag& t = s_tag;
  snprintf(ti->fmt, sizeof(ti->fmt), "OpenPrintTag");
  snprintf(ti->brand, sizeof(ti->brand), "%s", t.brand);
  snprintf(ti->material, sizeof(ti->material), "%s", optMaterialAbbr(t));
  snprintf(ti->prod_date, sizeof(ti->prod_date), "%s", g_tag.production_date);
  if (t.gtin) snprintf(ti->sku, sizeof(ti->sku), "%llu", (unsigned long long)t.gtin);
  snprintf(ti->code, sizeof(ti->code), "%s", t.instance_id);
  optColorName(t, ti->color_name, sizeof(ti->color_name));
  if (t.color_count) {
    ti->has_color = true;
    ti->r = t.colors[0][0]; ti->g = t.colors[0][1]; ti->b = t.colors[0][2];
  }
  if (t.color_count >= 2) {
    ti->has_color2 = true;
    ti->r2 = t.colors[1][0]; ti->g2 = t.colors[1][1]; ti->b2 = t.colors[1][2];
  }
  if (t.print_min_c > 0) ti->et_lo = (uint16_t)t.print_min_c;
  if (t.print_max_c > 0) ti->et_hi = (uint16_t)t.print_max_c;
  if (t.bed_min_c > 0) ti->bed_lo = (uint16_t)t.bed_min_c;
  if (t.bed_max_c > 0) ti->bed_hi = (uint16_t)t.bed_max_c;
  if (t.diameter_mm > 0) ti->dia_x100 = (uint16_t)lroundf(t.diameter_mm * 100.0f);
  if (g_tag.length_m > 0) ti->length_m = (uint16_t)g_tag.length_m;
  if (g_tag.spool_weight > 0) ti->weight_g = (uint16_t)lroundf(g_tag.spool_weight);
  if (t.dry_c > 0) {
    ti->dry_c = (uint16_t)t.dry_c;
    ti->dry_h = (uint16_t)g_tag.dry_hours;
  }
}

// Numbers for JSON: null when not given or not a number.
static void jsonNum(char* out, size_t cap, float v) {
  if (v < 0 || !isfinite(v)) snprintf(out, cap, "null");
  else snprintf(out, cap, "%.6g", (double)v);
}

// Text from the tag goes into JSON by hand: a quote, a backslash or a control
// character would break it, so they become an apostrophe.
static void jsonSafe(char* s) {
  for (; *s; s++) {
    if (*s == '"' || *s == '\\' || (uint8_t)*s < 0x20) *s = '\'';
  }
}

void optSummaryJson(char* out, size_t cap) {
  const OptTag& t = s_tag;
  char full[16], tare[16], used[16], left[16], density[16];
  jsonNum(full, sizeof(full), optFullWeightG(t));
  jsonNum(tare, sizeof(tare), t.container_weight_g);
  jsonNum(used, sizeof(used), t.consumed_g);
  jsonNum(left, sizeof(left), optRemainingG(t));
  jsonNum(density, sizeof(density), t.density);
  char color[10] = "";
  if (t.color_count) {
    snprintf(color, sizeof(color), "#%02X%02X%02X", t.colors[0][0], t.colors[0][1], t.colors[0][2]);
  }
  char brand[OPT_TEXT_BRAND], name[OPT_TEXT_MATERIAL], abbr[OPT_TEXT_ABBR], group[OPT_TEXT_WORKGROUP];
  snprintf(brand, sizeof(brand), "%s", t.brand);
  snprintf(name, sizeof(name), "%s", t.material_name);
  snprintf(abbr, sizeof(abbr), "%s", optMaterialAbbr(t));
  snprintf(group, sizeof(group), "%s", t.workgroup);
  for (char* s : {brand, name, abbr, group}) jsonSafe(s);
  snprintf(out, cap,
           "{\"format\":\"OpenPrintTag\",\"uid\":\"%s\",\"brand\":\"%s\",\"name\":\"%s\","
           "\"material\":\"%s\",\"color\":\"%s\",\"colors\":%u,\"full_g\":%s,\"spool_g\":%s,"
           "\"consumed_g\":%s,\"remaining_g\":%s,\"density\":%s,\"diameter_mm\":%.2f,"
           "\"nozzle\":\"%d-%d\",\"bed\":\"%d-%d\",\"dry_c\":%d,\"dry_min\":%ld,"
           "\"made\":\"%s\",\"gtin\":%llu,\"tags\":%u,\"workgroup\":\"%s\"}",
           s_uid, brand, name, abbr, color, (unsigned)t.color_count, full, tare,
           used, left, density, (double)t.diameter_mm, t.print_min_c, t.print_max_c,
           t.bed_min_c, t.bed_max_c, t.dry_c, (long)t.dry_minutes, g_tag.production_date,
           (unsigned long long)t.gtin, (unsigned)t.tag_count, group);
}

void optScanJson(char* out, size_t cap) {
  if (!s_uid[0]) {
    snprintf(out, cap, "{\"uid\":null}");
    return;
  }
  char summary[TAG_INFO_JSON_MAX];
  optSummaryJson(summary, sizeof(summary));
  int used = snprintf(out, cap,
                      "{\"uid\":\"%s\",\"wire\":\"%02X%02X%02X%02X%02X%02X%02X%02X\",\"read\":{\"ok\":%s,"
                      "\"bytes\":%u,\"wanted\":%u,\"ms\":%lu,\"failed_block\":%d,\"retries\":%u},"
                      "\"decode\":\"%s\",\"tag\":%s,\"memory\":\"",
                      s_uid, s_uid_wire[0], s_uid_wire[1], s_uid_wire[2], s_uid_wire[3],
                      s_uid_wire[4], s_uid_wire[5], s_uid_wire[6], s_uid_wire[7],
                      s_read_ok ? "true" : "false", (unsigned)s_report.bytes,
                      (unsigned)s_report.wanted, (unsigned long)s_report.ms,
                      s_report.failed_block, (unsigned)s_retries_used, optResultName(s_result),
                      s_result == OPT_OK ? summary : "null");
  for (size_t i = 0; i < s_report.bytes && used > 0 && (size_t)used + 3 < cap; i++) {
    used += snprintf(out + used, cap - used, "%02X", s_mem[i]);
  }
  if (used > 0 && (size_t)used + 3 < cap) snprintf(out + used, cap - used, "\"}");
}
