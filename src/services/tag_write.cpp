#include "tag_write.h"

#include <ArduinoJson.h>
#include <ctype.h>
#include <math.h>
#include <string.h>

#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "app/app_state.h"
#include "services/backend.h"
#include "services/backend_api.h"

// ACE page map (DnG-Crafts/ACE-RFID). Pages are 4 bytes.
#define ACE_P_MAGIC     4
#define ACE_P_SKU       5
#define ACE_P_BRAND    10
#define ACE_P_MATERIAL 15
#define ACE_P_COLOR    20
#define ACE_P_EXTRUDER 24
#define ACE_P_BED      29
#define ACE_P_DIALEN   30
#define ACE_P_WEIGHT   31

struct AceFields {
  char     sku[17];
  char     brand[17];
  char     material[17];
  uint8_t  r, g, b;
  uint16_t et_lo, et_hi, bed_lo, bed_hi;
  uint16_t dia_x100, length_m, weight_g;
};

static bool      pending = false;
static int       pending_id = 0;
static TagFormat pending_fmt = TAG_FMT_ACE;
static bool      pending_link = false;
static char      state[12] = "idle";
static char      message[96] = "";

static char      cached_uid[26] = "";
static char      cached_kind[34] = "";
static char      cached_content[128] = "";
static TagInfo   cached_info;
static bool      cache_dirty = false;

const char* tagCachedUid()     { return cached_uid; }
const char* tagCachedKind()    { return cached_kind; }
const char* tagCachedContent() { return cached_content; }
const TagInfo* tagCachedInfo() { return &cached_info; }

const char* tagWriteState()   { return state; }
const char* tagWriteMessage() { return message; }

static void finish(const char *st, const char *msg) {
  snprintf(state, sizeof(state), "%s", st);
  snprintf(message, sizeof(message), "%s", msg);
  logSDf("TagWrite: %s - %s", st, msg);
}

bool tagWriteRequest(int spool_id, TagFormat fmt, bool link) {
  if (pending || spool_id <= 0) return false;
  pending_id   = spool_id;
  pending_fmt  = fmt;
  pending_link = link;
  pending     = true;
  snprintf(state, sizeof(state), "pending");
  snprintf(message, sizeof(message), "Writing spool %d...", spool_id);
  return true;
}

static void materialFamily(const char *in, char *out, size_t out_len) {
  char up[40] = {0};
  for (size_t i = 0; i < sizeof(up) - 1 && in[i]; i++) up[i] = toupper((unsigned char)in[i]);
  const char *fam = "PLA";
  if      (strstr(up, "PETG")) fam = "PETG";
  else if (strstr(up, "ABS"))  fam = "ABS";
  else if (strstr(up, "ASA"))  fam = "ASA";
  else if (strstr(up, "TPU"))  fam = "TPU";
  else if (strstr(up, "PLA+")) fam = "PLA+";
  else if (strstr(up, "PC"))   fam = "PC";
  else if (strstr(up, "PLA"))  fam = "PLA";
  snprintf(out, out_len, "%s", fam);
}

// Neither backend stores print temperatures, so they come from the family.
static void defaultsFor(const char *fam, AceFields *f, float *density) {
  if      (!strcmp(fam, "PETG")) { f->et_lo=230; f->et_hi=250; f->bed_lo=70; f->bed_hi=80;  *density=1.27f; }
  else if (!strcmp(fam, "ABS"))  { f->et_lo=240; f->et_hi=260; f->bed_lo=90; f->bed_hi=100; *density=1.04f; }
  else if (!strcmp(fam, "ASA"))  { f->et_lo=240; f->et_hi=260; f->bed_lo=90; f->bed_hi=100; *density=1.07f; }
  else if (!strcmp(fam, "TPU"))  { f->et_lo=210; f->et_hi=230; f->bed_lo=40; f->bed_hi=50;  *density=1.21f; }
  else if (!strcmp(fam, "PC"))   { f->et_lo=260; f->et_hi=280; f->bed_lo=90; f->bed_hi=110; *density=1.20f; }
  else                           { f->et_lo=200; f->et_hi=220; f->bed_lo=50; f->bed_hi=60;  *density=1.24f; }
}

static void buildAce(JsonObjectConst sp, AceFields *f) {
  memset(f, 0, sizeof(*f));
  const char *material = sp["filament"]["material"] | "PLA";
  materialFamily(material[0] ? material : "PLA", f->material, sizeof(f->material));

  float density = 1.24f;
  defaultsFor(f->material, f, &density);

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

static void aceToInfo(const AceFields *f, TagInfo *ti) {
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

void tagInfoJson(const TagInfo *ti, char *out, size_t out_len) {
  int n = snprintf(out, out_len, "{\"fmt\":\"%s\"", ti->fmt);
  if (ti->brand[0])    n += snprintf(out + n, out_len - n, ",\"brand\":\"%s\"", ti->brand);
  if (ti->material[0]) n += snprintf(out + n, out_len - n, ",\"material\":\"%s\"", ti->material);
  if (ti->sku[0])      n += snprintf(out + n, out_len - n, ",\"sku\":\"%s\"", ti->sku);
  if (ti->has_color)   n += snprintf(out + n, out_len - n, ",\"color\":\"#%02X%02X%02X\"",
                                     ti->r, ti->g, ti->b);
  if (ti->et_hi)       n += snprintf(out + n, out_len - n, ",\"nozzle\":\"%u-%u\"",
                                     (unsigned)ti->et_lo, (unsigned)ti->et_hi);
  if (ti->bed_hi)      n += snprintf(out + n, out_len - n, ",\"bed\":\"%u-%u\"",
                                     (unsigned)ti->bed_lo, (unsigned)ti->bed_hi);
  if (ti->weight_g)    n += snprintf(out + n, out_len - n, ",\"weight\":%u", (unsigned)ti->weight_g);
  if (ti->dia_x100)    n += snprintf(out + n, out_len - n, ",\"dia\":\"%u.%02u\"",
                                     (unsigned)(ti->dia_x100 / 100), (unsigned)(ti->dia_x100 % 100));
  if (ti->length_m)    n += snprintf(out + n, out_len - n, ",\"len\":%u", (unsigned)ti->length_m);
  snprintf(out + n, out_len - n, "}");
}

// One format for both sides, so the page can compare them as plain strings.
static void describeAce(const AceFields *f, char *out, size_t out_len) {
  snprintf(out, out_len, "ACE: %s %s, #%02X%02X%02X, %ug, SKU %s",
           f->brand, f->material, f->r, f->g, f->b,
           (unsigned)f->weight_g, f->sku);
}

static bool wrPage(uint8_t page, const uint8_t *d) {
  if (page < 4) return false;          // UID, lock bytes, CC
  uint8_t buf[4];
  memcpy(buf, d, 4);
  return nfcWriteNtagPage(page, buf);
}

// Capability container at page 3: byte 2 counts 8 byte blocks of user
// memory. NTAG213 = 144, NTAG215 = 504, NTAG216 = 888.
static uint16_t tagUserBytes() {
  uint8_t cc[4] = {0};
  if (!nfcReadNtagPage(3, cc) || cc[0] != 0xE1 || !cc[2]) return 0;
  return (uint16_t)cc[2] * 8;
}

// Falls back to the smallest tag, so an unreadable CC never overruns.
static uint8_t lastUserPage() {
  const uint16_t b = tagUserBytes();
  return b ? (uint8_t)(4 + b / 4 - 1) : 39;
}

static bool wrText(uint8_t first, const char *s) {
  uint8_t buf[16] = {0};
  size_t n = strlen(s);
  if (n > 16) n = 16;
  memcpy(buf, s, n);
  for (int i = 0; i < 4; i++) if (!wrPage(first + i, buf + i * 4)) return false;
  // Fields are 16 bytes with a spare page after them. A full length value has
  // no NUL of its own, so old data left in that page would run the two
  // together on read.
  const uint8_t zero[4] = {0, 0, 0, 0};
  return wrPage(first + 4, zero);
}

static bool wrU16Pair(uint8_t page, uint16_t a, uint16_t b) {
  uint8_t buf[4] = { (uint8_t)(a & 0xFF), (uint8_t)(a >> 8),
                     (uint8_t)(b & 0xFF), (uint8_t)(b >> 8) };
  return wrPage(page, buf);
}

// Clears the user pages, whatever the tag has. A fixed upper page would
// overrun an NTAG213 and report a failed erase after erasing everything.
static bool eraseTag() {
  const uint8_t zero[4] = {0, 0, 0, 0};
  const uint8_t last = lastUserPage();
  for (uint8_t pg = 4; pg <= last; pg++)
    if (!wrPage(pg, zero)) return false;
  return true;
}

static bool writeAce(const AceFields *f) {
  const uint8_t magic[4] = { 0x7B, 0x00, 0x65, 0x00 };
  const uint8_t color[4] = { 0xFF, f->b, f->g, f->r };
  return wrPage(ACE_P_MAGIC, magic)
      && wrText(ACE_P_SKU, f->sku)
      && wrText(ACE_P_BRAND, f->brand)
      && wrText(ACE_P_MATERIAL, f->material)
      && wrPage(ACE_P_COLOR, color)
      && wrU16Pair(ACE_P_EXTRUDER, f->et_lo, f->et_hi)
      && wrU16Pair(ACE_P_BED, f->bed_lo, f->bed_hi)
      && wrU16Pair(ACE_P_DIALEN, f->dia_x100, f->length_m)
      && wrU16Pair(ACE_P_WEIGHT, f->weight_g, 0);
}


// NDEF on an NTAG: TLV 0x03, length, one application/json record, 0xFE.
// Record header D2 = MB|ME|SR, TNF 2 (media type).
static char write_err[80] = "";

static bool writeOpenSpool(const AceFields *f, int spool_id) {
  char json[224];
  int n = snprintf(json, sizeof(json),
    "{\"protocol\":\"openspool\",\"version\":\"1.0\",\"type\":\"%s\","
    "\"color_hex\":\"%02X%02X%02X\",\"brand\":\"%s\","
    "\"min_temp\":\"%u\",\"max_temp\":\"%u\",\"sm_id\":%d}",
    f->material, f->r, f->g, f->b, f->brand,
    (unsigned)f->et_lo, (unsigned)f->et_hi, spool_id);
  if (n <= 0 || n >= (int)sizeof(json)) return false;

  static const char TYPE[] = "application/json";
  const uint8_t tlen = sizeof(TYPE) - 1;

  uint8_t buf[288];
  int i = 0;
  buf[i++] = 0x03;                       // NDEF message TLV
  buf[i++] = (uint8_t)(3 + tlen + n);    // record header + type + payload
  buf[i++] = 0xD2;
  buf[i++] = tlen;
  buf[i++] = (uint8_t)n;
  memcpy(buf + i, TYPE, tlen); i += tlen;
  memcpy(buf + i, json, n);    i += n;
  buf[i++] = 0xFE;                       // terminator
  while (i % 4) buf[i++] = 0x00;

  const uint8_t need_last = (uint8_t)(4 + (i + 3) / 4 - 1);
  const uint8_t last = lastUserPage();
  if (need_last > last) {
    snprintf(write_err, sizeof(write_err),
             "OpenSpool needs %d bytes, this tag holds %u", i,
             (unsigned)((last - 3) * 4));
    return false;
  }

  for (int off = 0; off < i; off += 4)
    if (!wrPage((uint8_t)(4 + off / 4), buf + off)) return false;
  return true;
}

// Reads the JSON payload back out of the NDEF wrapper.
static bool readOpenSpool(char *out, size_t out_len) {
  uint8_t buf[240];
  if (!nfcReadNtagPage(4, buf)) return false;
  if (buf[0] != 0x03) return false;          // not an NDEF TLV, stop here
  int len = buf[1];
  const int need = 2 + len;
  const int pages = (need + 3) / 4;
  if (pages > (int)sizeof(buf) / 4) return false;
  for (int p2 = 1; p2 < pages; p2++)
    if (!nfcReadNtagPage((uint8_t)(4 + p2), buf + p2 * 4)) return false;
  if (len < 5 || 2 + len > (int)sizeof(buf)) return false;
  int tlen = buf[3];
  int plen = buf[4];
  int start = 5 + tlen;
  if (plen <= 0 || start + plen > (int)sizeof(buf)) return false;
  size_t copy = (size_t)plen < out_len - 1 ? (size_t)plen : out_len - 1;
  memcpy(out, buf + start, copy);
  out[copy] = 0;
  return strstr(out, "openspool") != nullptr;
}

static void describeOpenSpool(const char *json, char *out, size_t out_len, TagInfo *ti) {
  if (ti) { memset(ti, 0, sizeof(*ti)); snprintf(ti->fmt, sizeof(ti->fmt), "OpenSpool"); }
  JsonDocument d;
  if (deserializeJson(d, json)) { snprintf(out, out_len, "OpenSpool: unreadable"); return; }
  snprintf(out, out_len, "OpenSpool: %s %s, #%s, %s-%sC",
           d["brand"] | "?", d["type"] | "?", d["color_hex"] | "?",
           d["min_temp"] | "?", d["max_temp"] | "?");
  if (!ti) return;
  snprintf(ti->brand, sizeof(ti->brand), "%s", d["brand"] | "");
  snprintf(ti->material, sizeof(ti->material), "%s", d["type"] | "");
  const char *hex = d["color_hex"] | "";
  if (*hex == '#') hex++;
  unsigned r = 0, g = 0, b = 0;
  if (strlen(hex) >= 6 && sscanf(hex, "%02x%02x%02x", &r, &g, &b) == 3) {
    ti->has_color = true;
    ti->r = (uint8_t)r; ti->g = (uint8_t)g; ti->b = (uint8_t)b;
  }
  ti->et_lo = (uint16_t)(d["min_temp"] | 0);
  ti->et_hi = (uint16_t)(d["max_temp"] | 0);
}

static void readText(uint8_t first, char *out, size_t out_len) {
  uint8_t buf[16] = {0};
  for (int i = 0; i < 4; i++)
    if (!nfcReadNtagPage(first + i, buf + i * 4)) { out[0] = 0; return; }
  size_t j = 0;
  for (size_t i = 0; i < 16 && j < out_len - 1; i++) {
    char c = (char)buf[i];
    if (c < 0x20 || c > 0x7E) break;
    out[j++] = c;
  }
  out[j] = 0;
}

static uint16_t rdU16(const uint8_t *d) { return (uint16_t)(d[0] | (d[1] << 8)); }

// false when a page read came back short: the caller must not cache that.
static bool tagDescribe(char *out, size_t out_len, TagInfo *ti) {
  out[0] = 0;
  if (ti) memset(ti, 0, sizeof(*ti));
  uint8_t p4[4] = {0};
  if (!nfcReadNtagPage(4, p4)) return false;

  if (p4[0] == 0x7B && p4[1] == 0x00 && p4[2] == 0x65 && p4[3] == 0x00) {
    AceFields f;
    memset(&f, 0, sizeof(f));
    readText(ACE_P_SKU, f.sku, sizeof(f.sku));
    readText(ACE_P_BRAND, f.brand, sizeof(f.brand));
    readText(ACE_P_MATERIAL, f.material, sizeof(f.material));
    uint8_t col[4] = {0}, wt[4] = {0}, ext[4] = {0}, bed[4] = {0}, dl[4] = {0};
    nfcReadNtagPage(ACE_P_COLOR, col);
    nfcReadNtagPage(ACE_P_WEIGHT, wt);
    nfcReadNtagPage(ACE_P_EXTRUDER, ext);
    nfcReadNtagPage(ACE_P_BED, bed);
    nfcReadNtagPage(ACE_P_DIALEN, dl);
    f.r = col[3]; f.g = col[2]; f.b = col[1];
    f.weight_g = rdU16(wt);
    f.et_lo = rdU16(ext);     f.et_hi = rdU16(ext + 2);
    f.bed_lo = rdU16(bed);    f.bed_hi = rdU16(bed + 2);
    f.dia_x100 = rdU16(dl);   f.length_m = rdU16(dl + 2);
    describeAce(&f, out, out_len);
    if (ti) aceToInfo(&f, ti);
    return f.material[0] && f.brand[0];
  }

  char json[224];
  if (readOpenSpool(json, sizeof(json))) {
    describeOpenSpool(json, out, out_len, ti);
    return true;
  }

  bool blank = true;
  for (int pg = 5; pg <= 8 && blank; pg++) {
    uint8_t d[4] = {0};
    if (!nfcReadNtagPage(pg, d)) break;
    for (int i = 0; i < 4; i++) if (d[i]) { blank = false; break; }
  }
  snprintf(out, out_len, "%s", blank ? "blank" : "unrecognised data");
  if (ti) snprintf(ti->fmt, sizeof(ti->fmt), "%s", blank ? "blank" : "unknown");
  return true;
}

bool tagPreview(int spool_id, TagFormat fmt, char *out, size_t out_len,
                char *linked, size_t linked_len, TagInfo *info) {
  out[0] = 0;
  linked[0] = 0;
  if (info) memset(info, 0, sizeof(*info));
  if (spool_id <= 0) return false;

  JsonDocument doc;
  if (backendGetSpoolJson(backendBaseUrl(), spool_id, doc) != 200 || doc.isNull())
    return false;
  JsonObjectConst sp = doc.as<JsonObjectConst>();

  const char *tag = sp["extra"]["tag"] | "";
  snprintf(linked, linked_len, "%s", tag);

  if (fmt == TAG_FMT_ERASE) {
    snprintf(out, out_len, "blank");
    if (info) snprintf(info->fmt, sizeof(info->fmt), "blank");
    return true;
  }
  AceFields f;
  buildAce(sp, &f);
  if (info) {
    aceToInfo(&f, info);
    if (fmt == TAG_FMT_OPENSPOOL) {
      // OpenSpool carries neither the SKU nor the spool geometry.
      snprintf(info->fmt, sizeof(info->fmt), "OpenSpool");
      info->sku[0] = 0;
      info->bed_lo = info->bed_hi = 0;
      info->dia_x100 = info->length_m = info->weight_g = 0;
    }
  }
  if (fmt == TAG_FMT_OPENSPOOL) {
    snprintf(out, out_len, "OpenSpool: %s %s, #%02X%02X%02X, %u-%uC",
             f.brand, f.material, f.r, f.g, f.b,
             (unsigned)f.et_lo, (unsigned)f.et_hi);
    return true;
  }
  describeAce(&f, out, out_len);
  return true;
}

// Uses what the main NFC poll already found. Selecting the tag again here
// would compete with that poll, and the loser gets nothing back.
static void refreshCache() {
  static unsigned long last_ms = 0;
  static char last_uid[26] = "";

  if (!tag_present) {
    cached_uid[0] = 0; cached_kind[0] = 0; cached_content[0] = 0;
    memset(&cached_info, 0, sizeof(cached_info));
    last_uid[0] = 0;
    return;
  }

  const bool is_ntag = strlen(g_tag.uid_str) > 14;   // 7 bytes reads as 20 chars
  snprintf(cached_uid, sizeof(cached_uid), "%s", g_tag.uid_str);

  if (!is_ntag) {
    snprintf(cached_kind, sizeof(cached_kind), "MIFARE Classic, read-only");
    cached_content[0] = 0;
    memset(&cached_info, 0, sizeof(cached_info));
    return;
  }

  const bool changed = strcmp(last_uid, g_tag.uid_str) != 0 || cache_dirty;
  if (!changed && cached_content[0]) return;
  if (millis() - last_ms < 500) return;      // retry gap after a failed read
  last_ms = millis();
  if (changed) snprintf(last_uid, sizeof(last_uid), "%s", g_tag.uid_str);

  const uint16_t bytes = tagUserBytes();
  if (bytes) snprintf(cached_kind, sizeof(cached_kind), "NTAG, writable, %u bytes",
                      (unsigned)bytes);
  else       snprintf(cached_kind, sizeof(cached_kind), "NTAG, writable");

  // A page read that loses the reader returns a short or empty result, so keep
  // the last good description rather than blanking the page.
  char tmp[128];
  TagInfo ti;
  if (tagDescribe(tmp, sizeof(tmp), &ti) && tmp[0]) {
    snprintf(cached_content, sizeof(cached_content), "%s", tmp);
    cached_info = ti;
    cache_dirty = false;
  }
}

void tagWriteTick() {
  refreshCache();
  if (!pending) return;
  pending = false;

  uint8_t uid[8], uid_len = 0;
  if (!nfcReadPassiveTarget(uid, &uid_len, 600)) {
    finish("error", "No tag on the reader");
    return;
  }
  if (uid_len != 7) {
    finish("error", "Not a writable NTAG, this tag can only be read");
    return;
  }

  // Not querySpoolmanById(): that also repaints the main screen and would
  // change which spool the scale believes is loaded.
  JsonDocument doc;
  int code = backendGetSpoolJson(backendBaseUrl(), pending_id, doc);
  if (code != 200 || doc.isNull()) {
    char m[96];
    snprintf(m, sizeof(m), "Spool %d not found on %s (HTTP %d)",
             pending_id, backendName(), code);
    finish("error", m);
    return;
  }
  JsonObjectConst sp = doc.as<JsonObjectConst>();

  bool ok;
  write_err[0] = 0;
  if (pending_fmt == TAG_FMT_ERASE) {
    ok = eraseTag();
  } else {
    AceFields f;
    buildAce(sp, &f);
    ok = (pending_fmt == TAG_FMT_ACE) ? writeAce(&f)
                                      : writeOpenSpool(&f, pending_id);
  }

  cache_dirty = true;   // the tag changed under a UID that did not

  if (!ok) {
    finish("error", write_err[0] ? write_err
                                 : "Write failed - keep the tag still on the reader");
    return;
  }
  const char *name = sp["filament"]["name"] | "spool";
  char m[128];
  int n;
  if (pending_fmt == TAG_FMT_ERASE) {
    n = snprintf(m, sizeof(m), "Tag erased");
  } else {
    n = snprintf(m, sizeof(m), "Wrote spool %d (%s) as %s", pending_id,
                 name[0] ? name : "spool",
                 pending_fmt == TAG_FMT_ACE ? "ACE" : "OpenSpool");
  }

  if (pending_link) {
    char uid_str[26];
    int u = 0;
    for (int i = 0; i < uid_len && u < (int)sizeof(uid_str) - 3; i++)
      u += snprintf(uid_str + u, sizeof(uid_str) - u, i ? ":%02X" : "%02X", uid[i]);
    char note[48];
    int code2 = backendLinkSpoolTag(backendBaseUrl(), pending_id, uid_str,
                                    note, sizeof(note));
    if (code2 == 200)
      snprintf(m + n, sizeof(m) - n, note[0] ? ", linked (%s)" : ", linked to the spool", note);
    else
      snprintf(m + n, sizeof(m) - n, ", but linking failed (HTTP %d)", code2);
  }
  finish("ok", m);
}
