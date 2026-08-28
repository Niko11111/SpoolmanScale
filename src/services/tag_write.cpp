#include "tag_write.h"

#include <ArduinoJson.h>
#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <string.h>

#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "app/app_state.h"
#include "bambu/bambu_tag.h"
#include "bambu/material_match.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/filaman_api.h"
#include "services/tag_field.h"
#include "services/tag_uid.h"
#include "services/backend.h"

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
// Everything from the first user page through the last one ACE touches.
#define ACE_BYTES      ((ACE_P_WEIGHT - 4 + 1) * 4)

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
static uint8_t   result = TW_NONE;
static int       linked_spool = 0;
// The same answer as `message`, in parts, so a translated caller can build its
// own sentence - see TagWriteReport in the header.
static TagWriteReport report;

static char      cached_uid[26] = "";
static char      cached_kind[34] = "";
// The same statement as a number, because cached_kind is English prose and the
// web page is translated. 0 nothing, 1 MIFARE Classic read-only, 2 NTAG.
static uint8_t   cached_kindcode = TAG_KIND_NONE;
static char      cached_content[128] = "";
static TagInfo   cached_info;
static uint16_t  cached_bytes = 0;
static bool      cache_dirty = false;
static bool      scan_pending = false;
static unsigned long scan_since = 0;
#define SCAN_WAIT_MS 30000

const char* tagCachedUid()     { return cached_uid; }
const char* tagCachedKind()    { return cached_kind; }
const char* tagCachedContent() { return cached_content; }
const TagInfo* tagCachedInfo() { return &cached_info; }
uint16_t tagCachedBytes()      { return cached_bytes; }
uint8_t  tagCachedKindCode()   { return cached_kindcode; }

// "blank" and "unknown" are answers, not records: one says the pages are
// empty, the other that they hold something no format claims. Neither has a
// brand or a material to show, and both are asked about in three places.
bool tagCachedHasRecord() {
  return cached_info.fmt[0] && strcmp(cached_info.fmt, "blank") != 0 &&
         strcmp(cached_info.fmt, "unknown") != 0;
}
void tagScanRequest() { scan_pending = true; scan_since = millis(); }

const TagWriteReport* tagWriteReportData() { return &report; }

const char* tagWriteState()   { return state; }
const char* tagWriteMessage() { return message; }
uint8_t     tagWriteResultCode() { return result; }

int tagWriteTakeLinkedSpool() {
  const int id = linked_spool;
  linked_spool = 0;
  return id;
}

// The tag the main poll is looking at, judged the same way refreshCache()
// judges it: a 7 byte UID prints as 20 characters, a 4 byte one as 11. Reading
// the cached scan rather than selecting the tag again is the point - a select
// here would race the main poll, and the loser gets nothing back.
bool tagIsWritableNtag() {
  return tag_present && strlen(g_tag.uid_str) > 14;
}

static void finish(const char *st, const char *msg, uint8_t code) {
  snprintf(state, sizeof(state), "%s", st);
  snprintf(message, sizeof(message), "%s", msg);
  result = code;
  report.code = code;
  logSDf("TagWrite: %s - %s", st, msg);
}

bool tagWriteRequest(int spool_id, TagFormat fmt, bool link) {
  if (pending) return false;
  if (fmt != TAG_FMT_ERASE && spool_id <= 0) return false;
  pending_id   = spool_id;
  pending_fmt  = fmt;
  pending_link = link;
  pending     = true;
  result      = TW_BUSY;
  memset(&report, 0, sizeof(report));
  report.code     = TW_BUSY;
  report.erase    = (fmt == TAG_FMT_ERASE);
  report.spool_id = spool_id;
  report.fmt      = (uint8_t)fmt;
  snprintf(state, sizeof(state), "pending");
  if (fmt == TAG_FMT_ERASE)
    snprintf(message, sizeof(message), "Erasing the tag...");
  else
    snprintf(message, sizeof(message), "Writing spool %d...", spool_id);
  return true;
}

// Neither backend stores print temperatures, so they come from the family the
// material name starts with. Density is only used to estimate the length.
//
// Longer names first where one is a prefix of another: PLA+ before PLA, PETG
// before nothing else that starts with PET.
struct MatFamily {
  const char* name;
  uint16_t    et_lo, et_hi, bed_lo, bed_hi;
  float       density;
};
static const MatFamily MAT_FAMILIES[] = {
  { "PETG", 230, 250, 70,  80,  1.27f },
  { "PLA+", 200, 220, 50,  60,  1.24f },
  { "PLA",  200, 220, 50,  60,  1.24f },
  { "ABS",  240, 260, 90, 100,  1.04f },
  { "ASA",  240, 260, 90, 100,  1.07f },
  { "TPU",  210, 230, 40,  50,  1.21f },
  { "TPE",  210, 230, 40,  50,  1.21f },
  { "HIPS", 230, 245, 90, 110,  1.04f },
  { "PVA",  190, 210, 50,  60,  1.23f },
  { "PC",   260, 280, 90, 110,  1.20f },
  { "PA",   250, 270, 60,  80,  1.14f },
  { "PP",   220, 240, 60,  80,  0.90f },
};
#define MAT_DENSITY_FALLBACK  1.24f

// The family a material name begins with, or null when none of them fits.
//
// A prefix, and it has to end at a boundary: "PC-CF" is PC, "PCTG" is not - it
// is a copolyester that would print 60 degrees too hot on PC settings. This is
// also why an unmatched name gets no temperatures at all rather than PLA's:
// before this, every material outside the list was written to the tag as "PLA"
// at 200-220 C, which is what a TPE spool on this scale did.
static const MatFamily* matchFamily(const char *in) {
  if (!in || !in[0]) return nullptr;
  char up[40] = {0};
  for (size_t i = 0; i < sizeof(up) - 1 && in[i]; i++)
    up[i] = toupper((unsigned char)in[i]);

  for (unsigned i = 0; i < sizeof(MAT_FAMILIES) / sizeof(MAT_FAMILIES[0]); i++) {
    const char* fam = MAT_FAMILIES[i].name;
    const size_t n = strlen(fam);
    if (strncmp(up, fam, n) != 0) continue;
    const char c = up[n];
    // End of the name, or a separator - never another letter.
    if (c == '\0' || c == '-' || c == '+' || c == ' ' || c == '_' ||
        (c >= '0' && c <= '9'))
      return &MAT_FAMILIES[i];
  }
  return nullptr;
}


static void buildAce(JsonObjectConst sp, AceFields *f) {
  memset(f, 0, sizeof(*f));
  // The spool's own material name goes on the tag, not the family it belongs
  // to. Writing the family made a TPE-83A spool arrive as "PLA", and a reader
  // has no way of telling that apart from a spool that really is PLA.
  const char *material = sp["filament"]["material"] | "PLA";
  if (!material[0]) material = "PLA";
  snprintf(f->material, sizeof(f->material), "%s", material);

  float density = MAT_DENSITY_FALLBACK;
  const MatFamily* fam = matchFamily(material);
  if (fam) {
    f->et_lo = fam->et_lo; f->et_hi = fam->et_hi;
    f->bed_lo = fam->bed_lo; f->bed_hi = fam->bed_hi;
    density = fam->density;
  } else {
    // Zero, and the preview shows a dash. A reader can ignore a missing
    // temperature; a wrong one it cannot.
    logSDf("tag: material '%s' is in no known family, no temperatures written",
           material);
  }

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

// snprintf returns the length it *would* have written, so adding that up walks
// the cursor past the end of the buffer the moment anything is truncated:
// out + n then points outside it and out_len - n underflows to a huge size_t.
// This returns what was actually written instead.
//
// The buffers callers pass are big enough for real field sizes, so this was
// latent rather than live - but it is ten appends in a row in tagInfoJson()
// and the same shape again in scanTick(), and the data comes off a tag.
static size_t appendf(char *out, size_t out_len, size_t n, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static size_t appendf(char *out, size_t out_len, size_t n, const char *fmt, ...) {
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
  appendf(out, out_len, n, "}");
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

// Capability container at page 3: byte 2 counts 8 byte blocks. What it reports
// is the NDEF area, which is a little smaller than the chip: NTAG213 144 of
// 144, NTAG215 496 of 504, NTAG216 872 of 888. Those are the numbers the UI
// shows, because they are what a record actually has to fit into.
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
//
// The single byte TLV length field is what caps the payload, not the tag: past
// 255 total the TLV would need its three byte form, which nothing here writes.
#define NDEF_JSON_MAX 250

// TLV tag and length, record header with type and payload length, the media
// type itself, the payload, the terminator - then rounded up to whole 4 byte
// pages, because that is the unit a write goes in.
size_t tagNdefSizeFor(size_t json_len) {
  const size_t n = 2 + 3 + 16 + json_len + 1;
  return n + ((4 - (n % 4)) % 4);
}

static char    write_err[80] = "";
static uint8_t write_code = TW_ERR_WRITE;
static char    remote_payload[320] = "";
static char    remote_proto[12] = "";

// Wraps a JSON document in the NDEF TLV an OpenSpool reader expects.
static bool writeNdefJson(const char *json) {
  const int n = (int)strlen(json);
  if (n <= 0 || n > NDEF_JSON_MAX) return false;

  static const char TYPE[] = "application/json";
  const uint8_t tlen = sizeof(TYPE) - 1;

  // Settled before a single byte is laid out: the same arithmetic the preview
  // uses, so a tag the page called too small is exactly the one that fails here.
  const int i_need = (int)tagNdefSizeFor((size_t)n);
  {
    const uint8_t need_last = (uint8_t)(4 + (i_need + 3) / 4 - 1);
    const uint8_t last = lastUserPage();
    if (need_last > last) {
      // Two different faults used to read as one. A tag whose capability
      // container is blank reports no size at all, and lastUserPage() then
      // assumes the smallest NTAG - so an NTAG215 with 496 bytes free was
      // turned away claiming it held 144, which sends the owner looking for a
      // bigger tag instead of formatting the one in their hand.
      if (!tagUserBytes())
        snprintf(write_err, sizeof(write_err),
                 "Tag reports no size. Format it as NDEF once, then retry");
      else
        snprintf(write_err, sizeof(write_err),
                 "OpenSpool needs %d bytes, this tag holds %u", i_need,
                 (unsigned)((last - 3) * 4));
      write_code = TW_ERR_SPACE;
      return false;
    }
  }

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

  for (int off = 0; off < i; off += 4)
    if (!wrPage((uint8_t)(4 + off / 4), buf + off)) return false;
  return true;
}

// Two names for the same number, because two readers look for two different
// keys. sm_id is the OpenSpool convention this firmware has always written and
// what OpenSpoolman resolves. spool_id is what FilaMan's own reader looks for -
// the word sm_id does not appear anywhere in FilaMan, and a record carrying
// only that one arrives there as spool 0. Neither replaces the other.
// What the format is called where a person reads it.
static const char* fmtLabel(TagFormat fmt) {
  switch (fmt) {
    case TAG_FMT_ACE:     return "ACE";
    case TAG_FMT_FILAMAN: return "FilaMan";
    default:              return "OpenSpool";
  }
}

static const char* protoName(TagFormat fmt) {
  return fmt == TAG_FMT_FILAMAN ? "filaman" : "openspool";
}

const char* tagFormatLabel(uint8_t fmt) {
  switch (fmt) {
    case TAG_FMT_ACE:       return "Anycubic ACE";
    case TAG_FMT_FILAMAN:   return "FilaMan";
    case TAG_FMT_ERASE:     return "erase";
    default:                return "OpenSpool";
  }
}

static int buildOpenSpoolJson(const AceFields *f, int spool_id, TagFormat fmt,
                              char *json, size_t json_len) {
  int n = snprintf(json, json_len,
    "{\"protocol\":\"%s\",\"version\":\"1.0\",\"type\":\"%s\","
    "\"color_hex\":\"%02X%02X%02X\",\"brand\":\"%s\","
    "\"min_temp\":\"%u\",\"max_temp\":\"%u\","
    "\"spool_id\":%d,\"sm_id\":%d}",
    protoName(fmt), f->material, f->r, f->g, f->b, f->brand,
    (unsigned)f->et_lo, (unsigned)f->et_hi, spool_id, spool_id);
  return (n > 0 && n < (int)json_len) ? n : 0;
}

static bool writeOpenSpool(const AceFields *f, int spool_id, TagFormat fmt) {
  char json[224];
  if (!buildOpenSpoolJson(f, spool_id, fmt, json, sizeof(json))) return false;
  return writeNdefJson(json);
}

// What the server sent is kept exactly as it sent it - spool_id included. An
// earlier version swapped that key for sm_id on the way through, on the theory
// that sm_id was the one a reader needs. It is not: sm_id is this firmware's
// own convention, FilaMan looks for spool_id, and a record with only sm_id
// reaches FilaMan as spool 0. The one thing added here is sm_id when it is
// missing, so the same tag also answers to an OpenSpool reader.
void tagRemotePayloadSet(const char *json, int spool_id) {
  remote_payload[0] = 0;
  remote_proto[0] = 0;
  if (!json || !json[0]) return;

  JsonDocument d;
  if (deserializeJson(d, json)) {
    logSD("RemoteLink: tag payload is not JSON, ignoring it");
    return;
  }
  if (d["sm_id"].isNull() && spool_id > 0) d["sm_id"] = spool_id;

  const size_t n = measureJson(d);
  // Turned away here rather than at write time, because that is what lets the
  // caller fall back to the record the scale builds for itself.
  if (n == 0 || n > NDEF_JSON_MAX || n >= sizeof(remote_payload)) {
    logSDf("RemoteLink: tag payload is %u bytes, too long for a tag",
           (unsigned)n);
    return;
  }
  serializeJson(d, remote_payload, sizeof(remote_payload));

  // Kept for the question on the screen. FilaMan writes the name lowercase;
  // shown to a user it should read the way the two projects spell themselves.
  const char *proto = d["protocol"] | "";
  snprintf(remote_proto, sizeof(remote_proto), "%s",
           strcmp(proto, "filaman") == 0 ? "FilaMan" : "OpenSpool");
}

const char* tagRemotePayloadProtocol() {
  return remote_proto[0] ? remote_proto : "OpenSpool";
}

bool tagRemotePayloadPending() { return remote_payload[0] != 0; }

// Runs from the deferred handler, never from an LVGL callback: this talks to
// the reader and takes as long as a write takes.
//
// Reports through the same state the web page polls. A remote write used to
// leave no trace there at all, so the tag page showed the result of whatever
// had been written before it.
bool tagWriteRemotePayload() {
  if (!remote_payload[0]) return false;
  write_err[0] = 0;
  write_code = TW_ERR_WRITE;

  uint8_t uid[8], uid_len = 0;
  bool ok = false;
  if (!nfcReadPassiveTarget(uid, &uid_len, 600)) {
    finish("error", "No tag on the reader", TW_ERR_NO_TAG);
  } else if (uid_len != 7) {
    finish("error", "Not a writable NTAG, this tag can only be read",
           TW_ERR_NOT_NTAG);
  } else if (!writeNdefJson(remote_payload)) {
    finish("error", write_err[0] ? write_err
                                 : "Write failed - keep the tag still on the reader",
           write_code);
  } else {
    finish("ok", "Wrote the record the filament manager sent", TW_OK);
    ok = true;
  }

  remote_payload[0] = 0;
  remote_proto[0] = 0;
  cache_dirty = true;
  return ok;
}

// FilaMan can be set to write the record under either of two protocol names,
// and both hold the same fields - the choice is a label. Reading the value out
// rather than looking for the bare word anywhere in the record is what keeps a
// filament brand called Filaman from being taken for a protocol.
static bool isSupportedRecord(const char *json) {
  JsonDocument d;
  if (deserializeJson(d, json)) return false;
  const char *proto = d["protocol"] | "";
  return !strcmp(proto, "openspool") || !strcmp(proto, "filaman");
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
  return isSupportedRecord(out);
}

// OpenSpool carries the temperatures as JSON strings - "min_temp":"200" - and
// that is what this firmware, FilaMan and the OpenSpool tools all write. Read
// with `| 0` ArduinoJson answers 0 for a string, which is why the preview said
// "Duese -" next to a tag that plainly carried 200-220 C. Takes either shape.
static uint16_t jsonTemp(JsonVariantConst v) {
  if (v.is<unsigned>() || v.is<int>() || v.is<float>()) return (uint16_t)(v | 0);
  const char* s = v | "";
  return s[0] ? (uint16_t)atoi(s) : 0;
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
  ti->et_lo = jsonTemp(d["min_temp"]);
  ti->et_hi = jsonTemp(d["max_temp"]);
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
    bool bound_here = false;

    for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT && !bound_here; i++) {
      const char* raw = extra[tagFieldSpec(i).key] | "";
      if (raw[0] && here[0] && cardUidsContain(raw, here)) bound_here = true;
    }
    if (!bound_here && !tags.isNull()) {
      for (JsonObjectConst t : tags) {
        const char* raw = t["uid"] | "";
        if (raw[0] && here[0] && cardUidsContain(raw, here)) { bound_here = true; break; }
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

// Uses what the main NFC poll already found. Selecting the tag again here
// would compete with that poll, and the loser gets nothing back.
//
// force skips the retry gap, for the one caller that runs immediately after a
// poll and needs the answer in the same pass rather than half a second later.
static void refreshCache(bool force = false) {
  static unsigned long last_ms = 0;
  static char last_uid[26] = "";

  if (!tag_present) {
    cached_uid[0] = 0; cached_kind[0] = 0; cached_content[0] = 0;
    cached_bytes = 0;
    cached_kindcode = TAG_KIND_NONE;
    memset(&cached_info, 0, sizeof(cached_info));
    last_uid[0] = 0;
    return;
  }

  const bool is_ntag = strlen(g_tag.uid_str) > 14;   // 7 bytes reads as 20 chars
  snprintf(cached_uid, sizeof(cached_uid), "%s", g_tag.uid_str);

  if (!is_ntag) {
    snprintf(cached_kind, sizeof(cached_kind), "MIFARE Classic, read-only");
    cached_kindcode = TAG_KIND_MIFARE;
    cached_content[0] = 0;
    cached_bytes = 0;
    memset(&cached_info, 0, sizeof(cached_info));
    return;
  }

  const bool changed = strcmp(last_uid, g_tag.uid_str) != 0 || cache_dirty;
  if (!changed && cached_content[0]) return;
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
    cached_info = ti;
    cache_dirty = false;
  }
}

void tagReadInfoNow() { refreshCache(true); }

// Bambu puts the finish in the material, "PETG Basic", while FilaMan keeps it
// in material_subgroup and matches on "PETG". Only a known finish word is
// dropped: cutting at the first space would turn "Support For PLA" into
// "Support", and would leave composites like PLA-CF alone only by luck.
static void bareMaterial(char *m) {
  static const char *FINISH[] = {
    "Basic", "Matte", "Silk", "Silk+", "Tough", "Aero", "Galaxy", "Marble",
    "Glow", "Sparkle", "Metal", "Wood", "Translucent", "Impact", "HF", "Plus"
  };
  for (int pass = 0; pass < 2; pass++) {
    char *sp = strrchr(m, ' ');
    if (!sp) return;
    bool hit = false;
    for (unsigned i = 0; i < sizeof(FINISH) / sizeof(FINISH[0]); i++)
      if (!strcasecmp(sp + 1, FINISH[i])) { hit = true; break; }
    if (!hit) return;
    *sp = 0;
  }
}

// FilaMan asks for a scan, the answer is whatever is on the reader. Nothing
// is sent for a blank or unreadable tag: the request expires instead, which
// the web UI reports as a timeout rather than as bad data.
static void scanTick() {
  if (!scan_pending) return;
  if (millis() - scan_since > SCAN_WAIT_MS) {
    scan_pending = false;
    logSD("Tag scan: no readable tag, request expired");
    return;
  }

  char material[17] = "", brand[33] = "", color[8] = "";
  unsigned tlo = 0, thi = 0;
  int sm = 0;

  const TagInfo *ti = &cached_info;
  if (tagCachedHasRecord()) {
    snprintf(material, sizeof(material), "%s", ti->material);
    snprintf(brand, sizeof(brand), "%s", ti->brand);
    snprintf(color, sizeof(color), "%02X%02X%02X", ti->r, ti->g, ti->b);
    tlo = ti->et_lo; thi = ti->et_hi;
    if (ti->sku[0] == 'S' && ti->sku[1] == 'M') sm = atoi(ti->sku + 2);
  } else if (tag_present && g_tag.material[0]) {
    // A Bambu tag. The main flow has already decoded it, and it is the one
    // kind of tag the page itself cannot read.
    snprintf(material, sizeof(material), "%s", g_tag.material);
    bareMaterial(material);
    // Bambu stores no vendor string, but a tag that authenticates with the
    // Bambu keys can only be theirs.
    snprintf(brand, sizeof(brand), "%s",
             g_tag.vendor[0] ? g_tag.vendor : "Bambu Lab");
    const char *c = g_tag.color_hex;
    if (*c == '#') c++;
    snprintf(color, sizeof(color), "%s", c);
    tlo = (unsigned)g_tag.temp_min; thi = (unsigned)g_tag.temp_max;
    if (sm_found && sm_id > 0) sm = sm_id;
  } else {
    return;
  }

  char json[288];
  snprintf(json, sizeof(json),
    "{\"protocol\":\"openspool\",\"version\":\"1.0\",\"type\":\"%s\","
    "\"color_hex\":\"%s\",\"brand\":\"%s\","
    "\"min_temp\":\"%u\",\"max_temp\":\"%u\"",
    material, color, brand, tlo, thi);
  size_t n = strnlen(json, sizeof(json));
  if (sm > 0) n = appendf(json, sizeof(json), n, ",\"sm_id\":%d", sm);
  appendf(json, sizeof(json), n, "}");

  scan_pending = false;
  filamanSendTagData(backendBaseUrl(), filamanDeviceToken(), json);
}

// Selects the tag and says whether it can be written at all. Both write paths
// start here, so the two refusals read the same wherever they came from.
static bool selectWritableTag(uint8_t *uid, uint8_t *uid_len) {
  *uid_len = 0;
  if (!nfcReadPassiveTarget(uid, uid_len, 600)) {
    finish("error", "No tag on the reader", TW_ERR_NO_TAG);
    return false;
  }
  if (*uid_len != 7) {
    finish("error", "Not a writable NTAG, this tag can only be read",
           TW_ERR_NOT_NTAG);
    return false;
  }
  return true;
}

// Builds the record from the spool and puts it on the already selected tag.
// On failure it reports the reason itself and returns false; on success it
// leaves the filament name in name[] and lets the caller word the message,
// because only the caller knows whether a link is going to be appended to it.
static bool writeSpoolRecord(int spool_id, TagFormat fmt,
                             char *name, size_t name_len) {
  name[0] = 0;
  write_err[0] = 0;
  write_code = TW_ERR_WRITE;

  // Not querySpoolmanById(): that also repaints the main screen and would
  // change which spool the scale believes is loaded.
  JsonDocument doc;
  int code = backendGetSpoolJson(backendBaseUrl(), spool_id, doc);
  if (code != 200 || doc.isNull()) {
    char m[96];
    snprintf(m, sizeof(m), "Spool %d not found on %s (HTTP %d)",
             spool_id, backendName(), code);
    finish("error", m, TW_ERR_BACKEND);
    return false;
  }
  JsonObjectConst sp = doc.as<JsonObjectConst>();

  bool ok;
  {
    AceFields f;
    buildAce(sp, &f);
    ok = TAG_FMT_IS_NDEF(fmt) ? writeOpenSpool(&f, spool_id, fmt) : writeAce(&f);
  }

  cache_dirty = true;   // the tag changed under a UID that did not

  if (!ok) {
    finish("error", write_err[0] ? write_err
                                 : "Write failed - keep the tag still on the reader",
           write_code);
    return false;
  }
  const char *n = sp["filament"]["name"] | "spool";
  snprintf(name, name_len, "%s", n[0] ? n : "spool");
  return true;
}

// The whole write for a caller that has no parking slot to go through - the
// device screen and the FilaMan trigger both land here when no record came
// with the request.
bool tagWriteSpoolNow(int spool_id, TagFormat fmt) {
  if (spool_id <= 0) return false;
  uint8_t uid[8], uid_len = 0;
  if (!selectWritableTag(uid, &uid_len)) return false;

  char name[48];
  if (!writeSpoolRecord(spool_id, fmt, name, sizeof(name))) return false;

  char m[128];
  snprintf(m, sizeof(m), "Wrote spool %d (%s) as %s", spool_id, name,
           fmtLabel(fmt));
  memset(&report, 0, sizeof(report));
  report.spool_id = spool_id;
  report.fmt      = (uint8_t)fmt;
  snprintf(report.name, sizeof(report.name), "%s", name);
  finish("ok", m, TW_OK);
  return true;
}

void tagWriteTick() {
  refreshCache();
  scanTick();
  if (!pending) return;
  pending = false;

  uint8_t uid[8], uid_len = 0;
  if (!selectWritableTag(uid, &uid_len)) return;

  if (pending_fmt == TAG_FMT_ERASE) {
    const bool erased = eraseTag();
    cache_dirty = true;
    report.erase = true;
    finish(erased ? "ok" : "error",
           erased ? "Tag erased" : "Erase failed - keep the tag still",
           erased ? TW_OK : TW_ERR_WRITE);
    return;
  }

  char name[48];
  const bool wrote = writeSpoolRecord(pending_id, pending_fmt, name, sizeof(name));
  snprintf(report.name, sizeof(report.name), "%s", name);
  // writeSpoolRecord() has already reported why, and finish() below would
  // overwrite the code, so keep it.
  const uint8_t code = wrote ? TW_OK : result;

  // A tag too small to write is no reason to leave the spool unbound. But a
  // spool the backend could not hand over is not one to bind a tag to either,
  // so that failure keeps the floor to itself.
  if (!wrote && (!pending_link || code == TW_ERR_BACKEND)) return;

  // Erase returned above, so there is no format to branch on here any more.
  char m[160];
  if (wrote) {
    snprintf(m, sizeof(m), "Wrote spool %d (%s) as %s", pending_id, name,
             fmtLabel(pending_fmt));
  } else {
    snprintf(m, sizeof(m), "%s", message);
  }
  size_t n = strnlen(m, sizeof(m));

  if (pending_link) {
    char uid_str[26];
    int u = 0;
    for (int i = 0; i < uid_len && u < (int)sizeof(uid_str) - 3; i++)
      u += snprintf(uid_str + u, sizeof(uid_str) - u, i ? ":%02X" : "%02X", uid[i]);
    char note[48];
    int code2 = backendLinkSpoolTag(backendBaseUrl(), pending_id, uid_str,
                                    note, sizeof(note));
    // One retry. The failure seen in the field was HTTP -1, a connection error,
    // and it left a written tag on a spool that names no tag - the exact state
    // this step exists to prevent. A second attempt costs 300 ms and only ever
    // runs after something already went wrong.
    if (code2 != 200) {
      logSDf("TagWrite: link failed (HTTP %d), retrying once", code2);
      delay(300);
      code2 = backendLinkSpoolTag(backendBaseUrl(), pending_id, uid_str,
                                  note, sizeof(note));
    }
    // appendf, not m + n: a long filament name makes snprintf report a length
    // it never wrote, and then m + n points past the buffer while
    // sizeof(m) - n underflows. Same reason the rest of this file moved off it.
    report.link_http = code2;
    snprintf(report.link_note, sizeof(report.link_note), "%s", note);
    if (code2 == 200) {
      // The tag on the reader now points at this spool, so the screen should
      // say so rather than keep whatever it showed before. Handed over as an
      // id: the lookup repaints the main screen and belongs on the UI side.
      linked_spool = pending_id;
      report.link = TAG_LINK_OK;
      if (note[0]) appendf(m, sizeof(m), n, ", linked (%s)", note);
      else         appendf(m, sizeof(m), n, ", linked to the spool");
    } else {
      report.link = TAG_LINK_FAIL;
      appendf(m, sizeof(m), n, ", but linking failed (HTTP %d)", code2);
    }
  }
  finish(wrote ? "ok" : "error", m, code);
}
