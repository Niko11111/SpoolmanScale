// The OpenSpool record, and FilaMan's, which is the same JSON under another
// protocol name: one NDEF record on an NTAG, built, written and read back.
#include "tag_write.h"

#include <ArduinoJson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hardware/nfc.h"
#include "services/tag_write_internal.h"

using namespace tagw;

// TLV tag and length, record header with type and payload length, the media
// type itself, the payload, the terminator - then rounded up to whole 4 byte
// pages, because that is the unit a write goes in.
size_t tagNdefSizeFor(size_t json_len) {
  const size_t n = 2 + 3 + 16 + json_len + 1;
  return n + ((4 - (n % 4)) % 4);
}

// Wraps a JSON document in the NDEF TLV an OpenSpool reader expects.
bool tagw::writeNdefJson(const char *json) {
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
        tagWriteFail(TW_ERR_SPACE,
                     "Tag reports no size. Format it as NDEF once, then retry");
      else
        tagWriteFail(TW_ERR_SPACE, "OpenSpool needs %d bytes, this tag holds %u",
                     i_need, (unsigned)((last - 3) * 4));
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

  // The TLV header sits in the first page and is written last, after that
  // page has been blanked: a tag lifted mid-write then reads as empty, not
  // as a record whose length byte points into whatever the pages held
  // before. The header and the last page are read back - the two that
  // decide whether a reader sees a whole record.
  const uint8_t zero[4] = { 0, 0, 0, 0 };
  // Every page of the record, and the first one twice.
  progressBegin((uint16_t)(i / 4 + 1));
  if (!wrPage(NTAG_FIRST_USER_PAGE, zero)) return false;
  for (int off = 4; off < i; off += 4)
    if (!wrPage((uint8_t)(NTAG_FIRST_USER_PAGE + off / 4), buf + off)) return false;
  if (!wrPage(NTAG_FIRST_USER_PAGE, buf)) return false;

  const int last_off = i - 4;
  if (!rdPageIs(NTAG_FIRST_USER_PAGE, buf) ||
      (last_off > 0 && !rdPageIs((uint8_t)(NTAG_FIRST_USER_PAGE + last_off / 4), buf + last_off))) {
    tagWriteFail(TW_ERR_WRITE, "Tag did not keep the record - hold it still and retry");
    return false;
  }
  return true;
}

static const char* protoName(TagFormat fmt) {
  return fmt == TAG_FMT_FILAMAN ? "filaman" : "openspool";
}

// Two names for the same number, because two readers look for two different
// keys. sm_id is the OpenSpool convention this firmware has always written and
// what OpenSpoolman resolves. spool_id is what FilaMan's own reader looks for -
// the word sm_id does not appear anywhere in FilaMan, and a record carrying
// only that one arrives there as spool 0. Neither replaces the other.
int tagw::buildOpenSpoolJson(const AceFields *f, int spool_id, TagFormat fmt,
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

bool tagw::writeOpenSpool(const AceFields *f, int spool_id, TagFormat fmt) {
  char json[224];
  if (!buildOpenSpoolJson(f, spool_id, fmt, json, sizeof(json))) return false;
  return writeNdefJson(json);
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
bool tagw::readOpenSpool(char *out, size_t out_len) {
  // Zeroed: only the pages the TLV claims are read, and a record that says it
  // reaches past them must copy zeros, not whatever the stack held before.
  uint8_t buf[240] = {0};
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
  // Within what was read (2 + len), not merely within the buffer.
  if (plen <= 0 || start + plen > 2 + len) return false;
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

void tagw::describeOpenSpool(const char *json, char *out, size_t out_len, TagInfo *ti) {
  if (ti) { memset(ti, 0, sizeof(*ti)); snprintf(ti->fmt, sizeof(ti->fmt), "OpenSpool"); }
  JsonDocument d;
  if (deserializeJson(d, json)) { snprintf(out, out_len, "OpenSpool: unreadable"); return; }
  snprintf(out, out_len, "OpenSpool: %s %s, #%s, %s-%sC",
           d["brand"] | "?", d["type"] | "?", d["color_hex"] | "?",
           d["min_temp"] | "?", d["max_temp"] | "?");
  if (!ti) return;
  ti->spool_id = d["spool_id"] | (d["sm_id"] | 0);
  snprintf(ti->proto, sizeof(ti->proto), "%s", d["protocol"] | "");
  snprintf(ti->version, sizeof(ti->version), "%s", d["version"] | "");
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
