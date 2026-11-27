#pragma once

// Shared by the files behind services/tag_write.h and by nothing else:
// tag_write.cpp (the jobs), ntag_pages.cpp (the pages), tag_format_ace.cpp
// and tag_format_openspool.cpp (the records), tag_inspect.cpp (what is read
// back). Everything outside them goes through tag_write.h.

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>

#include "services/tag_write.h"

// The helpers behind tag_write.h carry short, generic names (wrPage, readText,
// appendf), so they live in their own namespace and reach no other file. The
// #defines below are not scoped by it; only the five tag files include this.
namespace tagw {

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

// The page every record starts on, once the four the chip keeps for itself
// are past.
#define NTAG_FIRST_USER_PAGE    4

// NDEF on an NTAG: TLV 0x03, length, one application/json record, 0xFE.
// Record header D2 = MB|ME|SR, TNF 2 (media type).
//
// The single byte TLV length field is what caps the payload, not the tag: past
// 255 total the TLV would need its three byte form, which nothing here writes.
#define NDEF_JSON_MAX 250

// ---- tag_format_ace.cpp
void buildAce(JsonObjectConst sp, AceFields *f);
void aceToInfo(const AceFields *f, TagInfo *ti);
void describeAce(const AceFields *f, char *out, size_t out_len);
bool writeAce(const AceFields *f);

// ---- tag_format_openspool.cpp
bool writeNdefJson(const char *json);
int  buildOpenSpoolJson(const AceFields *f, int spool_id, TagFormat fmt,
                        char *json, size_t json_len);
bool writeOpenSpool(const AceFields *f, int spool_id, TagFormat fmt);
bool readOpenSpool(char *out, size_t out_len);
void describeOpenSpool(const char *json, char *out, size_t out_len, TagInfo *ti);

// ---- ntag_pages.cpp
// The NTAG every page below goes onto, set once selectWritableTag() found it.
void ntagPagesSelect(const uint8_t *uid, uint8_t uid_len);
const uint8_t* ntagPagesUid();
uint8_t ntagPagesUidLen();
void progressBegin(uint16_t total);
bool wrPage(uint8_t page, const uint8_t *d);
bool rdPageIs(uint8_t page, const uint8_t *expect);
uint16_t tagUserBytes();
uint8_t lastUserPage();
bool wrText(uint8_t first, const char *s);
bool wrU16Pair(uint8_t page, uint16_t a, uint16_t b);
bool eraseTag();
void readText(uint8_t first, char *out, size_t out_len);
uint16_t rdU16(const uint8_t *d);

// ---- tag_inspect.cpp
void refreshCache(bool force = false);
// A write or an erase changed the tag under a UID that did not.
void tagCacheMarkDirty();
size_t appendf(char *out, size_t out_len, size_t n, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

// ---- tag_write.cpp
// Why the page write of the running job failed, reported when the job ends.
void tagWriteFail(uint8_t code, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

}  // namespace tagw
