// The NTAG pages under every record: the one place a page is written
// (nfcWriteNtagPage, check.sh rule 14), read back, counted for the progress
// bar, and the tag's size read off its capability container.
#include "tag_write.h"

#include <string.h>

#include "hardware/nfc.h"
#include "services/tag_pending.h"
#include "services/tag_write_internal.h"

using namespace tagw;

// Pages of the running job, counted where every one of them passes. A job
// says how many it is going to write before its first, see progressBegin().
static TagWriteProgressFn s_progress    = nullptr;
static uint16_t           s_pages_done  = 0;
static uint16_t           s_pages_total = 0;

void tagWriteSetProgress(TagWriteProgressFn fn) { s_progress = fn; }

// The NTAG selectWritableTag() found: every page below goes onto it, and an
// armed write marks it unfinished before the first one (services/tag_pending.h).
static uint8_t s_sel_uid[NFC_UID_MAX];
static uint8_t s_sel_len = 0;

void tagw::ntagPagesSelect(const uint8_t *uid, uint8_t uid_len) {
  memcpy(s_sel_uid, uid, uid_len);
  s_sel_len = uid_len;
}

const uint8_t* tagw::ntagPagesUid() { return s_sel_uid; }

uint8_t tagw::ntagPagesUidLen() { return s_sel_len; }

void tagw::progressBegin(uint16_t total) {
  s_pages_done  = 0;
  s_pages_total = total;
  if (s_progress && total) s_progress(0, total);
}

bool tagw::wrPage(uint8_t page, const uint8_t *d) {
  if (page < 4) return false;          // UID, lock bytes, CC
  uint8_t buf[4];
  memcpy(buf, d, 4);
  tagPendingBegin(s_sel_uid, s_sel_len);
  if (!nfcWriteNtagPage(page, buf)) return false;
  // After the page, never around it: the listener redraws, and that takes a
  // few milliseconds the chip should not spend waiting in the middle of one.
  if (s_pages_done < s_pages_total) s_pages_done++;
  if (s_progress && s_pages_total) s_progress(s_pages_done, s_pages_total);
  return true;
}

// Reads a page back and compares. A write the chip acknowledged is not yet a
// write that took: a tag drifting off the antenna acks and stores nothing.
bool tagw::rdPageIs(uint8_t page, const uint8_t *expect) {
  uint8_t got[4] = {0};
  return nfcReadNtagPage(page, got) && memcmp(got, expect, 4) == 0;
}

// The last user page an NTAG2xx can have: the library refuses pages from 231
// on, and the largest tag this firmware writes, an NTAG216, ends at 225.
#define NTAG_PAGE_MAX         230
// Without a readable capability container the smallest tag is assumed.
#define NTAG_FALLBACK_LAST_PG  39

// Capability container at page 3: byte 2 counts 8 byte blocks. What it reports
// is the NDEF area, which is a little smaller than the chip: NTAG213 144 of
// 144, NTAG215 496 of 504, NTAG216 872 of 888. Those are the numbers the UI
// shows, because they are what a record actually has to fit into.
uint16_t tagw::tagUserBytes() {
  uint8_t cc[4] = {0};
  if (!nfcReadNtagPage(3, cc) || cc[0] != 0xE1 || !cc[2]) return 0;
  return (uint16_t)cc[2] * 8;
}

// Falls back to the smallest tag, so an unreadable CC never overruns.
uint8_t tagw::lastUserPage() {
  const uint16_t b = tagUserBytes();
  if (!b) return NTAG_FALLBACK_LAST_PG;
  // In 16 bits. Byte 2 of the CC is whatever the tag says, and from 0x7F up -
  // an NTAG I2C plus 2k reports 0xEA - the old 8 bit sum wrapped to page 1,
  // after which eraseTag() ran no pass at all and reported success.
  uint16_t last = NTAG_FIRST_USER_PAGE + b / 4 - 1;
  if (last > NTAG_PAGE_MAX) last = NTAG_PAGE_MAX;
  return (uint8_t)last;
}

bool tagw::wrText(uint8_t first, const char *s) {
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

bool tagw::wrU16Pair(uint8_t page, uint16_t a, uint16_t b) {
  uint8_t buf[4] = { (uint8_t)(a & 0xFF), (uint8_t)(a >> 8),
                     (uint8_t)(b & 0xFF), (uint8_t)(b >> 8) };
  return wrPage(page, buf);
}

// Clears the user pages, whatever the tag has. A fixed upper page would
// overrun an NTAG213 and report a failed erase after erasing everything.
bool tagw::eraseTag() {
  const uint8_t zero[4] = {0, 0, 0, 0};
  const uint8_t last = lastUserPage();
  progressBegin((uint16_t)(last - NTAG_FIRST_USER_PAGE + 1));
  for (uint8_t pg = 4; pg <= last; pg++)
    if (!wrPage(pg, zero)) return false;
  return true;
}

void tagw::readText(uint8_t first, char *out, size_t out_len) {
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

uint16_t tagw::rdU16(const uint8_t *d) { return (uint16_t)(d[0] | (d[1] << 8)); }
