#include "flash_log.h"

#include <esp_partition.h>
#include <stdlib.h>
#include <string.h>

// ---- layout ---------------------------------------------------------
//
// A record is 128 bytes and 32 of them fill a 4 kB sector exactly. That is
// the whole reason for the number: a sector is the unit the flash can erase,
// so a record must never straddle two of them, otherwise erasing the oldest
// sector would cut a line in half.
#define REC_BYTES        128
#define SECTOR_BYTES     4096
#define RECS_PER_SECTOR  (SECTOR_BYTES / REC_BYTES)          // 32
#define SECTOR_COUNT     (FLASH_LOG_BYTES / SECTOR_BYTES)    // 512
#define REC_COUNT        (SECTOR_COUNT * RECS_PER_SECTOR)    // 16384
#define REC_HEADER       20
#define REC_TEXT         (REC_BYTES - REC_HEADER)            // 108
#define REC_MAX_PARTS    4

// Erased flash reads as all ones, so this is what "never written" looks like.
#define SEQ_EMPTY        0xFFFFFFFFUL

// Whatever stood in the data partition before is not a log. The first
// firmware to open it found a LittleFS left over from a measurement and read
// its metadata as records, which came out as 1.7 billion stored lines. A
// record is only a record if it says so.
#define REC_MAGIC        0x5350534CUL   // "SPSL", SpoolmanScale log

struct Rec {
  uint32_t magic;
  uint32_t seq;       // the line this record belongs to
  uint32_t when;      // UTC epoch, 0 when the clock was not set
  uint32_t up_s;      // seconds since boot
  uint8_t  part;      // 0 is the first piece of the line
  uint8_t  more;      // 1 when another piece follows
  uint16_t pad;
  char     text[REC_TEXT];
};
static_assert(sizeof(Rec) == REC_BYTES, "a record has to fill a 32nd of a sector");

static const esp_partition_t *s_part = nullptr;
static uint32_t s_next_rec  = 0;          // slot the next record goes into
static uint32_t s_next_seq  = 0;          // sequence the next line gets
static uint32_t s_first_seq = 0;          // oldest line still readable
static bool     s_lapped    = false;      // the head has been round at least once
// Which sector is known to be erased and still unused, or NO_SECTOR. It has
// to be the number and not a flag: with a flag, the tick erasing sector 1
// while the head still stood at record 0 was read as "the sector under the
// head is ready", and the first line of a device's life went into flash that
// had never been erased.
#define NO_SECTOR        0xFFFFFFFFUL
static uint32_t s_erased_sector = NO_SECTOR;

// A clear does not block: the reader is cut off at once and the sectors are
// erased one per tick afterwards.
static bool     s_clearing   = false;
static uint32_t s_clear_next = 0;

// How long to wait before trying a sector that refused to erase again, and
// how often to say so. Retrying every loop pass was 6,000 attempts and 6,000
// serial lines a minute, which buries the reason under its own symptom.
#define ERASE_RETRY_MS     5000
#define ERASE_COMPLAIN_MS  5000

static uint32_t s_erase_retry_at_ms = 0;
static uint32_t s_erase_complained_ms = 0;

static inline uint32_t recOffset(uint32_t rec) { return rec * REC_BYTES; }
static inline uint32_t sectorOf(uint32_t rec)  { return rec / RECS_PER_SECTOR; }

// True only for a record this firmware wrote. Anything else - erased flash,
// a filesystem that used to live here, a half written record - reads as empty.
static bool readRec(uint32_t rec, Rec *out) {
  if (!s_part) return false;
  if (esp_partition_read(s_part, recOffset(rec), out, sizeof(Rec)) != ESP_OK) return false;
  if (out->magic != REC_MAGIC) { out->seq = SEQ_EMPTY; return true; }
  return true;
}

// Erasing a sector destroys up to 32 lines at once, so the oldest sequence
// still worth looking for moves past the highest one that stood in it. Doing
// that here rather than at the call sites means no path can erase and forget.
static bool eraseSector(uint32_t sector) {
  if (!s_part) return false;
  const uint32_t first = sector * RECS_PER_SECTOR;
  for (int32_t i = RECS_PER_SECTOR - 1; i >= 0; i--) {
    Rec r;
    if (!readRec(first + (uint32_t)i, &r) || r.seq == SEQ_EMPTY) continue;
    if (r.seq >= s_first_seq) s_first_seq = r.seq + 1;
    break;                                  // sequences rise inside a sector
  }
  const esp_err_t e = esp_partition_erase_range(s_part, sector * SECTOR_BYTES,
                                                SECTOR_BYTES);
  if (e != ESP_OK) {
    const uint32_t now = millis();
    if (!s_erase_complained_ms || now - s_erase_complained_ms >= ERASE_COMPLAIN_MS) {
      Serial.printf("Flash log: erase of sector %lu failed (%d)\n",
                    (unsigned long)sector, (int)e);
      s_erase_complained_ms = now;
    }
    return false;
  }
  return true;
}

// Whether a sector is genuinely blank, not merely free of our records. The
// difference matters: a sector holding a filesystem somebody left behind has
// no record magic either, and writing into it without erasing first is how
// the first line of a device's life was lost.
static bool isSectorErased(uint32_t sector) {
  if (!s_part) return false;
  uint8_t *page = (uint8_t *)malloc(SECTOR_BYTES);
  if (!page) return false;
  bool blank = false;
  if (esp_partition_read(s_part, sector * SECTOR_BYTES, page, SECTOR_BYTES) == ESP_OK) {
    blank = true;
    for (uint32_t i = 0; i < SECTOR_BYTES; i++) {
      if (page[i] != 0xFF) { blank = false; break; }
    }
  }
  free(page);
  return blank;
}

// ---- finding the head at boot ---------------------------------------
//
// Records are written in order and a sector is always erased before its first
// record is used, so the first record of a sector carries the lowest sequence
// in it. Reading those 512 headers is enough to find the newest sector, and
// the 32 records inside it say where the head stands.
static void findHead() {
  uint32_t best_seq = 0, best_sector = 0, low_seq = 0, non_empty = 0;
  bool any = false;

  for (uint32_t s = 0; s < SECTOR_COUNT; s++) {
    Rec r;
    if (!readRec(s * RECS_PER_SECTOR, &r) || r.seq == SEQ_EMPTY) continue;
    if (!any || r.seq > best_seq) { best_seq = r.seq; best_sector = s; }
    if (!any || r.seq < low_seq)  { low_seq = r.seq; }
    any = true;
    non_empty++;
  }

  if (!any) {                       // never written, or cleared and left empty
    s_next_rec = 0; s_next_seq = 0; s_first_seq = 0; s_lapped = false;
    return;
  }

  // Inside the newest sector, walk to the first slot that was never used.
  const uint32_t base = best_sector * RECS_PER_SECTOR;
  uint32_t last_seq = best_seq;
  s_next_rec = base;
  for (uint32_t i = 0; i < RECS_PER_SECTOR; i++) {
    Rec r;
    if (!readRec(base + i, &r) || r.seq == SEQ_EMPTY) break;
    last_seq = r.seq;
    s_next_rec = (base + i + 1) % REC_COUNT;
  }
  s_next_seq  = last_seq + 1;
  s_first_seq = low_seq;
  // Before the first lap the used sectors are exactly the ones up to the head;
  // afterwards every sector holds something except the one erased ahead.
  s_lapped = (non_empty > best_sector + 1);
}

bool flashLogBegin() {
  s_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                    ESP_PARTITION_SUBTYPE_DATA_SPIFFS, NULL);
  if (!s_part) {
    Serial.println("Flash log: no data partition, nothing to write to");
    return false;
  }
  if (s_part->size < FLASH_LOG_BYTES) {
    Serial.printf("Flash log: data partition is only %lu bytes, need %lu\n",
                  (unsigned long)s_part->size, (unsigned long)FLASH_LOG_BYTES);
    s_part = nullptr;
    return false;
  }
  findHead();
  // The sector in front of the head was very likely erased before the last
  // restart. Asking costs one read and saves erasing it a second time, which
  // otherwise happened on every single boot.
  const uint32_t ahead = (sectorOf(s_next_rec) + 1) % SECTOR_COUNT;
  s_erased_sector = isSectorErased(ahead) ? ahead : NO_SECTOR;
  Serial.printf("Flash log: %lu KB at 0x%06lX, head at record %lu, %lu lines stored\n",
                (unsigned long)(FLASH_LOG_BYTES / 1024),
                (unsigned long)s_part->address,
                (unsigned long)s_next_rec, (unsigned long)flashLogLines());
  return true;
}

bool flashLogAvailable() { return s_part != nullptr; }

// ---- writing --------------------------------------------------------

// The sector a record falls into has to be erased before the first record in
// it is written. flashLogTick() normally did that already; a burst that
// crosses a boundary between two loop passes pays for it here, once per 32
// lines rather than once per line.
static void ensureSectorFor(uint32_t rec) {
  if (rec % RECS_PER_SECTOR != 0) return;   // mid-sector, already erased
  const uint32_t sector = sectorOf(rec);
  if (s_erased_sector == sector) { s_erased_sector = NO_SECTOR; return; }
  eraseSector(sector);
}

void flashLogWrite(time_t when, uint32_t up_s, const char *msg) {
  if (!s_part || s_clearing || !msg) return;

  const size_t len = strlen(msg);
  const uint32_t seq = s_next_seq++;

  size_t done = 0;
  uint8_t part = 0;
  do {
    Rec r;
    memset(&r, 0, sizeof(r));
    r.magic = REC_MAGIC;
    r.seq  = seq;
    r.when = (uint32_t)when;
    r.up_s = up_s;
    r.part = part;
    size_t take = len - done;
    if (take > REC_TEXT) take = REC_TEXT;
    memcpy(r.text, msg + done, take);
    done += take;
    r.more = (done < len && part + 1 < REC_MAX_PARTS) ? 1 : 0;

    ensureSectorFor(s_next_rec);
    const esp_err_t e = esp_partition_write(s_part, recOffset(s_next_rec),
                                            &r, sizeof(Rec));
    if (e != ESP_OK) {
      // Carry on rather than going quiet: a lost line is a smaller problem
      // than a log that stops without saying so.
      Serial.printf("Flash log: write to record %lu failed (%d)\n",
                    (unsigned long)s_next_rec, (int)e);
    }
    s_next_rec = (s_next_rec + 1) % REC_COUNT;
    if (s_next_rec == 0) s_lapped = true;
    part++;
  } while (done < len && part < REC_MAX_PARTS);
}

// ---- housekeeping ---------------------------------------------------

void flashLogTick() {
  if (!s_part) return;

  if (s_clearing) {
    eraseSector(s_clear_next);
    if (++s_clear_next >= SECTOR_COUNT) {
      s_clearing = false;
      s_next_rec = 0; s_next_seq = 0; s_first_seq = 0;
      s_lapped = false; s_erased_sector = NO_SECTOR;
      Serial.println("Flash log: cleared");
    }
    return;
  }

  // One erased sector ahead of the head, so no line ever waits for a 54 ms
  // erase. The head's own sector is never this one, and a boot that lands the
  // head on a sector start has that sector erased by ensureSectorFor().
  const uint32_t ahead = (sectorOf(s_next_rec) + 1) % SECTOR_COUNT;
  if (s_erased_sector == ahead) return;
  if (s_erase_retry_at_ms && (int32_t)(millis() - s_erase_retry_at_ms) < 0) return;
  if (eraseSector(ahead)) {
    s_erased_sector     = ahead;
    s_erase_retry_at_ms = 0;
  } else {
    // A sector that will not take an erase is a broken chip, not a busy one.
    // Writing carries on into it: a record without its magic is ignored by
    // the reader, so the log degrades instead of dying without a word.
    s_erase_retry_at_ms = millis() + ERASE_RETRY_MS;
    if (!s_erase_retry_at_ms) s_erase_retry_at_ms = 1;   // millis() wrapped
  }
}

void flashLogClear() {
  if (!s_part || s_clearing) return;
  s_clearing   = true;
  s_clear_next = 0;
  s_first_seq  = s_next_seq;   // hides everything from the reader at once
}

bool flashLogClearBusy() { return s_clearing; }

uint32_t flashLogLines() {
  if (!s_part || s_clearing || s_next_seq <= s_first_seq) return 0;
  return s_next_seq - s_first_seq;
}

uint32_t flashLogUsedBytes() {
  if (!s_part || s_clearing) return 0;
  return s_lapped ? (uint32_t)FLASH_LOG_BYTES : (s_next_rec * REC_BYTES);
}

uint32_t flashLogCapacityBytes() { return FLASH_LOG_BYTES; }

// ---- reading --------------------------------------------------------

uint32_t flashLogEmit(void (*emit)(const char *line, void *ctx), void *ctx) {
  if (!s_part || !emit || s_clearing) return 0;

  // A sector at a time rather than a record at a time. Sixteen thousand reads
  // of 128 bytes held the loop for 1.6 s, and this handler runs on it; 512
  // reads of 4 kB do the same work. The buffer goes on the heap because the
  // loop task's stack is not the place for four kilobytes.
  uint8_t *page = (uint8_t *)malloc(SECTOR_BYTES);
  if (!page) return 0;

  char line[REC_TEXT * REC_MAX_PARTS + 24];
  uint32_t emitted = 0;
  uint32_t loaded  = NO_SECTOR;

  // Walking the whole ring from the head is what puts the lines in order: the
  // slots in front of the head hold the previous lap, which is the oldest
  // material there is, and the slot behind it holds the newest.
  for (uint32_t i = 0; i < REC_COUNT; i++) {
    const uint32_t rec    = (s_next_rec + i) % REC_COUNT;
    const uint32_t sector = sectorOf(rec);
    if (sector != loaded) {
      if (esp_partition_read(s_part, sector * SECTOR_BYTES, page, SECTOR_BYTES) != ESP_OK) {
        i += RECS_PER_SECTOR - 1 - (rec % RECS_PER_SECTOR);
        continue;
      }
      loaded = sector;
      // Records fill a sector in order, so an empty first one means the whole
      // sector is empty and the other 31 need not be looked at.
      const Rec *first = (const Rec *)page;
      if (first->magic != REC_MAGIC && (rec % RECS_PER_SECTOR) == 0) {
        i += RECS_PER_SECTOR - 1;
        continue;
      }
    }

    const Rec *r = (const Rec *)(page + (rec % RECS_PER_SECTOR) * REC_BYTES);
    if (r->magic != REC_MAGIC || r->seq == SEQ_EMPTY || r->seq < s_first_seq) continue;
    if (r->part != 0) continue;   // picked up with its first piece below

    // Stamp first, the way the card writes it.
    size_t at = 0;
    if (r->when) {
      const time_t w = (time_t)r->when;
      struct tm t;
      localtime_r(&w, &t);
      at = (size_t)snprintf(line, sizeof(line), "[%02d:%02d:%02d] ",
                            t.tm_hour, t.tm_min, t.tm_sec);
    } else {
      at = (size_t)snprintf(line, sizeof(line), "[up %lus] ",
                            (unsigned long)r->up_s);
    }

    // The line itself, gathered from however many records it took. A
    // continuation can sit in the next sector, so it is read on its own
    // rather than out of the page above.
    Rec piece;
    memcpy(&piece, r, sizeof(Rec));
    uint32_t from = rec;
    for (uint8_t p = 0; p < REC_MAX_PARTS; p++) {
      const size_t take = strnlen(piece.text, REC_TEXT);
      if (at + take < sizeof(line) - 1) { memcpy(line + at, piece.text, take); at += take; }
      if (!piece.more) break;
      from = (from + 1) % REC_COUNT;
      if (!readRec(from, &piece) || piece.seq != r->seq) break;
    }
    line[at] = '\0';
    emit(line, ctx);
    emitted++;
  }
  free(page);
  return emitted;
}
