#include "creality_write.h"

#include <Arduino.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "creality/creality_scan.h"
#include "creality/creality_tag.h"

// The record sits in sector 1; Creality's own tags carry spaces in sector 2.
static constexpr uint8_t CFS_SECTOR     = 1;
static constexpr uint8_t CFS_PAD_SECTOR = 2;
static constexpr uint8_t CFS_PAD_BYTE   = ' ';
// A clock that reports an earlier year was never set: the record then gets
// the fixed fallback date crealityBuildRecord() knows.
static constexpr int     CLOCK_SET_FROM_YEAR = 2024;

bool crealityRecordForSpool(JsonObjectConst sp, int spool_id, char rec[41]) {
  CrealityRecordIn in;
  memset(&in, 0, sizeof(in));
  in.vendor    = sp["filament"]["vendor"]["name"] | "";
  in.name      = sp["filament"]["name"] | "";
  in.material  = sp["filament"]["material"] | "PLA";
  in.color_hex = sp["filament"]["color_hex"] | "";
  // What was on the spool when it was new: the spool's own figure first,
  // then the filament's nominal one. The record carries a length class, not
  // a weight, so 1 kg and 1.02 kg land on the same code.
  float net = sp["initial_weight"] | 0.0f;
  if (net <= 0) net = sp["filament"]["weight"] | 0.0f;
  in.net_g    = net;
  in.spool_id = spool_id;
  struct tm now;
  if (getLocalTime(&now, 0) && now.tm_year + 1900 >= CLOCK_SET_FROM_YEAR) {
    in.month = now.tm_mon + 1;
    in.day   = now.tm_mday;
    in.year  = now.tm_year + 1900;
  }
  return crealityBuildRecord(in, rec);
}

static bool isCrealityRecord(const uint8_t blocks[MIFARE_DATA_BLOCKS_MAX][MIFARE_BLOCK_BYTES]) {
  CrealityTag t;
  return crealityDecode(blocks, &t);
}

void crealityEraseJob(MifareWriteJob* job) {
  memset(job, 0, sizeof(*job));
  job->label         = "CFS";
  job->sector        = CFS_SECTOR;
  job->data_blocks   = MIFARE_DATA_BLOCKS_MAX;
  job->own_key       = crealityDeriveSectorKey;
  job->is_own_record = isCrealityRecord;
  job->family        = TAG_FAMILY_CREALITY;
}

bool crealityBuildJob(JsonObjectConst sp, int spool_id, MifareWriteJob* job,
                      char* text, size_t text_len) {
  char rec[41];
  uint8_t cipher[MIFARE_DATA_BLOCKS_MAX * MIFARE_BLOCK_BYTES];
  if (!crealityRecordForSpool(sp, spool_id, rec) || !crealityEncryptRecord(rec, cipher)) {
    return false;
  }
  crealityEraseJob(job);
  memcpy(job->data, cipher, sizeof(cipher));
  job->set_trailer   = true;
  job->pad_sector    = CFS_PAD_SECTOR;
  job->pad_byte      = CFS_PAD_BYTE;
  snprintf(text, text_len, "%.40s", rec);
  return true;
}

void crealityWritten(const uint8_t uid[4], const char* text) {
  // What the next comparison with the backend sees for this tag.
  crealityRememberRecord(uid, text);
}
