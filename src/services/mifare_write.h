#pragma once

#include <stdint.h>

#include "services/tag_family.h"

// ============================================================
//  WRITING TO A MIFARE CLASSIC TAG: THE ONE DOOR
//
//  Every block that goes onto a 4 byte MIFARE Classic tag goes through
//  mifareWrite(), and scripts/check.sh (rule 14) refuses the reader's block
//  write anywhere else. The rules that keep other people's tags whole live here, once, for
//  every format:
//
//  - Only the 4 byte UID the caller expects, never sector 0 and never a block
//    outside the job's sector.
//  - A tag remembered as Bambu is refused before any key is tried. Bambu's
//    keys are derived per tag and no format here knows them, so a Bambu tag
//    could not be opened anyway; the family check makes that explicit.
//  - Written only when the sector opens with the factory key and its data
//    blocks are empty, or when it opens with the factory key or the format's
//    own key and the caller asked for an overwrite - an answer given after the
//    owner was shown what is on the card. Anything else is left as it is.
//  - A sector trailer is written by this file alone, only on a blank tag, and
//    only with the transport access bits. It goes last, so a write that stops
//    part way leaves a tag that is still on the factory key.
//  - Read back with the final key before it counts.
//
//  What a format puts on the tag (its key, its blocks, whether it sets a new
//  key) comes in a MifareWriteJob, see services/mifare_formats.h.
//
//  Also the two card helpers the read side shares with it: waking a card a
//  refused key has left silent, and asking whether a card is still blank.
//  Loop task only, like every other NFC access.
// ============================================================

#define MIFARE_BLOCK_BYTES     16
#define MIFARE_KEY_BYTES        6
#define MIFARE_DATA_BLOCKS_MAX  3

struct MifareWriteJob {
  const char* label;        // log prefix, "CFS" gives "CFS write: ..."
  uint8_t     sector;       // 1..15
  uint8_t     data_blocks;  // 1..MIFARE_DATA_BLOCKS_MAX, from the sector's first block
  uint8_t     data[MIFARE_DATA_BLOCKS_MAX][MIFARE_BLOCK_BYTES];
  // The format's own key for this UID: what a tag carrying the format opens
  // with. False when it cannot be derived.
  bool (*own_key)(const uint8_t uid[4], uint8_t key[MIFARE_KEY_BYTES]);
  // The sector's data blocks, read with own_key, hold this format's record.
  bool (*is_own_record)(const uint8_t blocks[MIFARE_DATA_BLOCKS_MAX][MIFARE_BLOCK_BYTES]);
  // A blank tag gets own_key as key A and key B. False keeps the factory key.
  bool        set_trailer;
  // Cosmetic, nothing depends on it: a second sector still on the factory key
  // with empty blocks is filled with pad_byte. 0 = none.
  uint8_t     pad_sector;
  uint8_t     pad_byte;
  // Remembered for the UID once the format's record is on the tag.
  TagFamily   family;
};

enum MifareWriteResult {
  MIFARE_WRITE_OK,
  MIFARE_WRITE_NO_TAG,         // nothing, or no 4 byte tag, or not the expected one
  MIFARE_WRITE_IS_FORMAT,      // already opens with the format's key: left alone
  MIFARE_WRITE_NOT_BLANK,      // other keys, data in the sector, or a Bambu tag
  MIFARE_WRITE_FAILED,         // refused part way, or an unusable job
  MIFARE_WRITE_VERIFY_FAILED,  // written, but did not read back as written
};

// Called while a write waits for a tag that stopped answering to be put back:
// phase 0 once, then phase 1 about every 150 ms. Keeps the screen
// alive and says what to do. nullptr means no waiting.
typedef void (*MifareWaitFn)(int phase);

// Puts the job onto the tag on the reader. expect, when not nullptr, is the
// only UID accepted. overwrite: a tag that already opens with the format's
// key gets the new blocks too (keys unchanged); only ever on an explicit
// answer. uid_out receives the UID the write went to.
MifareWriteResult mifareWrite(const MifareWriteJob& job, uint8_t uid_out[4],
                              const uint8_t* expect, MifareWaitFn wait, bool overwrite);

// Empties the data blocks of the format's sector and nothing else: zeros
// through the same door as a write, overwrite included, but never a trailer
// and never the pad sector. A tag on the format's key keeps that key, one on
// the factory key keeps the factory key. Putting a key back would mean
// rewriting the trailer of a tag that holds data, and one wrong byte there
// makes the tag scrap. Only the job's sector, label, key and family are used;
// its data is ignored.
MifareWriteResult mifareErase(const MifareWriteJob& format, uint8_t uid_out[4],
                              const uint8_t* expect, MifareWaitFn wait);

// A data block nobody has written: all zeros, all FF, or all spaces.
bool mifareBlockIsBlank(const uint8_t block[MIFARE_BLOCK_BYTES]);

// True once for the tag a write was just verified on: the scan has to read it
// again rather than keep the record it decoded before the write. A tag put
// back within seconds counts as the same placement and is not read again, so
// the screen showed the old colour after a CFS write (12.11.2026).
bool mifareTakeReread(const uint8_t uid[4]);

// Sector 1 of this card as mifareProbeFactory() last found it: opened with the
// factory key, not blank. False for any other card, or once it was written.
// What the question before an overwrite shows.
bool mifareFactoryHeld(const uint8_t uid[4],
                       uint8_t out[MIFARE_DATA_BLOCKS_MAX][MIFARE_BLOCK_BYTES]);

// Gets a card back that a refused key has left unreachable. Returns how it
// answered: 1 = plain wake, 2 = after the reader released its target,
// 3..4 = after one or two RF field cycles, 0 = not at all. *reader_silent is
// set when a field cycle left the reader itself without an answer.
int mifareWakeCard(const uint8_t uid[4], const char* uid_str, bool* reader_silent);

// Whether sector 1 of the card on the reader opens with the factory key
// FFFFFFFFFFFF, and if so whether its data blocks hold nothing. A card that
// opens is neither Bambu's nor Creality's, so the Bambu probe can only refuse
// it - and every refusal knocks a card off the reader for a while: the main
// poll lost blank stickers within two seconds and a link made on one found
// no UID any more (13.10.2026). The card is left selectable either way.
enum MifareFactoryProbe {
  MIFARE_FACTORY_REFUSED = 0,  // other keys: the usual probes decide
  MIFARE_FACTORY_OPENS   = 1,  // factory key, but data in it, or unreadable
  MIFARE_FACTORY_BLANK   = 2,  // factory key and empty: ready for a write
};
int mifareProbeFactory(const uint8_t uid[4], const char* uid_str);
