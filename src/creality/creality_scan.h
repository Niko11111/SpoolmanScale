#pragma once
#include <stdint.h>

enum CrealityScanResult {
  CREALITY_SCAN_OK,       // sector 1 opened with the UID's key and decoded
  CREALITY_SCAN_NO_AUTH,  // not a Creality tag (or not one written yet)
  CREALITY_SCAN_GARBLED,  // opened, but did not decode to a Creality record
  CREALITY_SCAN_EMPTY     // opened, and sector 1 is empty: a CFS tag erased
};

// The tag the last scan opened with the Creality key and found empty, until a
// scan of it says otherwise. Such a tag takes a CFS write like a blank one.
bool crealityTagEmpty(const uint8_t uid[4]);

// Reads sector 1 of a 4 byte MIFARE Classic tag with the key Creality derives
// from its UID and, on success, fills g_tag the way the Snapmaker decoder
// does, with g_tag.decoder set to "Creality".
// fresh: the poll has just selected the card and no key has been tried on it,
// so key A is tried straight away. Otherwise the card is woken first.
CrealityScanResult scanCrealityTag(uint8_t *uid, uint8_t uid_len, bool fresh);

// A Creality tag that was on the reader and stopped answering the polls is
// woken (release, then up to two field cycles). Same return codes as the
// "woke" in the log: 0 = no answer, 1 = plain wake, 2 = after release,
// 3/4 = after field cycles.
int crealityRecoverCard(const uint8_t uid[4], const char* uid_str);

// The 40 character plain record of the Creality tag read or written last,
// false when that was another UID.
bool crealityLastRecord(const uint8_t uid[4], char out[41]);
void crealityRememberRecord(const uint8_t uid[4], const char rec40[40]);
