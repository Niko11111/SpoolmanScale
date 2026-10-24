#pragma once

#include <stddef.h>
#include <stdint.h>

// ============================================================
//  CREALITY CFS TAGS (K2 Plus, K2 Pro, K2 Max, Hi)
//
//  MIFARE Classic 1K. Sector 1 (blocks 4..6) holds 48 bytes, AES-128-ECB
//  encrypted with a fixed key. Its key A (and key B) is derived from the UID:
//
//    sector_key = AES-128-ECB(SECTOR_SECRET, uid4 x 4)[0..5]
//
//  Decrypted, the 48 bytes are ASCII: a 40 character record, padded with
//  spaces (or zeros, depending on who wrote it):
//
//    date(5) vendor(4) batch(2) filament(6) color(7) length(4) serial(6) reserve(6)
//    AB124   0276      A2       101001      0FFFFFF  0330      000001    000000
//
//  filament is "1" + the five character id of Creality's material database
//  (01001 = Hyper PLA). color is "0" + RRGGBB. length is the filament length
//  in metres, written as decimal digits: 0330 for 1 kg, 0165 for 500 g.
//
//  Everything here is plain C++ without Arduino or reader code, so the decoder
//  can be checked on a PC against a known tag. The reader side is in
//  creality_scan.cpp.
// ============================================================

// The 6 byte key A/B of sector 1. False only if AES itself failed.
bool crealityDeriveSectorKey(const uint8_t uid4[4], uint8_t key_out[6]);

struct CrealityTag {
  char     date[6];        // as written, not decoded: writers disagree on it
  char     vendor_id[5];   // 0276 is Creality
  char     batch[3];
  char     filament_id[7]; // the 6 characters on the tag
  char     serial[7];
  bool     has_color;
  uint8_t  r, g, b;
  uint16_t length_m;       // 0 when the field did not parse
  uint16_t weight_g;       // net filament weight derived from length_m, 0 if unknown

  // From the material table, empty when the id is not in it.
  const char* brand;       // "Creality", "Generic", "eSUN", "Polymaker"
  const char* name;        // "Hyper PLA"
  const char* material;    // "PLA", "PETG-CF"
  uint16_t temp_min, temp_max;
};

// Decrypts the three data blocks of sector 1 and parses them. False when the
// result is not a Creality record, which is what a tag that merely happened to
// authenticate with the derived key would give.
bool crealityDecode(const uint8_t sector1[3][16], CrealityTag* out);

// Exposed for the host test and for the log line.
bool crealityDecrypt48(const uint8_t in[48], uint8_t out[48]);
bool crealityParseRecord(const char* rec40, CrealityTag* out);

// ============================================================
//  WRITING (the other direction, for blank tags)
//
//  The same record FilaStation's waage.py v3.7+ writes, so a tag written by
//  either reads the same in the CFS:
//    date(5) "0276" "A2" filament(6) "0"RRGGBB length(4) serial(6) "000000"
//  The serial is the backend spool id, which is what CFSync links by.
// ============================================================

struct CrealityRecordIn {
  const char* vendor;    // "Sunlu", "Creality" - picks branded products
  const char* name;      // filament name, "Hyper PLA", "Matte PLA"
  const char* material;  // "PLA", "PETG-CF"
  const char* color_hex; // "FF6A14" or "#FF6A14"; empty = 808080
  float       net_g;     // filament on a full spool; 0 = 1 kg
  int         spool_id;  // goes into the serial, 6 decimal digits
  int         month, day, year;  // production date; 0 = fixed fallback
};

// "1" + the five character id of Creality's database. Branded products by
// vendor + name first (Creality "Hyper PLA" -> 101001), then the material
// type as a word inside material or name ("Overture Matte PLA" -> PLA),
// longest match winning, then Generic PLA.
void crealityFilamentIdFor(const char* vendor, const char* name, const char* material,
                           char out[7]);

// Filament length in metres as Creality writes it, for the nearest of
// 250/500/600/750/1000 g: "0082" ... "0330".
void crealityLengthCodeFor(float net_g, char out[5]);

// The 40 character record. False only when an argument is unusable.
bool crealityBuildRecord(const CrealityRecordIn& in, char out[41]);

// The 48 bytes for blocks 4..6: the record padded with spaces, encrypted.
bool crealityEncryptRecord(const char rec40[40], uint8_t out[48]);
