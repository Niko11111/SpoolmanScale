#pragma once

#include <stdint.h>

#include "services/tag_create.h"

// ============================================================
//  A NEW SPOOL FROM ANOTHER MAKER'S RECORD
//
//  The rules that turn what a foreign tag says - an Anycubic ACE record, an
//  OpenSpool record of eSun or Elegoo, a Snapmaker tag - into the input a
//  spool is created from. Plain C++ without Arduino or reader code, so the
//  host test (test/test_tag_create_record.py) compiles exactly this file.
//  Reading the tag, its colours and the UID it is linked by stay with the
//  input files that call this (tag_create_ntag.cpp, tag_create_snapmaker.cpp).
//
//  None of these formats names an article number or a colour: the filament
//  is named by material and hex (names_optional), unless the backend's
//  filament database knows it.
// ============================================================

// An NTAG record as tag_inspect.cpp describes it, in plain fields: TagInfo
// lives in a header that needs Arduino.
struct TagRecord {
  const char* fmt;        // "ACE", "OpenSpool"
  const char* brand;      // "AC" on an original Anycubic tag
  const char* material;   // "PLA", "PETG HF"
  const char* sku;        // ACE: "AHYGKP-101", or "SM<id>" from this scale
  int      spool_id;      // OpenSpool and FilaMan: the spool it was written for, 0 when none
  uint16_t et_lo, et_hi;  // nozzle, 0 when unknown
  uint16_t dia_x100;      // 175, 0 when unknown
  uint16_t weight_g;      // filament on a full spool, 0 when unknown
};

// Whether a scale wrote this record for a spool of its own: an ACE SKU "SM"
// followed by digits (buildAce()), an OpenSpool or FilaMan record with a
// spool id. Such a tag belongs to that spool, also when it was unlinked.
bool tagRecordIsOwn(const TagRecord& r);
// The spool such a record was written for: the digits behind "SM", or the
// spool id. 0 for a record that is not the scale's own, or names no id.
int tagRecordOwnSpoolId(const TagRecord& r);

// The maker as a database spells it: Anycubic writes "AC" on its tags.
// Empty in, empty out.
void tagCreateMakerName(const char* brand, char* out, size_t out_size);

// What a tag record holds of a maker's name at most: an ACE page run, and
// TagInfo's brand field for every record.
#define TAG_RECORD_BRAND_MAX  16

// Whether a backend's maker `name` is the maker a tag names: the same name in
// any case, or for a name cut at TAG_RECORD_BRAND_MAX the one it is the start
// of ("Polymaker Panchr" for "Polymaker Panchroma"), so a cut name does not
// file a second maker.
bool tagCreateVendorIs(const char* name, const char* vendor);

// Material, product and product line from one name: "PLA SnapSpeed" is PLA
// in the line SnapSpeed, "TPU 95A HF" is TPU in "95A HF", while "PLA-CF" and
// "PLA+" are base materials of their own and have no line.
void tagCreateMaterialAndLine(const char* name, TagCreateInput* in);

// Fills in from an ACE or OpenSpool record, the scale's own included. False
// for any other format and for one that names no material. The colours and
// link_id are left to the caller.
bool tagCreateFromRecord(const TagRecord& r, TagCreateInput* in);

// Fills in from a Snapmaker tag, its material as the decoder spells it. False
// when the material did not read or is one the decoder does not know
// ("Unknown ..."). Weight, temperatures, colours and link_id are the caller's.
bool tagCreateFromSnapmaker(const char* vendor, const char* material, TagCreateInput* in);
