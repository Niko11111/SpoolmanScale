#pragma once

#include "tag_create.h"

// ============================================================
//  A NEW SPOOL FROM ANOTHER MAKER'S NTAG: THE INPUT
//
//  An Anycubic ACE record or an OpenSpool record (eSun, Elegoo) on a 7 byte
//  NTAG, as the tag cache (tag_inspect.cpp) last described it. The rules
//  live in tag_create_record.cpp; this file only checks that the cached
//  record belongs to the tag on the reader and hands over its colour and
//  UID. A record this scale wrote is taken as well, and also names the
//  spool it was written for (tagOwnSpoolOnReader()).
// ============================================================

// False when the tag on the reader holds no such record. Loop task only.
bool tagCreateInputFromNtag(TagCreateInput* out);

// What a record this scale (or FilaMan) wrote says about its spool. brand and
// material point into the tag cache: read them before the next scan.
struct TagOwnSpool {
  int         spool_id;
  const char* brand;          // "" when the record names none
  const char* material;
  char        color_hex[8];   // "#RRGGBB", "" when the record names none
};
// False when the tag on the reader holds no record of the scale's own, or one
// without a spool id. Loop task only.
bool tagOwnSpoolOnReader(TagOwnSpool* out);

// Whether writing the NTAG on the reader would cost a record the scale did not
// write: a maker's (ACE, eSun's OpenSpool), one it cannot read, or one not
// read yet. "Always write" asks then all the same (Nikolai, 25.11.2026). False
// for a blank tag, one of the scale's own, and anything that is no NTAG.
// Loop task only.
bool tagOnReaderHoldsForeign();
