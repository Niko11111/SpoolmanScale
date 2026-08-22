#pragma once

#include <stddef.h>

// ============================================================
//  TAG UID NORMALISATION
//
//  The scale builds a UID with colons ("04:A1:B2:C3:D4:E5:F6",
//  see app_loop.cpp), Spoolman's extra.tag stores exactly that
//  string, and BamBuddy's endpoints want plain hex. SpoolLink,
//  the Snapmaker U1 companion, writes a comma separated list of
//  plain uppercase hex UIDs into extra.card_uids instead.
//
//  Comparing those forms needs one place that reduces them all
//  to the same shape, which is what this pair does.
// ============================================================

// Spoolman extra field SpoolLink keeps the UID list in. Not created by this
// firmware and deliberately not in REQUIRED_EXTRA_FIELDS_BASE: adding it there
// would give every user an empty column they never asked for.
#define CARD_UIDS_FIELD  "card_uids"

// Hex digits only, uppercase. "04:a1:b2" and "04A1B2" both become "04A1B2".
// Always NUL terminates when out_len > 0. A value longer than the buffer is
// truncated, which can only lose a match, never invent one.
void tagUidNormalize(const char* in, char* out, size_t out_len);

// True if `uid` appears as a whole entry in a SpoolLink card_uids value.
//
// The raw value arrives as Spoolman stores extra fields, JSON encoded and
// therefore still wrapped in literal quotes:
//   "\"04A1B2C3D4E5F6,AABBCCDD\""
// Quotes and whitespace are not hex digits, so normalising each entry drops
// them without a separate stripping pass. Splitting on the comma first is what
// makes the comparison whole entry rather than substring: Spoolman's own extra
// field filter is an ilike, so a 4 byte UID would otherwise match inside a
// 7 byte one belonging to a different spool.
bool cardUidsContain(const char* card_uids_raw, const char* uid);
