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

// Buffer size for a whole list. Holds twelve 7 byte UIDs; a spool has two.
// A value that does not fit is dropped rather than shortened, everywhere.
#define CARD_UIDS_MAX  192

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

// How many entries the list holds. Empty entries do not count, so a hand
// edited "A,,B" and a trailing comma both answer 2 and 1.
int cardUidsCount(const char* card_uids_raw);

enum CardUidsResult {
  CARD_UIDS_ADDED,            // uid was appended, `out` holds the new list
  CARD_UIDS_ALREADY_PRESENT,  // uid was in the list, `out` holds it unchanged
  CARD_UIDS_FULL              // would not fit, `out` holds the list unchanged
};

// Appends `uid` to the list, normalised to plain uppercase hex.
//
// Existing entries are carried over verbatim. Canonicalising them on the way
// is tempting - it would repair a hand typed colon form for the server side
// filter - but it would equally mangle anything in the field that is not a UID
// at all. Only the entry we add is ours to write.
//
// Never truncates. If the result does not fit, CARD_UIDS_FULL comes back and
// `out` holds the unchanged list, because a shortened list would silently drop
// somebody else's tag. Callers must not write on FULL.
//
// Both functions accept the raw field value with Spoolman's outer JSON quotes
// as well as an already cleaned one, and always produce a cleaned result.
CardUidsResult cardUidsAppend(const char* current, const char* uid,
                              char* out, size_t out_len);

// Removes `uid` from the list, comparing normalised. Returns false when it was
// not in there, in which case `out` still holds the unchanged list.
bool cardUidsRemove(const char* current, const char* uid,
                    char* out, size_t out_len);
