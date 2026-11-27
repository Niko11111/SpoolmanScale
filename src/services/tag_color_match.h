#pragma once

#include <stddef.h>
#include <stdint.h>

// ============================================================
//  A TAG'S COLOUR AGAINST A MAKER'S COLOUR TABLE
//
//  A tag that names no colour (Anycubic ACE, OpenSpool, Creality, Snapmaker)
//  carries its colour as a value only. The backend's filament database lists
//  the maker's colours with their values and names, so the nearest one can
//  lend its name - "Pink" for the 19.11.2026 Anycubic PLA Matte. A wrong name
//  is worse than none: the match is taken only when it is close and no
//  other entry of a different name comes nearly as close (the same pink as PLA and as PLA Matte). Otherwise the filament is
//  named by material and hex, as before.
//
//  Plain C++ without Arduino; the host test is test/test_tag_color_match.py.
//  Which entries are candidates (one maker, one material, loaded through
//  filament_db.h) is the caller's business.
// ============================================================

// One entry of the database, as the match needs it.
struct ColorCandidate {
  const char* hex;        // "RRGGBB", or "AARRGGBB" as SpoolmanDB spells see-through
  uint8_t     ncolors;    // 1 for a plain colour; others are never matched
  const char* name;       // "Matte Pink", "PLA Matte - Pink (A101)"
  const char* line;       // the product line where the database has one, else ""
  uint16_t    weight_g;   // filament on a full spool, 0 when unknown
};

// What the tag brings: its colour, the product line it names (Snapmaker's
// "SnapSpeed", empty for ACE), and its net weight (0 when it has none).
struct ColorQuery {
  const char* hex;
  const char* line;
  uint16_t    weight_g;
};

enum ColorMatchVerdict : uint8_t {
  CMV_NONE = 0,     // nothing close enough
  CMV_SURE,         // best is the tag's colour
  CMV_AMBIGUOUS     // two entries of different names are about as close
};

struct ColorMatch {
  ColorMatchVerdict verdict;
  int best;          // index into the candidates, -1 when none
  int runner_up;     // the next one that counts, -1 when none
  int best_dist;     // redmean distance, 0..255; -1 when nothing counted
};

// The redmean distance between two "RRGGBB" values, an approximation of how
// different they look, 0..255; -1 when either does not parse.
int tagColorDistance(const char* a, const char* b);

// Whether the candidate's product line is the one the tag names: the
// database's line, or the head of its name where it has none. Compared
// without case, spaces or dashes ("SnapSpeed", "snap-speed").
bool tagColorLineFits(const ColorCandidate& c, const char* line);

// The longest entry name kept for telling two entries apart; a FilamentDB
// designation runs to 84 bytes.
#define TCM_NAME_MAX  96

// The match as entries come in one by one, for a list that streams past
// (SpoolmanDB's light form) and is gone after each call.
struct ColorMatcher {
  ColorQuery q;
  bool       hue;              // the tag names a hue at all
  ColorMatch m;
  int        second_dist;
  char       best_name[TCM_NAME_MAX];
  char       second_name[TCM_NAME_MAX];
};

void tagColorMatchBegin(ColorMatcher* mt, const ColorQuery& q);
// Offers entry `index`. True when it is the best so far: the caller keeps
// what it needs of it, since the entry itself may be gone afterwards.
bool tagColorMatchAdd(ColorMatcher* mt, const ColorCandidate& c, int index);
ColorMatch tagColorMatchEnd(const ColorMatcher& mt);

// The same over a whole array.
ColorMatch tagColorMatch(const ColorQuery& q, const ColorCandidate* c, int n);

// Room for tagColorMatchText(): two names and the words around them.
#define TCM_TEXT_MAX  (2 * TCM_NAME_MAX + 96)
// The verdict in words, for the log: "nearest colour to #F4C0E0 is Matte
// Sakura Pink (distance 1), taken", and for a guess the other entry as well.
// Empty when no entry counted.
void tagColorMatchText(const ColorMatcher& mt, const ColorMatch& m, char* out, size_t out_size);
