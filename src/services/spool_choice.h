#pragma once

#include <stddef.h>
#include <stdint.h>

#include "services/spool_start.h"

// ============================================================
//  THE EMPTY SPOOL A NEW SPOOL IS WEIGHED AGAINST
//
//  A refill wound onto another maker's spool, filament respooled onto a
//  spool of its own, a printed spool, or a maker with several spools: the
//  card that creates the spool weighs it against what the inventory knows
//  for its filament and maker, and that is the wrong spool. Under Options
//  the user picks the right one: from the last two picked, from the makers'
//  spools SpoolmanDB lists (built in, services/spool_catalog_data.h), or by
//  typing the weight.
//
//  A choice belongs to the one spool being created. It is written to that
//  spool only, never to its filament or maker, where it would become the
//  default for every spool of theirs. Pure logic: no NVS, no screen, no
//  network (test/test_spool_choice.py).
// ============================================================

// What a spool is made of, as SpoolmanDB names it. Numbered as the generator
// writes it (tools/gen_spool_catalog.py).
enum SpoolKind : uint8_t {
  SPOOL_KIND_ANY = 0,      // the entry names none
  SPOOL_KIND_PLASTIC,
  SPOOL_KIND_CARDBOARD,
  SPOOL_KIND_METAL
};

// One empty spool of a maker in the built-in catalog.
struct SpoolCatalogSpool {
  uint8_t  kind;      // SpoolKind
  uint16_t weight_g;  // the empty spool
  uint16_t net_g;     // the filament it is sold with, 0 when unknown
};

struct SpoolCatalogMaker {
  const char* name;
  uint16_t    first;  // index of its first spool
  uint8_t     count;
};

// Where a choice came from.
enum SpoolChoiceSource : uint8_t {
  SCS_AUTO = 0,   // nothing chosen: the card's own chain decides
  SCS_CATALOG,    // a maker's spool from the built-in catalog
  SCS_TYPED,      // typed in on the pad
  SCS_MINE,       // one of the user's own, kept on the scale (web page "Empty spools")
  SCS_SERVER      // the backend's: a vendor's or manufacturer's, BamBuddy's catalog
};

#define SPOOL_CHOICE_NAME_MAX  32
// How many earlier choices the list offers first.
#define SPOOL_RECENT_MAX       2
// What one choice takes as text in NVS: "189|1|2|1000|0|" plus the name.
#define SPOOL_CHOICE_TEXT_MAX  (SPOOL_CHOICE_NAME_MAX + 32)
// The user's own empty spools: how many, and the weights the web page takes.
#define SPOOL_MINE_MAX         12
#define SPOOL_MINE_MIN_G       10
#define SPOOL_MINE_MAX_G       2000
// The backend's empty spools the list shows, and how many it reads to pick them.
#define SPOOL_SERVER_MAX       12
#define SPOOL_SERVER_READ_MAX  48
// All of them as NVS text, one line each.
#define SPOOL_MINE_TEXT_MAX    (SPOOL_MINE_MAX * SPOOL_CHOICE_TEXT_MAX)

struct SpoolChoice {
  uint16_t weight_g;    // the empty spool; 0 while nothing is chosen
  uint16_t net_g;       // the filament such a spool carries, 0 when unknown
  uint8_t  source;      // SpoolChoiceSource
  uint8_t  kind;        // SpoolKind
  // BamBuddy's own entry for the spool in its spool catalog, 0 for none.
  int      catalog_id;
  char     name[SPOOL_CHOICE_NAME_MAX];   // the maker; empty for a typed weight
};

void spoolChoiceClear(SpoolChoice* c);
bool spoolChoiceActive(const SpoolChoice& c);
// The same spool: weight, kind and maker alike.
bool spoolChoiceSame(const SpoolChoice& a, const SpoolChoice& b);

// The empty spool a card weighs against: the choice when one was made, which
// someone looked up or weighed, else the chain's own value, `from` and
// `quality` left as the chain set them.
int spoolChoiceTare(const SpoolChoice& c, int chain_g, uint8_t* from, TareQuality* quality);

// --- the built-in catalog ---------------------------------------

int spoolCatalogMakerCount();
const char* spoolCatalogMakerName(int maker);   // "" outside the range
int spoolCatalogSpoolCount(int maker);          // 0 outside the range
// The k-th spool of a maker, the most common first. False outside the range.
bool spoolCatalogChoice(int maker, int k, SpoolChoice* out);
// The maker by name, ignoring case and anything but letters and digits
// ("Bambu Lab" finds "BambuLab"); -1 when the catalog has none.
int spoolCatalogFindMaker(const char* name);

// --- the last choices -------------------------------------------

// Puts a choice in front of the list; the same spool further down goes, the
// oldest falls off the end.
void spoolRecentPush(SpoolChoice list[SPOOL_RECENT_MAX], const SpoolChoice& c);
// One choice as a line of text for NVS, and back. Decode refuses a line it
// cannot read whole, and an inactive choice.
bool spoolChoiceEncode(const SpoolChoice& c, char* out, size_t out_size);
bool spoolChoiceDecode(const char* text, SpoolChoice* out);

// --- the user's own ----------------------------------------------

// Whether a name and weight make one of the user's own: a name of 1 to 31
// bytes without '|' or a line break, and SPOOL_MINE_MIN_G to _MAX_G.
bool spoolMineValid(const char* name, int weight_g);
// One of them as a choice (SCS_MINE). False when not valid.
bool spoolMineMake(const char* name, int weight_g, SpoolChoice* out);
// All of them as text, one line per spool, and back. Decode skips a line it
// cannot read and stops at SPOOL_MINE_MAX; it returns how many it took.
bool spoolMineEncode(const SpoolChoice* list, int n, char* out, size_t out_size);
int spoolMineDecode(const char* text, SpoolChoice out[SPOOL_MINE_MAX]);

// --- the backend's ----------------------------------------------

// The server's empty spools as the list shows them, at most `max`: those of
// the card's maker first (a name that starts with it, "Sunlu 250g - Plastic"
// for Sunlu), then the rest in their order; the same spool once. Returns how
// many it wrote.
int spoolServerPick(const SpoolChoice* all, int n, const char* maker, SpoolChoice* out, int max);
