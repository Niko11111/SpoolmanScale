#pragma once

#include <stddef.h>
#include <stdint.h>

#include "color_family.h"
#include "tag_create.h"

// ============================================================
//  THE FILAMENT DATABASE, AS THE PICKER SEES IT
//
//  A spool without a maker's chip gets its filament from the backend's
//  filament database instead: SpoolmanDB behind Spoolman, the FilamentDB
//  behind FilaMan. The picker asks maker, material, product line and colour,
//  and each step needs only what this file holds:
//
//  - the index: every maker, and every material each one has, with counts
//    (SpoolmanDB: 67 makers, 6283 filaments of 1.75 mm, 08.10.2026). The
//    FilamentDB names 311 makers but no materials per maker: those come with
//    a load of their own when a maker is tapped (FDB_JOB_PAIRS);
//  - the entries of one maker and material, with everything a new filament
//    needs (SpoolmanDB Polymaker PLA, the longest: 224 names; FilamentDB
//    Polymaker PLA: 537 entries).
//
//  Both are loaded on a task of their own on core 0: the index is the whole
//  database, 3 MB, read once and boiled down to a few kB. The loop starts a
//  load, keeps running, and collects it on a later pass, the way
//  backend_job.h does for the spool list. What is loaded is held in PSRAM -
//  the index for a day, the entries until fdbReleaseEntries() - and belongs
//  to the backend generation it was loaded under. The index is also kept in
//  flash for a week (filament_db_store.h), so a restart does not read the
//  3 MB again. How each backend fills it is its own business, behind
//  backend_api.h; nothing in here talks to a server or the screen.
// ============================================================

// Room for the index and one list. SpoolmanDB has 67 makers and 299 pairs of
// maker and material, the FilamentDB 311 makers (09.10.2026); the longest
// list, FilamentDB Polymaker PLA, is 537 entries. An entry is about 260
// bytes, the full list 156 kB of PSRAM.
#define FDB_MAKERS_MAX      400
#define FDB_PAIRS_MAX       640
#define FDB_ENTRIES_MAX     600
// A name in SpoolmanDB is at most 58 bytes, a FilamentDB designation 84
// (09.10.2026).
#define FDB_NAME_MAX        96
// A FilamentDB product line, "high-speed-matte": at most 24 bytes.
#define FDB_LINE_MAX        25
// The diameter the picker offers, and how close an entry has to be to it.
#define FDB_DIAMETER_MM     1.75f
#define FDB_DIAMETER_TOL_MM 0.02f

struct FdbMaker {
  char     name[32];
  uint16_t count;        // filaments of the diameter, all materials
  bool     owned;        // the inventory already has spools by this maker
  // Its materials are in the index. In the byte that was padding: the
  // record stays 36 bytes, and a stored index sets it on restore.
  bool     pairs_known;
};

struct FdbPair {
  uint16_t maker;        // index into the makers
  char     material[17];
  uint16_t count;
};

// One filament of the database, in one weight.
struct FdbEntry {
  char     id[80];       // SpoolmanDB ids run to 74 characters
  char     name[FDB_NAME_MAX];   // "Tough+ Cyan", "Aero - Black (14103)"
  // The product line as the database spells it ("aero", "---other---"),
  // empty where the database has none (SpoolmanDB). The picker asks for it
  // when a list has two or more.
  char     line[FDB_LINE_MAX];
  // Where the colour's name begins in name: the FilamentDB puts the line in
  // front, "Aero - Black (14103)" from 7 on. 0 when the name is all colour.
  uint8_t  color_at;
  char     hex[TAG_CREATE_COLOURS][7];   // "RRGGBB", for the screen
  // The single colour as the database spells it, which a filament created
  // from the entry takes over: SpoolmanDB writes see-through as AARRGGBB.
  char     db_hex[9];
  uint8_t  ncolors;      // 0 for a clear one
  uint8_t  kind;         // TagColorKind
  uint8_t  family;       // ColorFamily
  uint16_t weight_g;     // filament on a full spool, 0 when unknown
  uint16_t spool_weight_g;
  float    density;
  int16_t  extruder_temp;
  int16_t  bed_temp;
};

enum FdbJob : uint8_t { FDB_JOB_NONE = 0, FDB_JOB_INDEX, FDB_JOB_ENTRIES, FDB_JOB_PAIRS };
enum FdbState : uint8_t { FDB_IDLE = 0, FDB_RUNNING, FDB_DONE };

// ---- loading, from the loop task ---------------------------------

// Starts loading the index, or the entries of one maker and material. False
// when a load is running, the heap is too low for its task, or the task
// could not be created; the caller tries again on a later pass.
bool fdbStartIndex();
bool fdbStartEntries(const char* maker, const char* material);
// The materials of one maker, for a database whose index names makers only
// (the FilamentDB). They stay with the index.
bool fdbStartPairs(const char* maker);

FdbState fdbState();
FdbJob   fdbJob();
// Bytes read so far, for the waiting card.
size_t   fdbBytes();
// Valid once the state is FDB_DONE: the HTTP code (200, or the backend's
// own, BACKEND_NOT_SUPPORTED among them) and whether the backend generation
// is still the one the load began under.
int      fdbResultCode();
bool     fdbResultCurrent();
// Hands the slot back for the next load. What was loaded stays.
void     fdbTake();

// Whether the picker can be offered: a backend with a filament database, and
// not one that has already answered that it has none (an older Spoolman,
// 404). Asked again after a switch of backend or host.
bool fdbOffered();

// Whether the index is loaded, for this backend, and young enough. It stays
// between two openings of the picker (about 20 kB of PSRAM), and comes back
// from flash after a day or a restart; the 3 MB are read once a week.
bool fdbIndexReady();
// Drops the entries and gives their PSRAM back (up to 114 kB). When the
// picker closes.
void fdbReleaseEntries();

// ---- reading, from the loop task once a load is taken ------------

int             fdbMakerCount();
const FdbMaker* fdbMaker(int i);
// The pairs of one maker, by count, most first. Returns how many were
// written to out (indices into fdbPair()).
int             fdbPairsOf(int maker, uint16_t* out, int out_max);
// Whether the maker's materials are known: always with SpoolmanDB, after
// fdbStartPairs() with the FilamentDB.
bool            fdbMakerHasPairs(int maker);
const FdbPair*  fdbPair(int i);
int             fdbEntryCount();
const FdbEntry* fdbEntry(int i);

// The entry's name as the screen shows it: without the trademark signs the
// fonts do not have (995 SpoolmanDB names carry a ™), without a "(Formerly
// ...)" note, and without the maker and the material, which the list's
// title already names - "Panchroma™ (Formerly PolyLite™) Silk Blue" in the
// PLA list is "Panchroma Silk Blue". Accents the fonts lack fall back to the
// plain letter. The server keeps the name as the database spells it.
void fdbDisplayName(const char* name, const char* maker, const char* material,
                    char* out, size_t out_size);
// The same for one entry: a FilamentDB entry shows the colour's name alone,
// since maker, material and product line are picked already.
void fdbEntryDisplayName(const FdbEntry& e, const char* maker, const char* material,
                         char* out, size_t out_size);
// The product line as a tile names it: the FilamentDB's own spelling in
// front of the colour ("Panchroma Matte", "95A"), else the slug in words
// ("basic" is "Basic"); other_text for "---other---".
void fdbLineName(const FdbEntry& e, const char* other_text, char* out, size_t out_size);

// Fills a new spool's input from one entry, maker and material.
void fdbEntryToInput(const FdbEntry& e, const char* maker, const char* material,
                     TagCreateInput* in);

// ---- filling, for the backend's loader on the job's task ---------

void fdbIndexAdd(const char* maker, const char* material);
// A maker without its materials yet, counted as the database counts it.
void fdbMakerAdd(const char* maker, uint16_t count);
// Marks a maker the inventory has. Case does not matter.
void fdbMarkOwned(const char* maker);
// False once the list is full.
bool fdbEntryAdd(const FdbEntry& e);
// Whether the list has the entry's name in its weight already: the same
// filament on a cardboard and a plastic spool is one choice.
bool fdbEntryListed(const FdbEntry& e);
// A byte count the loader keeps up to date.
volatile size_t* fdbBytesCounter();

// ---- the stored index (filament_db_store.h), on the job's task --

// The index being loaded, as it lies, to keep in flash. Returns the makers.
int  fdbIndexSnapshot(const FdbMaker** makers, const FdbPair** pairs, int* pair_n);
// Puts a stored index in place of the one being loaded, owned cleared: the
// inventory is asked again. False when it does not fit.
bool fdbIndexRestore(const FdbMaker* makers, int maker_n, const FdbPair* pairs, int pair_n);
