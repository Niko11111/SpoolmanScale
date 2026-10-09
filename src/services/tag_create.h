#pragma once

#include <stddef.h>
#include <stdint.h>

// ============================================================
//  A NEW SPOOL FROM A TAG
//
//  A filament tag can say enough to create the spool it sits on: maker,
//  material and product, colour, the net weight of a full spool, the
//  diameter. What each kind of tag holds, and where the rest comes from (for
//  Bambu: the catalog on the scale, for the article number and the colour's
//  name), is the business of one input file per kind - tag_create_bambu.cpp,
//  and the next one beside it. Everything after that reads only
//  TagCreateInput and knows no maker.
//
//  Spoolman and FilaMan keep a spool under a filament, so the filament has to
//  be found first and created when the inventory does not have it yet. This
//  file holds what all three backends share for that: the input, the plan a
//  lookup produces, and the rules that decide whether a filament the server
//  already has is the one on the tag. The requests themselves live with each
//  backend (spoolman_filament.cpp, filaman_filament.cpp); nothing here
//  reaches the network or the screen.
// ============================================================

// A diameter for a tag that names none.
#define TAG_CREATE_DIAMETER_MM  1.75f
// The most colours a spool is described with: Bambu's four colour gradient.
#define TAG_CREATE_COLOURS      4

// How the colours lie on the spool.
enum TagColorKind : uint8_t {
  TCK_SINGLE = 0,
  TCK_GRADIENT,   // one colour turning into the next along the filament
  TCK_DUAL        // colours side by side across it, dual and tri colour
};

// What a tag says about its filament, in the shape the backends need.
struct TagCreateInput {
  char  vendor[32];          // "Bambu Lab"
  char  material[17];        // the base type, "PLA", "PETG"
  // "Tough+", "HF"; empty when the tag names none. A FilamentDB product line
  // ("high-speed-matte") runs to 24 bytes.
  char  subtype[32];
  char  product[24];         // "PLA Tough+"
  char  article[8];          // "12601"; empty when unknown
  char  color_name[48];      // in the UI language; empty when unknown
  char  color_name_en[48];   // English: the servers' databases are English
  char  color_hex[7];        // "009BD8", the first colour; empty for a clear one
  // Every colour of a gradient or dual colour spool, color_hex first. One
  // entry on a plain spool, none on a clear one.
  char  colors_hex[TAG_CREATE_COLOURS][7];
  uint8_t color_count;
  uint8_t color_kind;        // TagColorKind, single unless a source says otherwise
  bool  clear;               // the tag names no hue: clear filament, 00000000
  char  rgba[9];             // "009BD8FF", alpha included, for BamBuddy
  char  link_id[36];         // what the new spool is linked to the tag by
  // The maker's plain line, which the filament databases name by its colour
  // alone ("Basic" for Bambu); empty when the maker has none.
  char  plain_line[12];
  int   net_weight_g;        // filament on a full spool, 0 when unknown
  // The empty spool, 0 when unknown: the spool then counts as full, since
  // nothing can be subtracted from the reading.
  int   spool_weight_g;
  // The backend's own entry for that empty spool (BamBuddy's spool catalog),
  // 0 when none.
  int   spool_catalog_id;
  float diameter_mm;         // 0 when unknown
  int   temp_min;
  int   temp_max;
  bool  names_known;         // article and colour name are known
  // Picked from the backend's filament database (services/filament_db.h)
  // rather than read off a tag: the entry's id and name as the database has
  // them, and what it says that no tag does. Empty and 0 for a tag.
  char  db_id[80];           // SpoolmanDB ids run to 74 characters
  char  db_name[96];         // a FilamentDB designation runs to 84 bytes
  char  db_color_hex[9];     // a single colour, spelled as the database does
  float db_density;
  int   db_bed_temp;
  // The FilamentDB's own spellings, which a filament created from the entry
  // takes: the colour's name ("Cyan (12601)"), the product line
  // ("tough-plus") and the material's key ("pla"). Empty when unknown.
  char  db_color_name[64];
  char  db_line[32];
  char  db_material_key[24];
};

// A database entry found for a tag's filament (services/tag_db_match.h
// merges it into the tag's input). Only what the tag can be compared with
// or lacks.
struct TagDbEntry {
  char  id[80];              // SpoolmanDB ids run to 74 characters
  char  name[96];
  char  color_name[64];
  char  line[32];
  char  material_key[24];
  char  color_hex[7];        // the single colour, "RRGGBB"; empty when none
  char  color_raw[9];        // the same as the database spells it
  int   net_weight_g;        // 0 when unknown
  float density;
  int   nozzle_min;
  int   nozzle_max;
  int   bed_temp;
};

// Builds the input from the tag that was scanned last (g_tag), through the
// first input file that recognises it. False when none does. Loop task only.
bool tagCreateInputFromTag(TagCreateInput* out);

// For the input files: subtype from product and material ("PLA Tough+" and
// "PLA" leave "Tough+"), the colours of g_tag (its first and, on a spool with
// two, its second), and one colour more for a source that knows them all.
void tagCreateSplitProduct(TagCreateInput* in);
void tagCreateColorsFromTag(TagCreateInput* in);
void tagCreateAddColor(TagCreateInput* in, uint32_t rgb);

// The colours as "9CDBD9,FFFFFF", for the backends that take a list.
void tagCreateColorList(const TagCreateInput& in, char* out, size_t out_size);


// What a lookup found out, before anything is written.
enum TagFilamentState : uint8_t {
  TFS_FOUND = 0,       // the inventory has the filament: filament_id
  TFS_CREATE_DB,       // new, from the server's filament database
  TFS_CREATE_TAG,      // new, from what the tag and its input file know
  TFS_NOT_NEEDED,      // BamBuddy: a spool carries its filament itself
  TFS_NEEDS_CATALOG,   // not in the inventory, and no names to create it by
  TFS_FAILED           // the server could not be asked: http_code
};

struct TagFilamentPlan {
  TagFilamentState state;
  int   filament_id;        // TFS_FOUND
  int   vendor_id;          // 0: the vendor is created along with the filament
  char  name[64];           // the filament as the inventory names it
  char  external_id[80];    // Spoolman: the database entry it comes from
  // Spoolman: the entry's colours as the database spells them, which a
  // filament created from it takes, the way Spoolman's own import does.
  char  db_color_hex[9];
  char  db_multi_hexes[32];
  char  db_multi_direction[16];
  float density;            // g/cm3, Spoolman requires one
  int   spool_weight_g;     // empty spool, 0 when unknown
  int   extruder_temp;
  int   bed_temp;
  int   http_code;          // TFS_FAILED
  // A tag's filament the database knows (TFS_CREATE_DB from a tag): the
  // entry, for the card to merge in and compare (tag_db_match.h).
  bool       db_found;
  TagDbEntry db;
};

void tagFilamentPlanClear(TagFilamentPlan* plan);

// --- the rules, shared by the backends ---------------------------

// Whether text begins with word as a whole word: "Tough Cyan" begins with
// "Tough", "Tough+ Cyan" does not. Bambu sells both lines.
bool tagCreateStartsWithWord(const char* text, const char* word);

// Whether a filament name in the Spoolman style ("Tough+ Cyan", or with the
// material in front) names the tag's product. The colour is compared by the
// caller, by value.
bool tagCreateNameMatches(const char* name, const TagCreateInput& in);

// Whether the tag's product is its maker's plain line ("PLA Basic"), which
// the filament databases name by its colour alone.
bool tagCreatePlainLine(const TagCreateInput& in);

// Whether the databases name this filament by its colour alone: the plain
// line, a gradient or dual colour spool ("Arctic Whisper", "Velvet Eclipse
// (Black-Red)" in SpoolmanDB, without "Basic" or "Silk"), a clear one ("Clear").
bool tagCreateNamedByColor(const TagCreateInput& in);

// The same for FilaMan, whose FilamentDB imports keep the subtype in
// material_subgroup ("tough", "tough-plus") and in front of the designation
// ("Tough - Gray (12102)").
bool tagCreateSubgroupMatches(const char* subgroup, const char* designation,
                              const TagCreateInput& in);

// Whether text carries the article number in brackets, "Gray (12102)": how
// the FilamentDB names Bambu colours.
bool tagCreateArticleInText(const char* text, const char* article);

// Whether two colours given as hex are the same, with or without "#".
bool tagCreateSameHex(const char* a, const char* b);

// The name a new filament gets, in the style of the database each backend
// imports from, so it sits among its neighbours: Spoolman "Tough+ Cyan",
// FilaMan "Tough Plus - Cyan (12601)" in subgroup "tough-plus", with
// "Cyan (12601)" as the colour name. The plain line goes by its colour alone.
void tagCreateSpoolmanName(const TagCreateInput& in, char* out, size_t out_size);
void tagCreateFilamanColorName(const TagCreateInput& in, char* out, size_t out_size);
void tagCreateFilamanDesignation(const TagCreateInput& in, char* out, size_t out_size);
void tagCreateFilamanSubgroup(const TagCreateInput& in, char* out, size_t out_size);
