#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "../services/spool_color.h"

// ============================================================
//  THE BAMBU CATALOG
//
//  A Bambu tag names its filament by two codes, "GFA10" and "A10-B0", and
//  says nothing a person would call it. BambuStudio keeps the table that
//  turns the pair into a product: filaments_color_codes.json, one entry per
//  colour with the article number Bambu sells it under ("12601", the number
//  Spoolman's article_number holds for the same spool) and the colour's name
//  in twelve languages.
//
//  The scale downloads that table itself, from BambuStudio's repository - it
//  is not shipped with the firmware, whose licence is not BambuStudio's. What
//  it keeps is a compact copy in the data partition, behind the log ring: 318
//  colours come to about 20 kB there.
//
//  When: on request from the tags page, and on its own a few minutes after
//  boot and then once a day, while the automatic update check is switched on
//  (bambu_catalog_sync.h). That daily request is conditional: while the file
//  is unchanged GitHub answers 304 and nothing is downloaded or written. With
//  the update check off, nothing is fetched unless someone asks.
// ============================================================

// Where the catalog lives: straight after the log ring's 512 kB.
#define BAMBU_CATALOG_BYTES   (64UL * 1024UL)

// How the colours of a spool lie on it.
enum BambuColorKind : uint8_t {
  BCK_SINGLE = 0,
  BCK_GRADIENT,   // one colour turning into the next along the filament
  BCK_DUAL        // two or three colours side by side across it
};

// The most colours one entry of the table names.
#define BAMBU_CATALOG_COLOURS  4

// What the catalog knows about one colour of one product.
struct BambuCatalogHit {
  char article[8];      // "12601"
  char product[24];     // "PLA Tough+"
  char color_name[48];  // in the UI language, English where the table has none
  // English always: what Spoolman's and FilaMan's filament databases call it.
  char color_name_en[48];
  uint8_t  kind;                            // BambuColorKind
  uint8_t  ncol;                            // 1 for a plain colour
  uint32_t rgba[BAMBU_CATALOG_COLOURS];     // 0xRRGGBBAA, the first colour first
};

// Looks the tag's two codes up, and its colour where the codes alone do not
// settle it. False when there is no catalog, or it does not know the pair.
// Loop task only.
bool bambuCatalogFind(const char* material_id, const char* variant_id,
                      const SpoolColor& color, BambuCatalogHit* out);

// The other way round, for a spool picked from a database rather than read
// off a tag: one colour of one product ("PLA Matte"), by its first colour
// (0xRRGGBB) and, where no entry has exactly that, by its English name. Case
// aside. False when there is no catalog or no entry fits. Loop task only.
bool bambuCatalogFindByLook(const char* product, uint32_t rgb, const char* name_en,
                            BambuCatalogHit* out);

// The installed catalog: how many colours, and when it was downloaded (UTC
// seconds, 0 when the clock was not set). Count 0 when there is none.
// Loop task only.
int      bambuCatalogCount();
uint32_t bambuCatalogStamp();

enum BambuCatalogOutcome : uint8_t {
  BCO_FAILED = 0,
  BCO_UPDATED,     // downloaded and stored
  BCO_UNCHANGED    // GitHub answered 304: the stored copy is current
};

// Downloads the table, converts and stores it. Blocks for seconds: the web
// worker's task, never the loop. conditional sends the stored copy's ETag,
// so an unchanged file costs a 304 and no download; the button on the tags
// page asks without it. count gets the colours stored.
BambuCatalogOutcome bambuCatalogDownload(bool conditional, char* err, size_t err_len,
                                         int* count);

// The conversion and the store on their own, for a table already parsed -
// the download above, and the simulator, which reads a local copy. etag may
// be empty; the next conditional check then downloads once.
bool bambuCatalogStore(JsonArrayConst entries, uint32_t stamp, const char* etag,
                       char* err, size_t err_len, int* count);

// When a download or a check last reached GitHub (UTC seconds, 1 when the
// clock was not set), once; 0 when nothing happened since the last call. The
// loop keeps it, see bambu_catalog_sync.h.
uint32_t bambuCatalogTakeChecked();
