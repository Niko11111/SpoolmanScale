#pragma once

#include <stddef.h>
#include <ArduinoJson.h>

// ============================================================
//  DOES THE BAMBU TAG DESCRIBE THIS SPOOL?
//
//  A Bambu tag says what is on the spool: material, subtype and
//  colour, and through Bambu's catalog the article number. A spool
//  it is linked to should say the same. When it does not, somebody
//  linked the wrong spool, and every screen shows half of one and
//  half of the other: the home screen takes material, maker and
//  temperature from the tag, name, weight and dates from the server.
//
//  One judgement for every place that asks, so a pair that passes
//  in the link list cannot fail on the home screen or the other way
//  round: the link list, the link by id, the link from the browser,
//  the link the filament manager asks for, and the lookup after a
//  scan. Warn, never refuse: a deliberate link stays possible.
//
//  Bambu tags only. An NTAG's record is compared by tag_write.cpp.
//  No lang.h here, tag_link.cpp includes this.
// ============================================================

struct TagSpoolVerdict {
  bool material = false;   // material family or Bambu subtype differ
  bool color    = false;   // both name a colour, and they are far apart
  bool vendor   = false;   // the spool names a maker, and it is not Bambu
  bool any() const { return material || color || vendor; }
};

// The rules the link list has filtered by for months, and the browser link
// has warned by: three characters of the material, then the subtype
// ("Tough+" must not pass as plain PLA) against the spool's material or name,
// then the colour where both name one. A support tag ("Support for PLA")
// wants a "-S" spool of the base it names (PLA-S). An article number both
// sides agree on settles all of it: it names product and colour at once.
TagSpoolVerdict tagSpoolCompare(const char* tag_material, const char* tag_color_hex,
                                const char* spool_material, const char* spool_name,
                                const char* spool_vendor, const char* spool_color_hex,
                                bool article_match);

// The Bambu tag on the reader (g_tag) against a spool in Spoolman's shape,
// the way backendGetSpoolJson() and the lookup documents carry it.
// Loop task only: it asks the catalog.
TagSpoolVerdict tagSpoolCompareTag(JsonObjectConst spool);

// The article number Bambu's catalog names for the tag on the reader,
// "12601", or empty without a catalog, a hit or a Bambu tag. Loop task only.
void tagSpoolTagArticle(char* out, size_t out_size);

// For the log: "material color" and so on, empty when nothing differs.
void tagSpoolVerdictText(const TagSpoolVerdict& v, char* out, size_t out_size);

// ---- the spool the last lookup found for the Bambu tag on the reader -------
// Kept for the status line and "More info", which paint long after the
// lookup's document is gone. Loop task only.

// Judges the spool a lookup found. Does nothing but clear for anything that is
// not a Bambu tag.
void tagSpoolLookupNote(JsonObjectConst spool, int spool_id);
// A new lookup starts: nothing is known about its spool yet.
void tagSpoolLookupClear();
bool tagSpoolLookupDiffers();
const TagSpoolVerdict& tagSpoolLookupVerdict();
// The spool's side of the comparison, as the server gave it.
const char* tagSpoolLookupMaterial();
const char* tagSpoolLookupColor();
const char* tagSpoolLookupVendor();

// Which side the home screen shows while tag and spool differ: the tag's by
// default, the spool's after a tap on the status line. Back to the tag with
// every new scan; a lookup of the same spool again keeps it.
bool tagSpoolLookupShowsSpool();
// Flips it. Does nothing while tag and spool agree.
void tagSpoolLookupToggleView();
