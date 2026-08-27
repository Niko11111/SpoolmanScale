#pragma once

#include <stddef.h>

bool extractBambuSubtype(const char* material, char* out_kw, size_t out_size);
bool isSupportMaterial(const char* material_filter);
bool isSupportSpoolmanMat(const char* mat);
bool containsIgnoreCase(const char* haystack, const char* needle);

// Whether a filament text names the subtype a Bambu tag reports, comparing the
// two the way a human reads them: "Tough+", "Tough Plus" and "tough-plus" are
// the same thing.
//
// Its own function rather than a change to containsIgnoreCase(), which is also
// used to compare plain name fragments and must keep matching literally.
//
// Why it is needed: the tag spells the subtype "Tough+", the FilamentDB spells
// it "Tough Plus" in the designation and "tough-plus" in the subgroup. The
// literal search found neither, so every Tough+ spool was filtered out of the
// link list and the list came up empty.
bool bambuSubtypeMatches(const char* haystack, const char* subtype);
int colorDistance(const char* hex_a, const char* hex_b);
