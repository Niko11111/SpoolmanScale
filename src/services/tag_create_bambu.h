#pragma once

#include "tag_create.h"

// ============================================================
//  A NEW SPOOL FROM A BAMBU TAG: THE INPUT
//
//  What a Bambu tag (bambu/bambu_tag.h) and the catalog on the scale
//  (bambu/bambu_catalog.h) say about the filament, in the shape every
//  backend reads (tag_create.h). The pattern for each further kind of tag.
// ============================================================

// False when the last scan was no Bambu tag read in full. Loop task only:
// the catalog is read there.
bool tagCreateInputFromBambu(TagCreateInput* out);

// A Bambu Lab spool picked from a database rather than read off a tag: the
// article number, every colour and the colour's names from the catalog, by
// in->product ("PLA Matte"), the first colour and in->color_name_en. Leaves
// the input as it is and returns false when the catalog does not know the
// colour. Loop task only.
bool tagCreateBambuFromCatalog(TagCreateInput* in);
