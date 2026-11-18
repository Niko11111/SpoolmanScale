#pragma once

#include "tag_create.h"

// ============================================================
//  A NEW SPOOL FROM AN OPENPRINTTAG: THE INPUT
//
//  What an OpenPrintTag (openprinttag/opt_tag.h) says about its filament, in
//  the shape every backend reads (tag_create.h). The tag names maker,
//  material, colour and its name, net weight, the empty spool, diameter,
//  temperatures, drying and density itself, so no catalog is needed. Only a
//  tag that names its maker and a colour qualifies.
// ============================================================

// False when the last scan was no OpenPrintTag, or it lacks maker or colour.
// Loop task only.
bool tagCreateInputFromOpenPrintTag(TagCreateInput* out);
