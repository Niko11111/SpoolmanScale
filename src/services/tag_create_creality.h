#pragma once

#include "tag_create.h"

// ============================================================
//  A NEW SPOOL FROM A CREALITY CFS TAG: THE INPUT
//
//  What a Creality CFS tag (creality/creality_tag.h) says about its filament,
//  in the shape every backend reads (tag_create.h). The tag names the
//  filament by Creality's id, which creality_tag.cpp resolves into maker,
//  product and material; it carries the colour, the net weight and the
//  length, but no diameter (the CFS takes 1.75 mm only) and no empty spool.
// ============================================================

// False when the last scan was no Creality tag. Loop task only.
bool tagCreateInputFromCreality(TagCreateInput* out);
