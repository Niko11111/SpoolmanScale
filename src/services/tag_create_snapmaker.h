#pragma once

#include "tag_create.h"

// ============================================================
//  A NEW SPOOL FROM A SNAPMAKER TAG: THE INPUT
//
//  What the Snapmaker decoder (snapmaker/snapmaker_scan.cpp) put into g_tag:
//  maker, material with its line ("PLA SnapSpeed"), colour, the net weight
//  and the nozzle range. No diameter and no empty spool. Told from the other
//  MIFARE tags by the tag cache, which names it the way the tag view does.
// ============================================================

// False when the last scan was no Snapmaker tag. Loop task only.
bool tagCreateInputFromSnapmaker(TagCreateInput* out);
