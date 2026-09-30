#pragma once

#include <lvgl.h>

#include "services/tag_spool_match.h"

// ============================================================
//  TAG AGAINST SPOOL, SIDE BY SIDE
//
//  The rows a question shows when the Bambu tag on the reader
//  does not describe the spool: a column for the tag, one for
//  the spool, a row for the material, one for the colour as two
//  swatches, and one for the maker where that is what differs.
//  Saying "does not match" without the two values leaves the user
//  guessing which of them is wrong. Values that differ are red.
//
//  The same rows in the link confirmation, the material warning
//  of the link by id and "More info", so the three look alike.
//  Laid out for a box 440 wide; eight to eleven objects, built
//  only when there is a difference to show.
// ============================================================

// Builds the rows into `box` from `y` down and returns their height.
int tagSpoolCompareRows(lv_obj_t* box, int y, const TagSpoolVerdict& v,
                        const char* spool_material, const char* spool_color_hex,
                        const char* spool_vendor);
