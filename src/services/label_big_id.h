#pragma once

#include <lvgl.h>

#include "services/label_facts.h"
#include "services/label_layout.h"
#include "services/label_render.h"

// ============================================================
//  THE LABEL THAT IS READ FROM ACROSS THE ROOM
//
//  The arrangements for picking a spool by its number in Fluidd or
//  Mainsail: no code, the number large, across the top with the
//  rest under it or on the right with the rest beside it (issue
//  #64). LabelLayout::id_share moves the two against each other.
//  What a number too wide to grow leaves over, the lines take,
//  each as large as its share of the height and the width allow.
// ============================================================

// The part of the canvas to fill, in dots.
struct BigIdBox { lv_coord_t x, y, w, h; };

// `lines` are the fact lines and `facts` the same n as caption and value; the
// maker, the material and the name come from `d` where `layout` keeps them.
struct BigIdContent {
  const SpoolLabelData* d;
  const LabelLayout* layout;
  const char* const* lines;
  const LabelFact* facts;
  int n;
};

void labelDrawBigId(lv_obj_t* canvas, const BigIdBox& box, const BigIdContent& c);
// The smallest share, in LABEL_ID_SHARE_STEP steps, at which this number is as
// large as it gets on this label: above it the share changes nothing, the width
// or the height is used up. 0 when no share applies, with no number to draw or
// nothing beside it.
int labelBigIdShareLimit(const BigIdBox& box, const BigIdContent& c);
