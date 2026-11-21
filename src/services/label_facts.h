#pragma once

#include "services/label_layout.h"
#include "services/label_render.h"

// ============================================================
//  THE FACTS ON A LABEL
//
//  The small lines under the header: which of a spool's facts the
//  layout puts on, in which order, each as a caption and a value
//  and as the one line that joins them. No drawing here; the
//  renderer decides how large they come out.
// ============================================================

#define LABEL_MAX_FACTS 6    // every fact line on, the maker among them

// One fact as its caption and its value; either may be missing (the maker
// has no caption, the project name no value).
struct LabelFact { const char* caption; const char* value; };

// The facts with the text they point to: captions are the language table's,
// values are copied in here.
struct LabelFactList {
  LabelFact facts[LABEL_MAX_FACTS];
  char values[LABEL_MAX_FACTS][LABEL_LINE_LEN];
  char lines[LABEL_MAX_FACTS][LABEL_LINE_LEN + 16];
  const char* line_ptrs[LABEL_MAX_FACTS];
  int n;
};

// A spool's facts as the layout has them, no more than `capacity` lines: the
// first ones in the page's order stay, the rest is left off.
void labelSpoolFacts(const LabelLayout& layout, const SpoolLabelData& spool, int capacity,
                     LabelFactList* out);
// The same for the filament's label: only what belongs to the filament.
void labelFilamentFacts(const LabelLayout& layout, const SpoolLabelData& spool, int capacity,
                        LabelFactList* out);
// True when the colour line made it into the list, within its budget.
bool labelFactsHaveColor(const LabelFactList& facts);
