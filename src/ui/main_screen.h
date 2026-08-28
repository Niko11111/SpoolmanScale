#pragma once

struct TagInfo;   // services/tag_write.h

void buildUI();
void updateDisplay();

// Fills material, brand, colour and temperature from the tag itself, for the
// stretch between putting a spool down and the backend answering. Everything
// the record does not carry is left alone.
//
// g_tag is deliberately not touched: half the code tells a Bambu tag from an
// NTAG by g_tag.material being filled - see querySpoolman() - and an NTAG that
// showed up there would be treated as a Bambu tag everywhere from the link
// filter to the spool the scale offers to create.
void showTagInfoOnDisplay(const TagInfo *ti);
