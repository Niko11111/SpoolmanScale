// ============================================================
//  SpoolmanScale – Bambu PLA Subtype Blacklist
//  bambu_blacklist.h
//
//  If Bambu Lab releases a new PLA product line with its own
//  subtype (e.g. "PLA Gradient"), simply add the name here.
//  Matching is case-insensitive.
//
//  Background: During the Bambu Link/Copy flow, the part after
//  the first space or dash in the tag material string
//  (e.g. "PLA Basic" -> "Basic") is extracted as a subtype.
//  If that subtype is found in this list, it is actively
//  matched against the filament name in Spoolman.
//  If it is NOT in this list (e.g. "Basic"), no subtype filter
//  is applied and the color filter handles narrowing instead.
// ============================================================
#pragma once

static const char* const BAMBU_PLA_SUBTYPE_BLACKLIST[] = {
  "Matte",
  "Silk",
  "Glow",
  "Sparkle",
  "Tough+",
  "Translucent",
  "Luminous",
  "Galaxy",
  "Metal",
  "Marble",
  // Bambu's newer PLA line. Added from the naming pattern of the entries
  // above, not from a tag that was actually read - unlike the rest of this
  // list. If the tag turns out to say something else, this entry simply never
  // matches and the colour filter narrows the list on its own, exactly as it
  // does today.
  "Pure",
  nullptr  // End marker – do not remove!
};
