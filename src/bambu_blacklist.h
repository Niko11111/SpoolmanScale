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
  nullptr  // End marker – do not remove!
};
