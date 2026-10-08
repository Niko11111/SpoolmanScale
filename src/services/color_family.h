#pragma once

#include <stdint.h>

// ============================================================
//  COLOUR FAMILIES
//
//  A maker's filaments of one material can be long: SpoolmanDB lists 148
//  Bambu Lab PLA and 224 Polymaker PLA (08.10.2026). A spool in hand has a
//  colour anyone can name at a glance, so the pick list is cut by that
//  first: 148 become at most 24 per family. The family comes from the
//  colour's value alone, so it is the same on every backend and needs no
//  name in any language. Pure arithmetic, no screen, no network.
// ============================================================

// In the order the picker shows them: the hue circle, then the greys, then
// what has no single hue.
enum ColorFamily : uint8_t {
  CF_RED = 0,
  CF_ORANGE,
  CF_YELLOW,
  CF_GREEN,
  CF_BLUE,
  CF_PURPLE,
  CF_PINK,
  CF_BROWN,
  CF_BLACK,
  CF_GREY,
  CF_WHITE,
  CF_MULTI,    // two colours or more on one spool
  CF_CLEAR,    // no hue at all: clear, or no colour known
  CF_COUNT
};

// The family of a colour given as "RRGGBB" or "RRGGBBAA", with or without
// "#". ncolors above 1 is CF_MULTI whatever the first colour is. A missing or
// unreadable colour is CF_CLEAR, and so is one that is mostly see-through and
// has no hue; a see-through colour with a hue stays with its hue.
ColorFamily colorFamilyOf(const char* hex, uint8_t ncolors);

// How well a colour stands for its family, 0..1000: the strongest hue for a
// hue, the darkest black, the lightest white, the most neutral grey. The
// picker paints a family in its most typical member, not in the first one
// the alphabet brings ("Apricot" for orange). 0 for an unreadable colour.
int colorFamilyTypicality(const char* hex, ColorFamily family);
