#pragma once

#include <stddef.h>
#include <stdint.h>

// ============================================================
//  SPOOL COLOUR
//
//  A filament colour is RGB plus how much light the filament
//  lets through. Bambu writes all four bytes to block 5 of its
//  tags, and the fourth is not decoration:
//
//    FF  opaque                     PLA Basic, PETG HF, ...
//    80  translucent                every PLA/PETG Translucent
//    00  clear, the tag names no hue  PETG Translucent Clear,
//                                   PC Transparent, PC Clear Black
//
//  Reading only three bytes turned a clear spool into a black
//  one, and a smoky translucent grey into a solid light grey.
//
//  Spoolman keeps RRGGBBAA when it knows the alpha, FilaMan and
//  BamBuddy's Spoolman mapping hand out RRGGBB. Six digits are
//  therefore opaque, which is what they meant everywhere they
//  were written.
//
//  Neither LVGL nor Arduino, so the tag parser, the backends and
//  the screens can all reach it.
// ============================================================

#define SPOOL_ALPHA_OPAQUE       0xFF
#define SPOOL_ALPHA_CLEAR        0x00

// "#RRGGBBAA" plus the terminator.
#define SPOOL_COLOR_HEX_MAX      10

// Plain data, so the structs that carry one stay memset-able: all zero is
// invalid, and nothing reads rgb or alpha of an invalid colour.
struct SpoolColor {
  uint32_t rgb;                          // 0xRRGGBB
  uint8_t  alpha;
  bool     valid;                        // false: nothing known, not black
};

// "#RRGGBB", "RRGGBB", "#RRGGBBAA" or "RRGGBBAA". Anything else, an empty
// string or a null pointer included, leaves out invalid and returns false.
bool spoolColorParse(const char* hex, SpoolColor* out);

// The four bytes of Bambu block 5, in the order the tag holds them.
SpoolColor spoolColorFromRgba(uint8_t r, uint8_t g, uint8_t b, uint8_t a);

// Lets light through: translucent or clear.
bool spoolColorSeeThrough(const SpoolColor& c);

// Carries a hue worth comparing. False for 00000000, which is how Bambu
// writes a clear filament: the zeros are not black, they are the absence
// of a colour, and a colour filter must not hold them against a spool.
bool spoolColorNamesHue(const SpoolColor& c);

// "#RRGGBB" when opaque, "#RRGGBBAA" otherwise, empty when invalid.
void spoolColorFormat(const SpoolColor& c, char* out, size_t out_size);

// The same without the '#', the form BamBuddy and Spoolman store.
void spoolColorFormatBare(const SpoolColor& c, char* out, size_t out_size);

// The colour a Bambu spool is shown in. The tag wins wherever it names a hue:
// it is the manufacturer's value, identical on every spool of that product,
// while a server colour is typed in by hand and often a placeholder. The
// server fills only what the tag leaves open - an unread colour block, or a
// clear filament, where it may know the tint the tag cannot express. Bambu
// writes "PC Clear Black" and "PC Transparent" identically.
//
// A clear spool stays see-through whatever the server says: the tag has
// already said that much for certain.
SpoolColor spoolColorResolve(const SpoolColor& tag, const SpoolColor& server);
