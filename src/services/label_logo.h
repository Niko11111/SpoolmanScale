#pragma once

#include <stddef.h>
#include <stdint.h>

#include "accent_fold.h"

// ============================================================
//  THE MAKERS' LOGOS, KEPT IN FLASH
//
//  A maker's logo is not part of the firmware: it is a trademark,
//  and the firmware is GPL. The browser fetches it once, the scale
//  keeps it in the data partition behind the filament index, and
//  a label looks it up by the vendor name it prints. The name is
//  the key: BamBuddy has no vendor object, its brand is a line of
//  free text on the spool.
//
//  The key is normalised on the scale (folding first), so the same
//  vendor always finds the same logo, whatever the browser sent.
//  A brand without a logo prints its name instead.
// ============================================================

// What a label draws: 1 bit per dot, the most significant bit of a byte its
// leftmost dot, every row padded to whole bytes.
struct LabelLogo {
  const uint8_t* bits;
  uint16_t w;
  uint16_t h;
};

// The room the logos own in the data partition, behind the filament index.
// The addresses below walk the region; the entries are 48 at the most.
#define LABEL_LOGO_BYTES        (512UL * 1024UL)
#define LABEL_LOGO_KEY_BYTES    24
#define LABEL_LOGO_MAX_W       640
#define LABEL_LOGO_MAX_H       640
#define LABEL_LOGO_MAX_BITS     (24UL * 1024UL)
#define LABEL_LOGO_MAX_COUNT    48

// One entry of the store, as the page lists it.
struct LabelLogoInfo {
  char key[LABEL_LOGO_KEY_BYTES];
  uint16_t w, h;
  uint32_t bytes;
};

// The key a vendor name is stored and looked up under: the German letters
// spelled out (ae, oe, ue, ss), the other accents folded onto their base
// letters, everything but a to z and 0 to 9 dropped, lower case. "3D Filament"
// and "3D  filament" both become "3dfilament", and a name written with an
// umlaut becomes the same key as its plain spelling. Out is n bytes and
// always ends with a NUL; a name with no letter or digit in it leaves it
// empty, and no logo is stored under an empty key.
static inline void labelLogoKey(const char* vendor, char* out, size_t n) {
  if (!out || !n) return;
  out[0] = '\0';
  if (!vendor) return;
  // The fold keeps the German letters, because the label fonts have them;
  // the key is plain ASCII and spells them out first.
  char folded[96];
  accentFold(vendor, folded, sizeof(folded));
  size_t o = 0;
  for (const char* p = folded; *p && o + 1 < n; ) {
    const char* pair = nullptr;
    if ((unsigned char)p[0] == 0xC3) {
      switch ((unsigned char)p[1]) {
        case 0x84: case 0xA4: pair = "ae"; break;   // A-umlaut, a-umlaut
        case 0x96: case 0xB6: pair = "oe"; break;   // O-umlaut, o-umlaut
        case 0x9C: case 0xBC: pair = "ue"; break;   // U-umlaut, u-umlaut
        case 0x9F:            pair = "ss"; break;   // sharp s
        default: break;
      }
    }
    if (pair) {
      if (o + 2 >= n) break;
      out[o++] = pair[0];
      out[o++] = pair[1];
      p += 2;
      continue;
    }
    char c = *p++;
    if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) out[o++] = c;
  }
  out[o] = '\0';
}

// Reads the store's index. False when it holds no logo. Every call below
// reads it on first use; a boot does not.
bool labelLogoBegin(void);
int labelLogoCount(void);
bool labelLogoAt(int i, LabelLogoInfo* out);

// The logo stored for a vendor name, null when there is none or its bits do
// not check out. The bits point at a buffer the next call may reuse: draw
// the logo before looking up another.
const LabelLogo* labelLogoFor(const char* vendor);

// Stores a logo under the vendor name, replacing the one there. False when
// it is too large, the store is full, or the flash write failed.
bool labelLogoPut(const char* vendor, const LabelLogo& logo);
bool labelLogoDrop(const char* vendor);

uint32_t labelLogoUsedBytes(void);
uint32_t labelLogoCapacityBytes(void);
