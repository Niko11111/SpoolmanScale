#include "services/label_tape_name.h"

#include <stdio.h>
#include <strings.h>

// The makers whose name the tape cannot carry next to the rest, in the form
// their owners write by hand (a D110 user, 31.10.2026: "Bambu Lab" is "BL").
struct TapeShortName { const char* full; const char* tape; };
static const TapeShortName TAPE_SHORT_NAMES[] = {
  { "Bambu Lab", "BL" }, { "BambuLab", "BL" }, { "Bambu", "BL" },
};

void labelTapeVendor(const char* vendor, char* out, size_t n) {
  if (!out || !n) return;
  out[0] = '\0';
  if (!vendor) return;
  for (const TapeShortName& s : TAPE_SHORT_NAMES)
    if (strcasecmp(vendor, s.full) == 0) { snprintf(out, n, "%s", s.tape); return; }
  snprintf(out, n, "%s", vendor);
}
