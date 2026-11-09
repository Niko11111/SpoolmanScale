"""Compile the production logo key and check what a vendor name is stored under."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/label_logo.h"
#include <cassert>
#include <cstring>

static void same(const char* in, const char* want) {
  char out[LABEL_LOGO_KEY_BYTES];
  labelLogoKey(in, out, sizeof(out));
  assert(strcmp(out, want) == 0);
}

int main() {
  // The names the backend holds, and the ways the same maker is spelled.
  same("Bambu Lab", "bambulab");
  same("bambu lab", "bambulab");
  same("Bambu-Lab", "bambulab");
  same("Prusament", "prusament");
  same("3D Filament", "3dfilament");
  same("3d-filament", "3dfilament");
  same("3D  filament", "3dfilament");
  same("SUNLU", "sunlu");
  same("ColorFabb", "colorfabb");
  same("AzureFilm", "azurefilm");
  same("Prusa Polymers, s.r.o.", "prusapolymerssro");
  // Umlauts and the sharp s are spelled out, the other accents folded.
  same("Müller", "mueller");
  same("MÜLLER", "mueller");
  same("Mueller", "mueller");
  same("Straße", "strasse");
  same("Société", "societe");
  same("Crème brûlée", "cremebrulee");
  // Nothing a logo could be stored under.
  same("", "");
  same("  --  ", "");
  same("Привет", "");
  // A name longer than the key is cut; the NUL always fits.
  same("AVeryLongVendorNameIndeed", "averylongvendornameinde");
  char tiny[5];
  labelLogoKey("Bambu Lab", tiny, sizeof(tiny));
  assert(strcmp(tiny, "bamb") == 0);
  char one[1] = { 'x' };
  labelLogoKey("Bambu Lab", one, sizeof(one));
  assert(one[0] == 0);
  labelLogoKey(nullptr, tiny, sizeof(tiny));
  assert(tiny[0] == 0);
  labelLogoKey("Bambu Lab", nullptr, 0);
  return 0;
}
'''

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"), str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("label logo key: ok")
