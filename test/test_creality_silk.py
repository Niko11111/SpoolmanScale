"""Compile the production rule that picks a Creality filament id and read it
back for silk PLA: a material of plain PLA with a silk name gets Generic
PLA-Silk, nothing else is taken from the name (creality/creality_tag.cpp)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]

# The AES calls are not part of the rule; a stub lets the unit build on a host.
mbedtls_stub = r"""
#pragma once
#include <stddef.h>
#define MBEDTLS_AES_ENCRYPT 1
#define MBEDTLS_AES_DECRYPT 0
typedef struct { int unused; } mbedtls_aes_context;
static inline void mbedtls_aes_init(mbedtls_aes_context*) {}
static inline void mbedtls_aes_free(mbedtls_aes_context*) {}
static inline int mbedtls_aes_setkey_enc(mbedtls_aes_context*, const unsigned char*, unsigned) { return 0; }
static inline int mbedtls_aes_setkey_dec(mbedtls_aes_context*, const unsigned char*, unsigned) { return 0; }
static inline int mbedtls_aes_crypt_ecb(mbedtls_aes_context*, int, const unsigned char*, unsigned char*) { return 0; }
"""

source = r"""
#include "creality/creality_tag.h"
#include <cassert>
#include <cstring>
#include <string>

static const char* idFor(const char* vendor, const char* name, const char* material) {
  static char out[7];
  crealityFilamentIdFor(vendor, name, material, out);
  return out;
}

int main() {
  // The case that started it: Spoolman says only PLA, the name says silk.
  assert(strcmp(idFor("Geeetech", "Silk PLA Lila", "PLA"), "100002") == 0);
  // Silk after the material, and in lower case.
  assert(strcmp(idFor("Sunlu", "PLA silk Gold", "PLA"), "100002") == 0);
  // Plain and matte PLA stay plain PLA.
  assert(strcmp(idFor("Geeetech", "Basic Weiss", "PLA"), "100001") == 0);
  assert(strcmp(idFor("Overture", "Matte PLA Schwarz", "PLA"), "100001") == 0);
  // The name never overrides another material: matte PLA as PETG stays PETG,
  // and a silk name on PETG does not become silk PLA.
  // idFor() returns one static buffer, so the reference is copied first.
  const std::string petg = idFor("", "", "PETG");
  assert(petg != "100001" && petg != "100002");
  assert(petg == idFor("Overture", "Matte PLA Schwarz", "PETG"));
  assert(petg == idFor("Overture", "Silk Blau", "PETG"));
  // A Creality product keeps its own id.
  const std::string hyper = idFor("Creality", "Hyper PLA", "PLA");
  assert(hyper != "100001" && hyper != "100002");
  // Nothing known: plain PLA as before.
  assert(strcmp(idFor("", "", ""), "100001") == 0);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    (Path(tmp) / "mbedtls").mkdir()
    (Path(tmp) / "mbedtls" / "aes.h").write_text(mbedtls_stub)
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
                    "-I", tmp, "-I", str(root / "src"),
                    str(cpp), str(root / "src" / "creality" / "creality_tag.cpp"), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)
print("creality silk rule: ok")
