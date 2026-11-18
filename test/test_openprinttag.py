"""Host test for src/openprinttag/opt_tag.cpp and cbor_reader.cpp: the format's
own test vectors decode to the values the reference implementation prints.

The vectors are taken from prusa3d/OpenPrintTag at 060e420 (MIT licence,
Copyright 2025 Prusa Research a.s.): docs_src/sample_data/sample_tag.bin and
tests/encode_decode/0N_data.bin, trailing zero bytes cut. Expected values from
the matching data_to_fill.yaml and 0N_info.yaml.
"""

import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]

SAMPLE = (
    "e140260103ff0127c21c000001056170706c69636174696f6e2f766e642e6f70656e7072696e74746167a10218e2bf00"
    "50473bb8cde12945b89fcfda1c3add9c47076131080009000a70504c412047616c61787920426c61636b0b6950727573"
    "616d656e740e1a67acb31a101903e8111903f412186413433d3e3d181bf93266181c9f17ff182218cd182318dc182418"
    "aa182518281826183c18281828182914182a184bff000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000"
    "000000000000000000000000000000fe"
)

V01 = (
    "e140270103ff012f910117550433647461672e6f72672f732f33333463353466303838521cf56170706c69636174696f"
    "6e2f766e642e6f70656e7072696e74746167a10218d2bf041b000007d0fcab45f9056a33333463353466303838080009"
    "000a76504c412050727573612047616c61787920426c61636b0b6950727573616d656e740e1a68d3c7d7101903e81119"
    "03f41219011813443d3e3dff181c9f17ff181df93cf6182218cd182318e1182418aa182518281826183c182712182818"
    "28182914182a1840182b18c8182c1864182d183418389f0001ff183b831832fa4134cccdfa43014ccd183c6932373020"
    "3330203230ff000000000000000000000000000000000000000000000000000000000000a00000000000000000000000"
    "0000000000000000000000000000000000000000000000fe"
)

V03 = (
    "e140270103ff012fc21c0000010d6170706c69636174696f6e2f766e642e6f70656e7072696e74746167a10218eabf04"
    "1b000007d0fcab465c056a37616232616362353039080009010a6e50455447204a657420426c61636b0e1a68c01ae710"
    "1903e81119041a12190118134324292a181c9fff181df93d14182218f0182318d2182419012c182518461826185a1827"
    "185a1828183c18291823182a1840182b18c8182c1864182d18d2ff000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000bf001901bc01666d79686f6d"
    "65ff000000000000000000000000000000000000000000fe"
)

V04 = (
    "e140270103ff012f91010d5502336478746563682e636f6d2f521cff6170706c69636174696f6e2f766e642e6f70656e"
    "7072696e74746167a10218dcbf080009150a7819436172626f6e582050454b4b2d412b4346313520426c61636b0b6733"
    "4458546563680e1a690c5d9b101902ee111902f4121901361343303030181c9f04181f181eff181df93d8f1821f93666"
    "18221901681823190186182518781826188c1827183c1828188c1829185a182a183d182b18c6182c1864182d18351834"
    "6750454b4b2d434618361a000372d0ff0000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000"
    "0000000000000000000000000000000000000000000000fe"
)

V05 = (
    "e140270103ff012fc21c0000010d6170706c69636174696f6e2f766e642e6f70656e7072696e74746167a10218eabf08"
    "00181bfb4014666666666666181c9f171924d5ff19ffff6474657374ff00000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000"
    "0000000000000000000000000000000000000000000000fe"
)


def c_array(name, hexstr):
    data = bytes.fromhex(hexstr)
    body = ", ".join(f"0x{b:02X}" for b in data)
    return f"static const uint8_t {name}[] = {{{body}}};\n"


CPP = r"""
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include "openprinttag/opt_tag.h"
#include "openprinttag/cbor_reader.h"
#include "vectors.h"

static bool near(float a, float b) { return fabsf(a - b) < 0.01f; }

// Reads a vector the way the reader does: the CC says how much, the rest is
// zero, as on a fresh tag.
static OptResult decode(const uint8_t* v, size_t n, OptTag* t) {
  static uint8_t mem[OPT_MEMORY_MAX];
  memset(mem, 0, sizeof(mem));
  memcpy(mem, v, n);
  const size_t size = optMemorySize(mem);
  assert(size > 0 && size <= OPT_MEMORY_MAX);
  return optDecodeMemory(mem, size, t);
}

static void sampleTag() {
  OptTag t;
  assert(decode(SAMPLE, sizeof(SAMPLE), &t) == OPT_OK);
  assert(strcmp(t.brand, "Prusament") == 0);
  assert(strcmp(t.material_name, "PLA Galaxy Black") == 0);
  assert(t.material_class == 0 && t.material_type == 0);
  assert(strcmp(optMaterialAbbr(t), "PLA") == 0);
  assert(t.color_count == 1 && t.colors[0][0] == 0x3D && t.colors[0][1] == 0x3E &&
         t.colors[0][2] == 0x3D && t.colors[0][3] == 0xFF);
  assert(near(t.nominal_weight_g, 1000) && near(t.actual_weight_g, 1012));
  assert(near(t.container_weight_g, 100));
  assert(t.print_min_c == 205 && t.print_max_c == 220 && t.preheat_c == 170);
  assert(t.bed_min_c == 40 && t.bed_max_c == 60);
  assert(t.tag_count == 1 && t.tags[0] == 23);          // glitter
  assert(near(t.diameter_mm, 1.75f));                    // not on the tag: the default
  assert(t.manufactured == 1739371290);
  char date[12];
  optFormatDate(t.manufactured, date, sizeof(date));
  assert(strcmp(date, "2025-02-12") == 0);
  assert(near(optRemainingG(t), 1012));                  // nothing consumed yet
}

// URI record first, then ours; GTIN in 8 bytes, half-float density.
static void vector01() {
  OptTag t;
  assert(decode(V01, sizeof(V01), &t) == OPT_OK);
  assert(strcmp(t.brand, "Prusament") == 0);
  assert(strcmp(t.material_name, "PLA Prusa Galaxy Black") == 0);
  assert(t.gtin == 8594173675001ULL);
  assert(strcmp(t.instance_id, "334c54f088") == 0);
  assert(near(t.container_weight_g, 280) && near(t.actual_weight_g, 1012));
  assert(near(t.density, 1.24f));
  assert(t.print_min_c == 205 && t.print_max_c == 225);
  assert(t.manufactured == 1758709719);
}

// Aux written: consumed weight and workgroup; no brand.
static void vector03() {
  OptTag t;
  assert(decode(V03, sizeof(V03), &t) == OPT_OK);
  assert(t.brand[0] == '\0');
  assert(strcmp(t.material_name, "PETG Jet Black") == 0);
  assert(strcmp(optMaterialAbbr(t), "PETG") == 0);
  assert(near(t.consumed_g, 444));
  assert(strcmp(t.workgroup, "myhome") == 0);
  assert(near(optRemainingG(t), 1050 - 444));
  assert(t.colors[0][0] == 0x24 && t.colors[0][1] == 0x29 && t.colors[0][2] == 0x2A);
}

// Own abbreviation, three tags, a length, half-float nozzle.
static void vector04() {
  OptTag t;
  assert(decode(V04, sizeof(V04), &t) == OPT_OK);
  assert(strcmp(t.brand, "3DXTech") == 0);
  assert(strcmp(t.material_name, "CarbonX PEKK-A+CF15 Black") == 0);
  assert(t.material_type == 21);
  assert(strcmp(optMaterialAbbr(t), "PEKK-CF") == 0);
  assert(t.tag_count == 3 && t.tags[0] == 4 && t.tags[1] == 31 && t.tags[2] == 30);
  assert(near(t.min_nozzle_mm, 0.4f));
  assert(near(t.actual_length_mm, 226000));
  assert(t.print_min_c == 360 && t.print_max_c == 390);
  assert(near(t.nominal_weight_g, 750) && near(t.container_weight_g, 310));
}

// An unknown key 65535, an unknown enum value, a double float: all survive.
static void vector05() {
  OptTag t;
  assert(decode(V05, sizeof(V05), &t) == OPT_OK);
  assert(t.material_class == 0 && t.material_type == -1);
  assert(t.tag_count == 2 && t.tags[0] == 23 && t.tags[1] == 9429);
  assert(t.brand[0] == '\0' && optFullWeightG(t) < 0 && optRemainingG(t) < 0);
}

static void brokenInput() {
  OptTag t;
  uint8_t mem[64] = {0};
  assert(optDecodeMemory(mem, sizeof(mem), &t) == OPT_NO_CC);
  mem[0] = 0xE1; mem[1] = 0x40; mem[2] = 0x08; mem[3] = 0x01;
  assert(optDecodeMemory(mem, sizeof(mem), &t) == OPT_NO_NDEF);      // only NULL TLVs
  const uint8_t uri[] = {0x03, 0x08, 0xD1, 0x01, 0x04, 0x55, 0x04, 'a', '.', 'b', 0xFE};
  memcpy(mem + 4, uri, sizeof(uri));
  assert(optDecodeMemory(mem, sizeof(mem), &t) == OPT_NO_RECORD);
  // A TLV length running past the memory read.
  mem[5] = 0x7F;
  assert(optDecodeMemory(mem, sizeof(mem), &t) == OPT_NO_NDEF);
  // Every cut of a real tag either decodes or fails cleanly, never reads past.
  for (size_t cut = 0; cut < sizeof(SAMPLE); cut++) {
    static uint8_t part[sizeof(SAMPLE)];
    memcpy(part, SAMPLE, cut);
    optDecodeMemory(part, cut, &t);
  }
}

static void cborEdges() {
  // {1: [1, {2: "x"}], "k": 7, 3: 1.5 (half)} with an indefinite array inside.
  const uint8_t m[] = {0xA3, 0x01, 0x9F, 0x01, 0xA1, 0x02, 0x61, 'x', 0xFF,
                       0x61, 'k', 0x07, 0x03, 0xF9, 0x3E, 0x00};
  CborReader r = cborReader(m, sizeof(m));
  CborContainer c;
  assert(cborMapBegin(r, &c));
  int64_t key = 0;
  assert(cborMapNextKey(r, c, &key) && key == 1);
  int64_t v = 0;
  assert(!cborInt(r, &v));               // an array: skipped, reader still in step
  assert(cborMapNextKey(r, c, &key) && key == 3);   // the text key was passed over
  double d = 0;
  assert(cborNumber(r, &d) && d == 1.5);
  assert(!cborMapNextKey(r, c, &key) && !r.bad && r.pos == sizeof(m));
  // Nesting deeper than allowed is malformed, not a crash.
  uint8_t deep[20];
  memset(deep, 0x81, sizeof(deep));
  CborReader rd = cborReader(deep, sizeof(deep));
  assert(!cborSkip(rd) && rd.bad);
}

int main() {
  sampleTag();
  vector01();
  vector03();
  vector04();
  vector05();
  brokenInput();
  cborEdges();
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    (tmp / "vectors.h").write_text(
        "#include <stdint.h>\n" + "".join(
            c_array(n, globals()[n]) for n in ("SAMPLE", "V01", "V03", "V04", "V05")))
    cpp = tmp / "t.cpp"
    cpp.write_text(CPP)
    binary = tmp / "t"
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", f"-I{root/'src'}",
                    f"-I{tmp}", str(cpp), str(root / "src/openprinttag/opt_tag.cpp"),
                    str(root / "src/openprinttag/cbor_reader.cpp"), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)

print("openprinttag: ok")
