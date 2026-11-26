"""Compile the rules that turn another maker's tag record into the input a
spool is created from, and read them back: an original Anycubic ACE tag
(vendor "AC", 19.11.2026), an eSun OpenSpool record, Snapmaker materials with
their line, and the records this scale wrote itself, which belong to their
spool and are never taken (services/tag_create_record.cpp)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]

source = r"""
#include "services/tag_create_record.h"
#include <cassert>
#include <cmath>
#include <cstring>

static TagRecord ace(const char* brand, const char* material, const char* sku) {
  TagRecord r = {};
  r.fmt = "ACE"; r.brand = brand; r.material = material; r.sku = sku;
  r.et_lo = 200; r.et_hi = 230; r.dia_x100 = 175; r.weight_g = 1000;
  return r;
}

static TagRecord openspool(const char* brand, const char* type, int spool_id) {
  TagRecord r = {};
  r.fmt = "OpenSpool"; r.brand = brand; r.material = type; r.sku = "";
  r.spool_id = spool_id; r.et_lo = 190; r.et_hi = 220;
  return r;
}

int main() {
  TagCreateInput in;

  // The original Anycubic PLA Matte of the Formnext: "AC", "PLA", 1000 g net.
  memset(&in, 0, sizeof(in));
  assert(tagCreateFromRecord(ace("AC", "PLA", "AHYGKP-101"), &in));
  assert(strcmp(in.vendor, "Anycubic") == 0);
  assert(strcmp(in.material, "PLA") == 0);
  assert(strcmp(in.product, "PLA") == 0);
  assert(in.subtype[0] == '\0');
  assert(in.net_weight_g == 1000);
  assert(in.spool_weight_g == 0 && !in.spool_weight_default);
  assert(std::fabs(in.diameter_mm - 1.75f) < 0.001f);
  assert(in.temp_min == 200 && in.temp_max == 230);
  assert(!in.names_known && in.names_optional);

  // An ACE record without a brand is Anycubic's; an unknown brand stays as it is.
  memset(&in, 0, sizeof(in));
  assert(tagCreateFromRecord(ace("", "PETG", "X1"), &in));
  assert(strcmp(in.vendor, "Anycubic") == 0);
  memset(&in, 0, sizeof(in));
  assert(tagCreateFromRecord(ace("Sunlu", "PLA", ""), &in));
  assert(strcmp(in.vendor, "Sunlu") == 0);

  // The scale's own ACE record: SKU "SM" and the spool id. It names its spool,
  // and a new spool can be made from it as well.
  TagRecord own = ace("Generic", "PLA", "SM45");
  assert(tagRecordIsOwn(own));
  assert(tagRecordOwnSpoolId(own) == 45);
  assert(tagCreateFromRecord(own, &in));
  assert(strcmp(in.vendor, "Generic") == 0 && strcmp(in.material, "PLA") == 0);
  // A maker's ACE record names no spool.
  assert(tagRecordOwnSpoolId(ace("AC", "PLA", "AHYGKP-101")) == 0);
  // An id too large for any backend is none.
  assert(tagRecordOwnSpoolId(ace("Generic", "PLA", "SM99999999999")) == 0);
  // "SM" without digits, or with more behind them, is a maker's SKU.
  assert(!tagRecordIsOwn(ace("AC", "PLA", "SMX-1")));
  assert(!tagRecordIsOwn(ace("AC", "PLA", "SM12A")));
  assert(!tagRecordIsOwn(ace("AC", "PLA", "SM")));

  // A record without a material names nothing to create.
  assert(!tagCreateFromRecord(ace("AC", "", "AHYGKP-101"), &in));

  // An eSun OpenSpool record: no weight on the tag, the reading decides.
  memset(&in, 0, sizeof(in));
  assert(tagCreateFromRecord(openspool("eSun", "PLA+", 0), &in));
  assert(strcmp(in.vendor, "eSun") == 0);
  assert(strcmp(in.material, "PLA+") == 0);
  assert(in.subtype[0] == '\0');
  assert(in.net_weight_g == 0);
  assert(std::fabs(in.diameter_mm - 1.75f) < 0.001f);
  assert(in.temp_min == 190 && in.temp_max == 220);
  // A type with a line: "PETG HF" is PETG in the line HF.
  memset(&in, 0, sizeof(in));
  assert(tagCreateFromRecord(openspool("Elegoo", "PETG HF", 0), &in));
  assert(strcmp(in.material, "PETG") == 0 && strcmp(in.subtype, "HF") == 0);
  assert(strcmp(in.product, "PETG HF") == 0);
  // Without a brand: Generic.
  memset(&in, 0, sizeof(in));
  assert(tagCreateFromRecord(openspool("", "PLA", 0), &in));
  assert(strcmp(in.vendor, "Generic") == 0);
  // One this scale or FilaMan wrote carries the spool id, and is taken too.
  assert(tagRecordIsOwn(openspool("eSun", "PLA", 12)));
  assert(tagRecordOwnSpoolId(openspool("eSun", "PLA", 12)) == 12);
  assert(tagRecordOwnSpoolId(openspool("eSun", "PLA", 0)) == 0);
  assert(tagCreateFromRecord(openspool("eSun", "PLA", 12), &in));

  // A maker by name: any case, and a name cut at 16 as the start of the full one.
  assert(tagCreateVendorIs("ANYCUBIC", "Anycubic"));
  assert(!tagCreateVendorIs("Anycubic Pro", "Anycubic"));
  assert(tagCreateVendorIs("Polymaker Panchroma", "Polymaker Panchr"));
  assert(!tagCreateVendorIs("Polymaker", "Polymaker Panchr"));
  assert(!tagCreateVendorIs("Anycubic", ""));

  // Formats this file does not know.
  TagRecord other = ace("AC", "PLA", "");
  other.fmt = "blank";
  assert(!tagCreateFromRecord(other, &in));

  // Snapmaker: the line behind the material, "PLA-CF" a base of its own.
  memset(&in, 0, sizeof(in));
  assert(tagCreateFromSnapmaker("", "PLA SnapSpeed", &in));
  assert(strcmp(in.vendor, "Snapmaker") == 0);
  assert(strcmp(in.material, "PLA") == 0 && strcmp(in.subtype, "SnapSpeed") == 0);
  assert(strcmp(in.product, "PLA SnapSpeed") == 0);
  assert(in.names_optional && !in.names_known);
  memset(&in, 0, sizeof(in));
  assert(tagCreateFromSnapmaker("Snapmaker", "TPU 95A HF", &in));
  assert(strcmp(in.material, "TPU") == 0 && strcmp(in.subtype, "95A HF") == 0);
  memset(&in, 0, sizeof(in));
  assert(tagCreateFromSnapmaker("Snapmaker", "PLA-CF", &in));
  assert(strcmp(in.material, "PLA-CF") == 0 && in.subtype[0] == '\0');
  // A material id the decoder does not know, or one that did not read.
  assert(!tagCreateFromSnapmaker("Snapmaker", "Unknown", &in));
  assert(!tagCreateFromSnapmaker("Snapmaker", "Unknown Matte", &in));
  assert(!tagCreateFromSnapmaker("Snapmaker", "", &in));

  // The maker names.
  char name[32];
  tagCreateMakerName("ac", name, sizeof(name));
  assert(strcmp(name, "Anycubic") == 0);
  tagCreateMakerName("ACE", name, sizeof(name));
  assert(strcmp(name, "ACE") == 0);
  tagCreateMakerName("", name, sizeof(name));
  assert(name[0] == '\0');
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    "-I", str(root / "src"),
                    str(cpp), str(root / "src" / "services" / "tag_create_record.cpp"), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)
print("tag create record rules: ok")
