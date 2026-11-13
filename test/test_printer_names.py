"""Compile the production printer name helpers and check the split, the marks and the order."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/printer_names.h"
#include <cassert>
#include <cstring>
#include <string>

// "model" or "model?" for an untried one, joined by "|".
static void collect(const char* model, size_t len, bool untried, void* ctx) {
  std::string& out = *static_cast<std::string*>(ctx);
  if (!out.empty()) out += '|';
  out.append(model, len);
  if (untried) out += '?';
}

static std::string walk(const char* names, const char* untried) {
  std::string out;
  printerNameEach(names, untried, collect, &out);
  return out;
}

int main() {
  // One model, nothing untried.
  assert(walk("M220", nullptr) == "M220");
  // Several, all tried.
  assert(walk("B1, B21, B203", nullptr) == "B1|B21|B203");
  // The one not printed on yet is marked, the other not.
  assert(walk("PM245-BT, PM241-BT", "PM241-BT") == "PM245-BT|PM241-BT?");
  // A whole entry only: "D110" must not mark "D110 M".
  assert(walk("D110 M, D110", "D110") == "D110 M|D110?");
  // More than one untried.
  assert(walk("B1, B21, B203", "B21, B203") == "B1|B21?|B203?");
  // An empty list marks nothing.
  assert(walk("M2", "") == "M2");

  // Brands in the order they first appear, names sorted inside.
  const char* brands[] = { "Phomemo", "NIIMBOT", "Phomemo", "Phomemo", "NIIMBOT", "Phomemo" };
  const char* names[]  = { "M220", "M2", "M110", "PM245-BT, PM241-BT", "D110 M, D110", "M110S" };
  int order[6];
  printerSortByBrand(brands, names, order, 6);
  const int want[] = { 2, 5, 0, 3, 4, 1 };  // M110 M110S M220 PM245 | D110 M2
  for (int i = 0; i < 6; i++) assert(order[i] == want[i]);
  return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "test.cpp"
    cpp.write_text(source)
    binary = Path(tmp) / "test"
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"), str(cpp),
                    str(root / "src/services/printer_names.cpp"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("Printer name tests passed")
