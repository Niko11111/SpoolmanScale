"""Compile the production rule for a link a server names for a spool and check
what may go onto a label (services/spool_link_rules.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/spool_link_rules.h"
#include <cassert>
#include <string>

#define MAX (SPOOL_LINK_LEN - 1)

int main() {
  // The link Spooly names for a spool, on the size the label has.
  const char* spooly = "https://dev.spooly.eu/filament/e050d133-955e-45ba-90ba-5665eb0d23f6";
  assert(spoolLinkOk(spooly, MAX));
  assert(spoolLinkOk("http://192.168.4.100:7913/spool/show/12", MAX));
  assert(spoolLinkOk("https://a.example/s?id=12&x=%20#top", MAX));

  // A server without the field, or with an empty one.
  assert(!spoolLinkOk(nullptr, MAX));
  assert(!spoolLinkOk("", MAX));

  // Only an address a phone can open, with something after the scheme.
  assert(!spoolLinkOk("https://", MAX));
  assert(!spoolLinkOk("http://", MAX));
  assert(!spoolLinkOk("ftp://a.example/1", MAX));
  assert(!spoolLinkOk("javascript:alert(1)", MAX));
  assert(!spoolLinkOk("/filament/abc", MAX));
  assert(!spoolLinkOk("HTTPS://a.example/1", MAX));

  // Exactly the room there is, and one more: never cut short.
  std::string room = "https://a.example/" + std::string(MAX - 18, 'x');
  assert(room.size() == MAX);
  assert(spoolLinkOk(room.c_str(), MAX));
  assert(!spoolLinkOk((room + "x").c_str(), MAX));

  // Refused whole for one bad character.
  for (const char* bad : {"https://a.example/a b", "https://a.example/\"x", "https://a.example/'x",
                          "https://a.example/<b>", "https://a.example/\\x", "https://a.example/`x",
                          "https://a.example/\n", "https://a.example/\xC3\xA4"})
    assert(!spoolLinkOk(bad, MAX));
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", "-I", str(root / "src"), str(cpp), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)
print("test_spool_link: ok")
