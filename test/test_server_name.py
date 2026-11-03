"""Compile the production rules for a server's own name and check what gets
through, how it is cut, and which badge it gives (services/server_name_rules.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/server_name_rules.h"
#include <cassert>
#include <cstring>

static bool clean(const char* in, const char* want) {
  char out[SERVER_NAME_MAX + 1];
  const bool ok = serverNameClean(in, out, sizeof(out));
  return ok && strcmp(out, want) == 0;
}
static bool refused(const char* in) {
  char out[SERVER_NAME_MAX + 1] = "x";
  return !serverNameClean(in, out, sizeof(out)) && out[0] == '\0';
}
static bool badge(const char* in, const char* want) {
  char out[SERVER_BADGE_LEN + 1];
  serverNameBadge(in, out);
  return strcmp(out, want) == 0;
}

int main() {
  // A plain name passes, blanks around it go.
  assert(clean("FilaCloud", "FilaCloud"));
  assert(clean("  My Shop 3D  ", "My Shop 3D"));
  assert(clean("Spool-Hub_2 (beta).v+", "Spool-Hub_2 (beta).v+"));

  // What could break a format string, a page or a glyph is refused whole.
  assert(refused("100%s"));
  assert(refused("<script>"));
  assert(refused("a&b"));
  assert(refused("say \"hi\""));
  assert(refused("it's"));
  assert(refused("Filamentb\xc3\xb6rse"));
  assert(refused("line\nbreak"));

  // Nothing there, nothing to show.
  assert(refused(""));
  assert(refused("    "));
  assert(refused(nullptr));

  // Cut at 31 bytes, and a blank left at the cut goes too.
  assert(clean("abcdefghijklmnopqrstuvwxyz01234567", "abcdefghijklmnopqrstuvwxyz01234"));
  assert(clean("abcdefghijklmnopqrstuvwxyz0123 567", "abcdefghijklmnopqrstuvwxyz0123"));

  // A small buffer is respected as well.
  char small[5];
  assert(serverNameClean("FilaCloud", small, sizeof(small)) && !strcmp(small, "Fila"));
  assert(!serverNameClean("FilaCloud", nullptr, 0));

  // Badges.
  assert(badge("FilaCloud", "FIL"));
  assert(badge("my 3d shop", "MY3"));
  assert(badge("a-b_c", "ABC"));
  assert(badge("ab", "SRV"));
  assert(badge("", "SRV"));
  assert(badge(nullptr, "SRV"));
  return 0;
}
"""
with tempfile.TemporaryDirectory() as d:
    src = Path(d) / "t.cpp"
    exe = Path(d) / "t"
    src.write_text(source)
    subprocess.run(["clang++", "-std=c++17", f"-I{root}/src", str(src), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("server name rules: ok")
