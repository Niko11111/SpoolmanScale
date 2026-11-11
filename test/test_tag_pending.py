"""Compile the marker of an unfinished tag write and check how it is spelled
in NVS and which tag it names (services/tag_pending_rules.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/tag_pending_rules.h"
#include <cassert>
#include <cstring>

static TagPendingMark mark(const uint8_t* uid, uint8_t len, int spool, uint8_t fmt) {
  TagPendingMark m{};
  memcpy(m.uid, uid, len);
  m.uid_len = len;
  m.spool_id = spool;
  m.fmt = fmt;
  return m;
}

int main() {
  const uint8_t ntag[7] = {0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6};
  const uint8_t cfs[4]  = {0x6E, 0xC6, 0xDB, 0x4F};
  char text[TAG_PENDING_TEXT_MAX];

  // Both UID lengths there and back.
  assert(tagPendingEncode(mark(ntag, 7, 123, 1), text, sizeof(text)));
  assert(strcmp(text, "04A1B2C3D4E5F6/123/1") == 0);
  TagPendingMark back{};
  assert(tagPendingDecode(text, &back));
  assert(back.uid_len == 7 && memcmp(back.uid, ntag, 7) == 0);
  assert(back.spool_id == 123 && back.fmt == 1);

  assert(tagPendingEncode(mark(cfs, 4, 9, 4), text, sizeof(text)));
  assert(strcmp(text, "6EC6DB4F/9/4") == 0);
  assert(tagPendingDecode(text, &back));
  assert(back.uid_len == 4 && back.spool_id == 9 && back.fmt == 4);
  assert(tagPendingDecode("6ec6db4f/9/4", &back) && back.uid[0] == 0x6E);

  // Nothing the scale would not write itself is a marker.
  assert(!tagPendingEncode(mark(cfs, 4, 0, 4), text, sizeof(text)));
  assert(!tagPendingEncode(mark(cfs, 5, 9, 4), text, sizeof(text)));
  assert(!tagPendingEncode(mark(cfs, 4, 9, 4), text, 8));
  const char* bad[] = {"", "/", "6EC6DB4F", "6EC6DB4F/9", "6EC6DB4F/0/4", "6EC6DB4F/-3/4",
                       "6EC6DB/9/4", "6EC6DB4F00/9/4", "6EC6DB4G/9/4", "6EC6DB4F/9/256",
                       "6EC6DB4F/9/-1", "6EC6DB4F/9/4x", "6EC6DB4/9/4"};
  for (const char* b : bad) assert(!tagPendingDecode(b, &back));
  assert(!tagPendingDecode(nullptr, &back));

  // The tag it names, and no other: same bytes and same length.
  const TagPendingMark m = mark(cfs, 4, 9, 4);
  assert(tagPendingMatches(m, cfs, 4));
  const uint8_t other[4] = {0x6E, 0xC6, 0xDB, 0x50};
  assert(!tagPendingMatches(m, other, 4));
  assert(!tagPendingMatches(m, ntag, 7));
  assert(!tagPendingMatches(m, cfs, 7));
  assert(!tagPendingMatches(m, nullptr, 4));
  assert(!tagPendingMatches(TagPendingMark{}, cfs, 0));
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", f"-I{root / 'src'}", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("tag pending: ok")
