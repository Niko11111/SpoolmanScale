"""Compile the production rule for where an OpenPrintTag read starts
(src/openprinttag/opt_resume.h) and check it: from block 0 without a usable
broken-off read, from the first missing block with one."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "openprinttag/opt_resume.h"
#include <cassert>

int main() {
  const size_t HEAD = 32, BLOCK = 4;
  const uint32_t KEEP = 5000;

  // Nothing kept: from block 0.
  assert(optResumeBlock(0, 0, KEEP, HEAD, BLOCK) == 0);
  // Less than the head: the length is unknown, from block 0.
  assert(optResumeBlock(28, 100, KEEP, HEAD, BLOCK) == 0);

  // The head whole: on after it.
  assert(optResumeBlock(32, 100, KEEP, HEAD, BLOCK) == 8);
  // The placement of 19.11.2026, 15:19:36: 224 of 312 bytes, on at block 56.
  assert(optResumeBlock(224, 1200, KEEP, HEAD, BLOCK) == 56);

  // Fresh up to the limit, not a millisecond after.
  assert(optResumeBlock(160, KEEP, KEEP, HEAD, BLOCK) == 40);
  assert(optResumeBlock(160, KEEP + 1, KEEP, HEAD, BLOCK) == 0);

  // A byte count off the block grid goes back to the whole block.
  assert(optResumeBlock(163, 0, KEEP, HEAD, BLOCK) == 40);

  // No block size: never resumes, never divides by zero.
  assert(optResumeBlock(160, 0, KEEP, HEAD, 0) == 0);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    src = Path(tmp) / "t.cpp"
    exe = Path(tmp) / "t"
    src.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    f"-I{root / 'src'}", str(src), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("opt_resume: ok")
