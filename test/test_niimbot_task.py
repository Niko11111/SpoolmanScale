"""Compile the production NIIMBOT task selection and check it against niimbluelib's table."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/niimbot_task.h"
#include <cassert>

int main() {
  // Status version to protocol, as niimbluelib's parsePrinterStatusDataResponse.
  assert(niimbotProtocolFromStatus(0) == 0);
  assert(niimbotProtocolFromStatus(203) == 0);
  assert(niimbotProtocolFromStatus(204) == 3);
  assert(niimbotProtocolFromStatus(299) == 3);
  assert(niimbotProtocolFromStatus(300) == 4);
  assert(niimbotProtocolFromStatus(301) == 4);
  assert(niimbotProtocolFromStatus(302) == 5);
  assert(niimbotProtocolFromStatus(512) == 5);

  // The D110 M: the B1's task, the V4 task on protocol 4 alone.
  const int not_v4[] = { 0, 1, 2, 3, 5 };
  for (int v : not_v4)
    assert(niimbotTaskFor(NB_ID_D110_M, NB_TASK_B1, (uint8_t)v) == NB_TASK_B1);
  assert(niimbotTaskFor(NB_ID_D110_M, NB_TASK_B1, 4) == NB_TASK_V4);

  // Every other model keeps its table task at every version.
  const uint16_t others[] = { 4096, 768, 777, 4608, NB_ID_D110_A, NB_ID_D110_B, 512 };
  const NiimbotTask tasks[] = { NB_TASK_B1, NB_TASK_D110, NB_TASK_B21_V1 };
  for (uint16_t id : others)
    for (NiimbotTask t : tasks)
      for (int v = 0; v <= 5; v++) assert(niimbotTaskFor(id, t, (uint8_t)v) == t);

  // The D110 class: the D110's two ids and the D110 M, nothing with the same head.
  assert(niimbotIsD110(NB_ID_D110_A) && niimbotIsD110(NB_ID_D110_B) && niimbotIsD110(NB_ID_D110_M));
  assert(!niimbotIsD110(512));    // D11
  assert(!niimbotIsD110(3584));   // B18
  assert(!niimbotIsD110(4096));   // B1
  assert(!niimbotIsD110(0));
  return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "test.cpp"
    cpp.write_text(source)
    binary = Path(tmp) / "test"
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"), str(cpp),
                    str(root / "src/services/niimbot_task.cpp"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("NIIMBOT task tests passed")
