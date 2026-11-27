"""Compile the sorting of the PN7160's error notifications and check that each
NCI status lands in its own counter, that the last one is kept raw, and the
JSON the measurement answers with (hardware/nfc_rf_counts.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "hardware/nfc_rf_counts.h"
#include <cassert>
#include <cstring>

int main() {
  NfcRfCounts c = {};
  nfcRfCountError(c, 0xB2);   // the tag did not answer
  nfcRfCountError(c, 0xB2);
  nfcRfCountError(c, 0xB0);   // garbled ...
  nfcRfCountError(c, 0x02);   // ... and a corrupted frame count together
  nfcRfCountError(c, 0xB1);
  nfcRfCountError(c, 0xA1);   // a tag discovery could not select
  nfcRfCountError(c, 0x06);   // anything else
  assert(c.rf_timeout == 2 && c.rf_corrupted == 2 && c.rf_protocol == 1);
  assert(c.activation_failed == 1 && c.other_errors == 1);
  assert(c.last_error == 0x06);
  // Nothing else moves.
  assert(c.commands == 0 && c.answered_ok == 0 && c.no_answer == 0 && c.reselect_miss == 0);

  assert(strcmp(nfcRfStatusName(0xB2), "rf timeout") == 0);
  assert(strcmp(nfcRfStatusName(0xA1), "activation failed") == 0);
  assert(strcmp(nfcRfStatusName(0x7F), "other") == 0);

  NfcRfCounts j = {};
  j.commands = 50; j.answered_ok = 47; j.no_answer = 1;
  nfcRfCountError(j, 0xB2);
  nfcRfCountError(j, 0xB0);
  char out[400];
  nfcRfCountsJson(j, out, sizeof(out));
  assert(strcmp(out,
    "{\"commands\":50,\"answered_ok\":47,\"tag_status\":0,\"no_answer\":1,"
    "\"dropped\":0,\"rf_timeout\":1,\"rf_corrupted\":1,\"rf_protocol\":0,"
    "\"activation_failed\":0,\"other_errors\":0,\"reselect_miss\":0,"
    "\"last_error\":176}") == 0);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", f"-I{root / 'src'}", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("nfc rf counts: ok")
