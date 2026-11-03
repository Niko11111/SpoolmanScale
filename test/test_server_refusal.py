"""Compile the production reading of a server's refusal and check what each
code means and how a Retry-After is read (services/server_refusal_rules.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/server_refusal_rules.h"
#include <cassert>

int main() {
  assert(serverRefusalOf(401) == REFUSAL_ACCESS);
  assert(serverRefusalOf(403) == REFUSAL_ACCESS);
  assert(serverRefusalOf(402) == REFUSAL_ACCOUNT);
  assert(serverRefusalOf(429) == REFUSAL_TOO_MANY);

  // None of these is the server turning us down.
  const int other[] = {200, 201, 204, 400, 404, 409, 500, 502, 503, 504, 0, -1, -2, -11};
  for (int code : other) assert(serverRefusalOf(code) == REFUSAL_NONE);

  assert(retryAfterSeconds("120") == 120);
  assert(retryAfterSeconds("1") == 1);
  // Zero would mean asking again on the next pass.
  assert(retryAfterSeconds("0") == 1);
  // A daily limit names hours.
  assert(retryAfterSeconds("43200") == 43200);

  // Nothing usable: a default rather than no wait at all.
  assert(retryAfterSeconds(nullptr) == RETRY_AFTER_DEFAULT_S);
  assert(retryAfterSeconds("") == RETRY_AFTER_DEFAULT_S);
  assert(retryAfterSeconds("Wed, 21 Oct 2026 07:28:00 GMT") == RETRY_AFTER_DEFAULT_S);
  assert(retryAfterSeconds("-5") == RETRY_AFTER_DEFAULT_S);
  assert(retryAfterSeconds("12.5") == RETRY_AFTER_DEFAULT_S);

  // Never more than a day, also when the number overflows on the way.
  assert(retryAfterSeconds("86401") == RETRY_AFTER_MAX_S);
  assert(retryAfterSeconds("99999999999999999999") == RETRY_AFTER_MAX_S);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", f"-I{root / 'src'}", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("server refusal: ok")
