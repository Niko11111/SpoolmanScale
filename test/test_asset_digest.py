"""A manual update check takes the image's checksum from the release list it
already reads: GitHub gives every release asset a "digest" of the form
"sha256:<64 hex>". Compile the rule that reads it (services/asset_digest.h) and
check what it accepts: the sha256 prefix and exactly 64 hex digits, handed on
in lower case like version.json's checksum. Anything else gives no checksum, and
the install then runs on TLS alone, as it did before.

Then read the source: both release filters ask GitHub for the digest, both
manual checks, on the scale and on the web page, hand it to the install, and
the daily check stores for a reboot only the checksum of the version it
stores."""
import re
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
src = root / "src"
source = r"""
#include "services/asset_digest.h"
#include <cassert>
#include <cctype>
#include <cstring>
#include <string>

static std::string read(const char* digest, size_t len = 65) {
  char out[80];
  memset(out, 'x', sizeof(out));
  const bool ok = assetDigestSha256(digest, out, len);
  if (len > 0) assert(ok == (out[0] != '\0'));   // false always leaves ""
  return ok ? std::string(out) : std::string();
}

int main() {
  const std::string hex = "248243c60e75f4333043ca24ea01142764acc0cd4e131a1376f2c2f35724abbe";
  static_assert(ASSET_SHA256_HEX_LEN == 64, "a sha256 in hex");

  // The form GitHub publishes (v0.8.3, SpoolmanScale.bin).
  assert(read(("sha256:" + hex).c_str()) == hex);
  // Upper case digits come out in lower case, as version.json writes them.
  std::string upper = hex;
  for (char& c : upper) c = (char)toupper((unsigned char)c);
  assert(read(("sha256:" + upper).c_str()) == hex);

  // No checksum: nothing, an empty field, another algorithm, no prefix.
  assert(read(nullptr).empty());
  assert(read("").empty());
  assert(read(("sha512:" + hex).c_str()).empty());
  assert(read(hex.c_str()).empty());
  assert(read(("SHA256:" + hex).c_str()).empty());
  assert(read("sha256:").empty());

  // Not exactly 64 hex digits.
  assert(read(("sha256:" + hex.substr(0, 63)).c_str()).empty());
  assert(read(("sha256:" + hex + "0").c_str()).empty());
  std::string bad = hex;
  bad[10] = 'g';
  assert(read(("sha256:" + bad).c_str()).empty());

  // A buffer too small for 64 digits and the end takes nothing.
  assert(read(("sha256:" + hex).c_str(), 64).empty());
  char none[1] = {'x'};
  assert(!assetDigestSha256(("sha256:" + hex).c_str(), none, 0));
  assert(none[0] == 'x');
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(src),
                    str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


def code_only(text):
    return "\n".join(line.split("//")[0] for line in text.splitlines())


gh = code_only((src / "services/github_release.cpp").read_text(encoding="utf-8"))
asks = re.findall(r'\[\s*"assets"\s*\]\s*\[\s*0\s*\]\s*\[\s*"digest"\s*\]\s*=\s*true', gh)
assert len(asks) == 2, f"github_release.cpp: {len(asks)} of the 2 release filters ask for the asset's digest"
assert re.search(r"\bassetDigestSha256\s*\(", gh), "github_release.cpp: does not read the digest with assetDigestSha256()"

def call_args(code, name):
    """The argument text of every call to name, nested parentheses included."""
    out = []
    for m in re.finditer(rf"\b{name}\s*\(", code):
        depth, i = 1, m.end()
        while i < len(code) and depth:
            depth += {"(": 1, ")": -1}.get(code[i], 0)
            i += 1
        out.append(re.sub(r"\s+", "", code[m.end():i - 1]))
    return out


# Both manual checks ask for the checksum, and the one that collects it keeps
# it for the install. The web check asks in the worker and keeps it in the
# page's handler.
CHECKS = {"ui/ota_github.cpp": ("ui/ota_github.cpp", ",sha,sizeof(sha)"),
          "web/web_jobs.cpp": ("web/pages/page_firmware.cpp", ",s_res.image_sha,sizeof(s_res.image_sha)")}
for asker, (keeper, args) in CHECKS.items():
    calls = call_args(code_only((src / asker).read_text(encoding="utf-8")), "githubLatestTag")
    assert calls and all(c.endswith(args) for c in calls), \
        f"src/{asker}: githubLatestTag() is not asked for the image's checksum"
    keep = code_only((src / keeper).read_text(encoding="utf-8"))
    assert re.search(r"\botaRememberSha\s*\(", keep), f"src/{keeper}: the manual check does not hand the checksum on"

# What the daily check stores for a reboot is the checksum of the version it
# stores, never the pair's for another tag a manual check left behind.
upd = code_only((src / "services/update_check.cpp").read_text(encoding="utf-8"))
stored = [c for c in call_args(upd, "prefsPutString") if c.startswith('"upd_sha"')]
assert stored == ['"upd_sha",keep?otaExpectedSha(gh_latest_version):""'], \
    f"src/services/update_check.cpp: upd_sha is stored as {stored}, not as the checksum of gh_latest_version"

print("asset digest: ok")
