#pragma once

#include <stddef.h>

// ============================================================
//  THE CHECKSUM GITHUB PUBLISHES FOR A RELEASE ASSET
//
//  The release list carries a "digest" for every asset, "sha256:" and 64 hex
//  digits. A manual update check reads that list anyway, so it takes the
//  image's checksum from there; the daily check keeps reading version.json.
//  An asset uploaded before GitHub started this, or an answer without the
//  field, gives none, and the install runs on TLS alone as before.
// ============================================================

constexpr size_t ASSET_SHA256_HEX_LEN = 64;

// The 64 hex digits of digest, in lower case like version.json writes them,
// into hex (at least ASSET_SHA256_HEX_LEN + 1 bytes). False, and hex left
// empty, for anything else: no digest, another algorithm, a wrong length or a
// character that is not a hex digit.
inline bool assetDigestSha256(const char *digest, char *hex, size_t hex_len) {
  static const char PREFIX[] = "sha256:";
  const size_t prefix_len = sizeof(PREFIX) - 1;
  if (!hex || hex_len == 0) return false;
  hex[0] = '\0';
  if (!digest || hex_len < ASSET_SHA256_HEX_LEN + 1) return false;
  for (size_t i = 0; i < prefix_len; i++)
    if (digest[i] != PREFIX[i]) return false;
  const char *d = digest + prefix_len;
  for (size_t i = 0; i < ASSET_SHA256_HEX_LEN; i++) {
    const char c = d[i];
    if (c >= '0' && c <= '9')      hex[i] = c;
    else if (c >= 'a' && c <= 'f') hex[i] = c;
    else if (c >= 'A' && c <= 'F') hex[i] = (char)(c - 'A' + 'a');
    else { hex[0] = '\0'; return false; }
  }
  if (d[ASSET_SHA256_HEX_LEN] != '\0') { hex[0] = '\0'; return false; }
  hex[ASSET_SHA256_HEX_LEN] = '\0';
  return true;
}
