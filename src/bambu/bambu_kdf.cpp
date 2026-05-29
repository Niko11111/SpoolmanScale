#include "bambu_kdf.h"

#include <Arduino.h>
#include <stddef.h>
#include <string.h>
#include "mbedtls/md.h"

// Master key from Bambu-Research-Group/RFID-Tag-Guide.
// HKDF with SHA256, context "RFID-B\0", 16 keys of 6 bytes each.
static const uint8_t BAMBU_MASTER_KEY[16] = {
  0x9a, 0x75, 0x9c, 0xf2, 0xc4, 0xf7, 0xca, 0xff,
  0x22, 0x2c, 0xb9, 0x76, 0x9b, 0x41, 0xbc, 0x96
};
static const uint8_t BAMBU_KDF_CONTEXT[] = "RFID-B";

static bool hmac_sha256(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        uint8_t* out) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return mbedtls_md_hmac(info, key, key_len, data, data_len, out) == 0;
}

static bool hkdf_expand(const uint8_t* prk, size_t prk_len,
                        const uint8_t* info, size_t info_len,
                        uint8_t* okm, size_t okm_len) {
  uint8_t t[32] = {0};
  size_t t_len = 0;
  size_t done = 0;
  uint8_t counter = 1;
  while (done < okm_len) {
    uint8_t input[256];
    size_t input_len = 0;
    memcpy(input, t, t_len);                   input_len += t_len;
    memcpy(input + input_len, info, info_len); input_len += info_len;
    input[input_len++] = counter++;
    if (!hmac_sha256(prk, prk_len, input, input_len, t)) return false;
    t_len = 32;
    size_t copy = (okm_len - done < 32) ? (okm_len - done) : 32;
    memcpy(okm + done, t, copy);
    done += copy;
  }
  return true;
}

bool deriveKeys(const uint8_t* uid, uint8_t uid_len, uint8_t keys[16][6]) {
  uint8_t prk[32];
  if (!hmac_sha256(BAMBU_MASTER_KEY, 16, uid, uid_len, prk)) {
    Serial.println("HKDF-Extract error");
    return false;
  }

  uint8_t okm[96];
  if (!hkdf_expand(prk, 32, BAMBU_KDF_CONTEXT, 7, okm, 96)) {
    Serial.println("HKDF-Expand error");
    return false;
  }

  for (int i = 0; i < 16; i++) {
    memcpy(keys[i], okm + i * 6, 6);
  }
  return true;
}
