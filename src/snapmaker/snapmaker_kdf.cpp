#include "snapmaker_kdf.h"
#include <Arduino.h>
#include <string.h>
#include <string>
#include "mbedtls/md.h"

static const uint8_t SNAPMAKER_SALT_A[] = "Snapmaker_qwertyuiop[,.;]";
static const uint8_t SNAPMAKER_SALT_B[] = "Snapmaker_qwertyuiop[,.;]_1q2w3e";

static bool hmac_sha256(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        uint8_t* out) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return mbedtls_md_hmac(info, key, key_len, data, data_len, out) == 0;
}

bool deriveSnapmakerKeys(const uint8_t* uid4, uint8_t keyA[16][6], uint8_t keyB[16][6]) {
  uint8_t prk_A[32];
  uint8_t prk_B[32];

  if (!hmac_sha256(SNAPMAKER_SALT_A, 25, uid4, 4, prk_A)) {
    return false;
  }
  
  if (keyB != nullptr) {
    if (!hmac_sha256(SNAPMAKER_SALT_B, 32, uid4, 4, prk_B)) {
      return false;
    }
  }

  for (int i = 0; i < 16; i++) {
    uint8_t okm[32];
    
    std::string infoA = "key_a_" + std::to_string(i);
    uint8_t inputA[32];
    size_t lenA = infoA.length();
    memcpy(inputA, infoA.c_str(), lenA);
    inputA[lenA] = 1; // counter = 1
    if (!hmac_sha256(prk_A, 32, inputA, lenA + 1, okm)) return false;
    memcpy(keyA[i], okm, 6);

    if (keyB != nullptr) {
      std::string infoB = "key_b_" + std::to_string(i);
      uint8_t inputB[32];
      size_t lenB = infoB.length();
      memcpy(inputB, infoB.c_str(), lenB);
      inputB[lenB] = 1; // counter = 1
      if (!hmac_sha256(prk_B, 32, inputB, lenB + 1, okm)) return false;
      memcpy(keyB[i], okm, 6);
    }
  }
  return true;
}
