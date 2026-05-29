#pragma once

#include <stdint.h>

bool deriveKeys(const uint8_t* uid, uint8_t uid_len, uint8_t keys[16][6]);
