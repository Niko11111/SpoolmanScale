#pragma once
#include <stdint.h>

bool deriveSnapmakerKeys(const uint8_t* uid4, uint8_t keyA[16][6], uint8_t keyB[16][6] = nullptr);
