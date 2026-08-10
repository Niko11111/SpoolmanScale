#pragma once

#include <stdint.h>

#include "bambu_tag.h"

int countBambuDataBlocksRead(const BambuTagData& tag);
void scanTag(uint8_t *uid, uint8_t uid_len);
