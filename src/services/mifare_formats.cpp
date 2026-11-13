#include "mifare_formats.h"

#include "creality/creality_write.h"

static const MifareFormat MIFARE_FORMATS[] = {
  { TAG_FMT_CREALITY, crealityBuildJob, crealityWritten, crealityEraseJob },
};

const MifareFormat* mifareFormatFor(uint8_t fmt) {
  for (const MifareFormat& f : MIFARE_FORMATS) {
    if (f.fmt == fmt) return &f;
  }
  return nullptr;
}
