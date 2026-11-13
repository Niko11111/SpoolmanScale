#pragma once

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>

#include "services/mifare_write.h"
#include "services/tag_write.h"

// ============================================================
//  THE MIFARE CLASSIC FORMATS THE SCALE WRITES
//
//  One line per format in MIFARE_FORMATS (mifare_formats.cpp). A format says
//  what goes onto the tag; how it gets there safely is mifare_write.cpp's
//  business and the same for all of them. A new format is a file of its own
//  with a build() and a written(), plus its line in the table and its
//  TagFormat in tag_write.h.
// ============================================================

// Room for the printable record a format logs, Creality's 40 characters.
#define MIFARE_RECORD_TEXT_BYTES 48

struct MifareFormat {
  TagFormat   fmt;
  // Fills the job from the spool as the backend returned it (every backend
  // answers in Spoolman's shape) and puts a printable form of the record into
  // text. False when the spool cannot be written in this format.
  bool (*build)(JsonObjectConst spool, int spool_id, MifareWriteJob* job,
                char* text, size_t text_len);
  // After a verified write: what the read side keeps about the tag.
  void (*written)(const uint8_t uid[4], const char* text);
  // The format's sector and key without a record, for mifareErase().
  void (*erase_job)(MifareWriteJob* job);
};

// The format behind fmt, nullptr when fmt is not a MIFARE format.
const MifareFormat* mifareFormatFor(uint8_t fmt);
