#pragma once

#include <stddef.h>

// The format a tag is linked with in Spoolman's own tag relation. Spoolman
// takes any name and only shows it, but a MIFARE card filed as "ntag" read as
// an NTAG in its list. Names from Spoolman's KNOWN_FORMATS where one fits
// ("bambu", "creality", "ntag", "openprinttag"); "mifare" for any other 4 byte
// card. Every 8 byte UID is an ISO 15693 tag, which only the PN7160 reads, and
// it is filed as "openprinttag" whether or not it carried that format.

// Hex digits of a normalised id: a Bambu tray uuid, a 4 byte and an 8 byte UID.
constexpr size_t TAG_HEX_LEN_TRAY_UUID = 32;
constexpr size_t TAG_HEX_LEN_4_BYTE    = 8;
constexpr size_t TAG_HEX_LEN_8_BYTE    = 16;

// hex_len: length of the normalised id the link is made with.
// creality: that id is the tag on the reader, and it read as a Creality tag.
inline const char* tagFormatFor(size_t hex_len, bool creality) {
  if (hex_len == TAG_HEX_LEN_TRAY_UUID) return "bambu";
  if (hex_len == TAG_HEX_LEN_8_BYTE) return "openprinttag";
  if (creality) return "creality";
  if (hex_len == TAG_HEX_LEN_4_BYTE) return "mifare";
  return "ntag";
}
