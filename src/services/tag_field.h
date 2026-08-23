#pragma once

#include <stddef.h>
#include <stdint.h>

// ============================================================
//  WHICH EXTRA FIELD HOLDS THE TAG UID
//
//  Spoolman has no field for NFC tags, so every project around it picked its
//  own extra field. The scale can write any of them, and which one is the
//  user's choice.
//
//  The choice covers the field name AND the value format, because the two are
//  not separable: a UID written with colons into nfc_id would never be found
//  by the tools that expect plain hex there, and the field name alone would
//  make the setting look like it works while quietly failing.
//
//  Writing goes to the selected field only. Reading always covers all of them
//  - see spoolMatchesTag() - so switching never makes a spool disappear.
// ============================================================

// The other extra field the scale writes. Not a tag field and never selectable,
// but it is probed and created alongside them, so it belongs in the same list.
#define LAST_DRIED_FIELD  "last_dried"

enum TagFieldId : uint8_t {
  TAG_FIELD_TAG       = 0,   // extra.tag       - this scale, OpenSpoolman
  TAG_FIELD_NFC_ID    = 1,   // extra.nfc_id    - FilaMan, nfc2klipper, SpoolSense
  TAG_FIELD_CARD_UIDS = 2,   // extra.card_uids - SpoolLink, Snapmaker U1
  TAG_FIELD_COUNT     = 3
};

struct TagFieldSpec {
  const char* key;        // the Spoolman extra field key
  bool        is_list;    // comma separated list of UIDs, card_uids only
  bool        plain_hex;  // value normalised to uppercase hex, no separators
  // StringIDs, kept as plain numbers so this header stays clear of lang.h:
  // its T() macro collides with ArduinoJson's template parameter, and this
  // header is included from files that use both.
  uint16_t    str_name;
  uint16_t    str_sub;
  uint16_t    str_info;
};

// Never null. An id out of range answers with the default field rather than
// reading past the table - a corrupted NVS value must not crash the scale.
const TagFieldSpec& tagFieldSpec(uint8_t id);

// The field the user selected, and the two things most callers want from it.
const TagFieldSpec& tagFieldSelected();
const char*         tagFieldKey();
bool                tagFieldIsList();

// Writes `uid` the way `spec` wants it: verbatim for a field that stores what
// it is given, normalised uppercase hex for the ones that expect it. Always
// NUL terminates when out_len > 0.
void tagFieldFormat(const TagFieldSpec& spec, const char* uid,
                    char* out, size_t out_len);
