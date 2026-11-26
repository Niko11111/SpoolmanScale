#pragma once

// Prusa's OpenPrintTag (specs.openprinttag.org, format of prusa3d/OpenPrintTag
// at 060e420): an ISO 15693 tag whose NDEF message holds a MIME record
// "application/vnd.openprinttag" with three CBOR maps - meta, main (what the
// maker wrote) and aux (what printers update, e.g. the weight used). Decoded
// here from the tag's memory as read, block 0 on. Pure: no Arduino, tested on
// the host against the format's own test vectors (test/test_openprinttag.py).

#include <stddef.h>
#include <stdint.h>

#define OPT_COLORS_MAX     6    // primary and secondary_color_0..4
#define OPT_TAGS_MAX       16
#define OPT_TEXT_BRAND     32
#define OPT_TEXT_MATERIAL  64
#define OPT_TEXT_ABBR      8
#define OPT_TEXT_ID        17
#define OPT_TEXT_WORKGROUP 9
// What a reader reads at most: the format's tag is 320 bytes, and the CC
// cannot describe more than 255 * 8.
#define OPT_MEMORY_MAX     2040
#define OPT_CC_BYTES       4
#define OPT_UID_BYTES      8
#define OPT_UID_STR_LEN    23   // "E0:04:01:08:66:2F:6F:BC"
#define OPT_CLASS_FILAMENT 0    // material_class
#define OPT_CLASS_RESIN    1

enum OptResult : uint8_t {
  OPT_OK = 0,
  OPT_NO_CC,          // block 0 is no NDEF capability container
  OPT_NO_NDEF,        // no NDEF TLV, or it runs past the memory read
  OPT_NO_RECORD,      // an NDEF message, but no OpenPrintTag record in it
  OPT_BAD_PAYLOAD,    // the record is there, its CBOR is not readable
};

// Absent values: numbers below 0, temperatures 0, texts empty.
struct OptTag {
  int16_t material_class;   // 0 filament, 1 resin, -1 not given
  int16_t material_type;    // the format's enum (0 PLA, 1 PETG, ...), -1 not given
  char brand[OPT_TEXT_BRAND];
  char material_name[OPT_TEXT_MATERIAL];
  char abbreviation[OPT_TEXT_ABBR];          // as written; see optMaterialAbbr()
  char instance_id[OPT_TEXT_ID];             // brand_specific_instance_id
  uint8_t color_count;                       // 0 when the tag gives none
  uint8_t colors[OPT_COLORS_MAX][4];         // RGBA, primary first
  uint8_t tag_count;
  uint16_t tags[OPT_TAGS_MAX];               // the format's tag enum (16 matte, 17 silk, ...)
  float nominal_weight_g;
  float actual_weight_g;
  float container_weight_g;                  // the empty spool
  float density;
  float diameter_mm;                         // 1.75 when not given, as the format says
  float nominal_length_mm;
  float actual_length_mm;
  float min_nozzle_mm;
  int16_t print_min_c, print_max_c, preheat_c;
  int16_t bed_min_c, bed_max_c;
  int16_t dry_c;
  int32_t dry_minutes;
  int64_t manufactured;                      // UNIX time, 0 not given
  uint64_t gtin;                             // 0 not given
  // aux
  float consumed_g;
  char workgroup[OPT_TEXT_WORKGROUP];
};

// How many bytes of the tag hold the NDEF area, from the CC in block 0; 0 when
// it is no CC. The reader reads that much (at most OPT_MEMORY_MAX).
size_t optMemorySize(const uint8_t cc[OPT_CC_BYTES]);

// How much of the tag to read, given its first bytes (have >= 4): up to the
// end of the NDEF TLV when its header is among them, else what the CC
// declares; 0 when block 0 is no CC. Reading only that much spares the
// blocks after the message, and those past the tag's end.
size_t optBytesNeeded(const uint8_t* head, size_t have);

// The whole tag as read, block 0 first.
OptResult optDecodeMemory(const uint8_t* mem, size_t len, OptTag* out);
// Just the record's payload: the three regions.
OptResult optDecodePayload(const uint8_t* p, size_t len, OptTag* out);
// Where the aux region lies in the memory as read: its first byte (block 0
// is byte 0) and its size. False without an OpenPrintTag record or without an
// aux region its meta names; a writer never invents one (opt_aux.h).
bool optAuxLocate(const uint8_t* mem, size_t len, size_t* at, size_t* size);

const char* optResultName(OptResult r);
// The format's abbreviation for a material_type, or nullptr.
const char* optMaterialTypeName(int material_type);
// What to call the material: the tag's own abbreviation, else that of its type.
const char* optMaterialAbbr(const OptTag& t);
// The filament on the spool when full: actual, else nominal; below 0 unknown.
float optFullWeightG(const OptTag& t);
// What is left: full minus what printers recorded as consumed; below 0 unknown.
float optRemainingG(const OptTag& t);
// "YYYY-MM-DD" in UTC; empty for 0.
void optFormatDate(int64_t unix_s, char* out, size_t cap);

// An ISO 15693 UID as the reader hands it over (least significant byte first)
// in the order the format and phones print it, E0 first. False when neither
// end is E0, the ISO 15693 manufacturer prefix; it is reversed all the same.
bool optUidMsbFirst(const uint8_t wire[OPT_UID_BYTES], uint8_t out[OPT_UID_BYTES]);
// "E0:04:01:..." from the MSB-first UID, OPT_UID_STR_LEN characters.
void optUidString(const uint8_t msb_first[OPT_UID_BYTES], char* out, size_t cap);

// The colour's name: the material name without a leading material word
// ("PLA Galaxy Black" -> "Galaxy Black"), else the whole name. Cut at a
// character boundary to fit.
void optColorName(const OptTag& t, char* out, size_t cap);

// One line for the log: brand, name, material, colour, weights, temperatures,
// date.
void optSummary(const OptTag& t, char* out, size_t cap);
