#include "openprinttag/opt_aux.h"

#include <math.h>
#include <string.h>

#include "openprinttag/cbor_reader.h"

namespace {

constexpr uint64_t AUX_KEY_CONSUMED = 0;   // aux_fields.yaml: consumed_weight
// CBOR (RFC 8949): a map of indefinite length, and its end; a map of a given
// length below 24 is one byte, its count in it.
constexpr uint8_t  CBOR_MAP_INDEFINITE = 0xBF;
constexpr uint8_t  CBOR_BREAK          = 0xFF;
constexpr uint8_t  CBOR_MAP_DEFINITE   = 0xA0;
// The head of an unsigned integer: the value itself below 24, else the
// width of the argument that follows.
constexpr uint64_t CBOR_TINY_MAX = 23;
constexpr uint8_t  CBOR_ARG_1    = 0x18;
constexpr uint8_t  CBOR_ARG_2    = 0x19;
constexpr uint8_t  CBOR_ARG_4    = 0x1A;
constexpr uint8_t  CBOR_ARG_8    = 0x1B;
constexpr int      BITS_PER_BYTE = 8;

}  // namespace

static bool allZero(const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (p[i]) return false;
  return true;
}

// Appends an unsigned integer in its shortest form. False when it does not fit.
static bool putUint(uint8_t* out, size_t cap, size_t* at, uint64_t v) {
  uint8_t head;
  size_t arg_bytes;
  if (v <= CBOR_TINY_MAX)    { head = (uint8_t)v;  arg_bytes = 0; }
  else if (v <= UINT8_MAX)   { head = CBOR_ARG_1;  arg_bytes = 1; }
  else if (v <= UINT16_MAX)  { head = CBOR_ARG_2;  arg_bytes = 2; }
  else if (v <= UINT32_MAX)  { head = CBOR_ARG_4;  arg_bytes = 4; }
  else                       { head = CBOR_ARG_8;  arg_bytes = 8; }
  if (*at + 1 + arg_bytes > cap) return false;
  out[(*at)++] = head;
  for (size_t i = arg_bytes; i > 0; i--)
    out[(*at)++] = (uint8_t)(v >> ((i - 1) * BITS_PER_BYTE));
  return true;
}

// Every entry of the old map but consumed_weight, byte for byte and in its
// order, definite or indefinite as it was. count: the entries copied.
static bool copyOthers(const uint8_t* aux, size_t size, uint8_t* out, size_t* at,
                       uint64_t* count) {
  CborReader r = cborReader(aux, size);
  CborContainer m;
  if (!cborMapBegin(r, &m)) return false;
  while (m.indefinite ? !cborAtBreak(r) : m.left > 0) {
    const size_t start = r.pos;
    int64_t key = -1;
    // A key of another type is skipped by the read and copied all the same.
    const bool int_key = cborInt(r, &key);
    if (r.bad || !cborSkip(r)) return false;
    if (!m.indefinite) m.left--;
    if (int_key && key == (int64_t)AUX_KEY_CONSUMED) continue;
    const size_t n = r.pos - start;
    if (*at + n > size) return false;
    memcpy(out + *at, aux + start, n);
    *at += n;
    (*count)++;
  }
  return !r.bad;
}

bool optAuxWithConsumed(const uint8_t* aux, size_t size, uint32_t consumed_g, uint8_t* out) {
  if (!aux || !out || aux == out || size == 0) return false;
  size_t at = 1;   // the map's head, settled once the entries are known
  uint64_t entries = 1;
  if (!putUint(out, size, &at, AUX_KEY_CONSUMED) || !putUint(out, size, &at, consumed_g))
    return false;
  if (!allZero(aux, size) && !copyOthers(aux, size, out, &at, &entries)) return false;
  if (at < size) {
    out[0] = CBOR_MAP_INDEFINITE;
    out[at++] = CBOR_BREAK;
  } else if (at == size && entries <= CBOR_TINY_MAX) {
    // A region the old map filled exactly: the break does not fit, a map of
    // given length does, one byte shorter.
    out[0] = (uint8_t)(CBOR_MAP_DEFINITE | entries);
  } else {
    return false;
  }
  memset(out + at, 0, size - at);
  return true;
}

uint32_t optConsumedFor(float full_g, float remaining_g) {
  const float used = full_g - remaining_g;
  if (!(used > 0.0f)) return 0;
  return (uint32_t)lroundf(used);
}
