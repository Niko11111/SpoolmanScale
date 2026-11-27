#include "cbor_reader.h"

#include <math.h>
#include <string.h>

namespace {

constexpr uint8_t MAJOR_UINT   = 0;
constexpr uint8_t MAJOR_NEG    = 1;
constexpr uint8_t MAJOR_BYTES  = 2;
constexpr uint8_t MAJOR_TEXT   = 3;
constexpr uint8_t MAJOR_ARRAY  = 4;
constexpr uint8_t MAJOR_MAP    = 5;
constexpr uint8_t MAJOR_TAG    = 6;
constexpr uint8_t MAJOR_SIMPLE = 7;
constexpr uint8_t INFO_ONE_BYTE   = 24;   // the argument follows in 1, 2, 4, 8 bytes
constexpr uint8_t INFO_RESERVED   = 28;
constexpr uint8_t INFO_INDEFINITE = 31;
constexpr uint8_t INFO_HALF   = 25;       // with major 7: the float widths
constexpr uint8_t INFO_SINGLE = 26;
constexpr uint8_t INFO_DOUBLE = 27;
constexpr uint8_t BREAK_BYTE  = 0xFF;

struct Head {
  uint8_t major;
  uint8_t info;
  uint64_t arg;        // the value, length or count; for floats the raw bits
  bool indefinite;
};

}  // namespace

static bool fail(CborReader& r) {
  r.bad = true;
  return false;
}

static bool readHead(CborReader& r, Head* h) {
  if (r.bad || r.pos >= r.n) return fail(r);
  const uint8_t b = r.p[r.pos++];
  h->major = b >> 5;
  h->info = b & 0x1F;
  h->arg = h->info;
  h->indefinite = h->info == INFO_INDEFINITE;
  if (h->info < INFO_ONE_BYTE || h->indefinite) {
    // Indefinite length exists for strings, arrays and maps only; with major 7
    // it is the break byte, which no caller reads as a head.
    return h->indefinite ? (h->major >= MAJOR_BYTES && h->major <= MAJOR_MAP) || fail(r) : true;
  }
  if (h->info >= INFO_RESERVED) return fail(r);
  const size_t width = (size_t)1 << (h->info - INFO_ONE_BYTE);
  if (r.n - r.pos < width) return fail(r);
  h->arg = 0;
  for (size_t i = 0; i < width; i++) h->arg = (h->arg << 8) | r.p[r.pos++];
  return true;
}

bool cborAtBreak(const CborReader& r) {
  return !r.bad && r.pos < r.n && r.p[r.pos] == BREAK_BYTE;
}

static bool skipDepth(CborReader& r, int depth);

// The chunks of an indefinite string, or the entries of a container.
static bool skipEntries(CborReader& r, const Head& h, int depth) {
  const uint64_t per_entry = (h.major == MAJOR_MAP) ? 2 : 1;
  if (h.indefinite) {
    while (!cborAtBreak(r)) {
      for (uint64_t i = 0; i < per_entry; i++) if (!skipDepth(r, depth + 1)) return false;
    }
    r.pos++;
    return true;
  }
  if (h.arg > r.n) return fail(r);   // more entries than bytes left: not CBOR
  for (uint64_t i = 0; i < h.arg * per_entry; i++) if (!skipDepth(r, depth + 1)) return false;
  return true;
}

static bool skipDepth(CborReader& r, int depth) {
  if (depth > CBOR_DEPTH_MAX) return fail(r);
  Head h;
  if (!readHead(r, &h)) return false;
  switch (h.major) {
    case MAJOR_UINT:
    case MAJOR_NEG:
    case MAJOR_SIMPLE:
      return true;
    case MAJOR_BYTES:
    case MAJOR_TEXT:
      if (h.indefinite) return skipEntries(r, h, depth);
      if (h.arg > r.n - r.pos) return fail(r);
      r.pos += (size_t)h.arg;
      return true;
    case MAJOR_TAG:
      return skipDepth(r, depth + 1);   // the tagged item
    default:
      return skipEntries(r, h, depth);
  }
}

bool cborSkip(CborReader& r) { return skipDepth(r, 0); }

// Reads the head of the next item if it has one of the two majors; otherwise
// leaves the item in place for the caller to skip.
static bool headIf(CborReader& r, uint8_t major_a, uint8_t major_b, Head* h) {
  if (r.bad || r.pos >= r.n) return fail(r);
  const uint8_t major = r.p[r.pos] >> 5;
  if (major != major_a && major != major_b) return false;
  return readHead(r, h);
}

static bool skipAndFalse(CborReader& r) {
  cborSkip(r);
  return false;
}

bool cborInt(CborReader& r, int64_t* out) {
  Head h;
  if (!headIf(r, MAJOR_UINT, MAJOR_NEG, &h)) return r.bad ? false : skipAndFalse(r);
  if (h.arg > (uint64_t)INT64_MAX) return false;
  *out = (h.major == MAJOR_UINT) ? (int64_t)h.arg : -1 - (int64_t)h.arg;
  return true;
}

static double halfToDouble(uint16_t half) {
  const int exponent = (half >> 10) & 0x1F;
  const int mantissa = half & 0x3FF;
  double value;
  if (exponent == 0) value = ldexp(mantissa, -24);
  else if (exponent != 31) value = ldexp(mantissa + 1024, exponent - 25);
  else value = mantissa == 0 ? INFINITY : NAN;
  return (half & 0x8000) ? -value : value;
}

static bool floatValue(const Head& h, double* out) {
  if (h.info == INFO_HALF) {
    *out = halfToDouble((uint16_t)h.arg);
  } else if (h.info == INFO_SINGLE) {
    const uint32_t bits = (uint32_t)h.arg;
    float f;
    memcpy(&f, &bits, sizeof(f));
    *out = f;
  } else if (h.info == INFO_DOUBLE) {
    const uint64_t bits = h.arg;
    memcpy(out, &bits, sizeof(*out));
  } else {
    return false;   // a simple value (true, false, null, ...)
  }
  return true;
}

bool cborNumber(CborReader& r, double* out) {
  if (r.bad || r.pos >= r.n) return fail(r);
  const uint8_t major = r.p[r.pos] >> 5;
  if (major == MAJOR_UINT || major == MAJOR_NEG) {
    int64_t v = 0;
    if (!cborInt(r, &v)) return false;
    *out = (double)v;
    return true;
  }
  Head h;
  if (major != MAJOR_SIMPLE || !readHead(r, &h)) return r.bad ? false : skipAndFalse(r);
  return floatValue(h, out);
}

// A definite string of the given major; an indefinite one is skipped.
static bool stringHead(CborReader& r, uint8_t major, Head* h) {
  if (!headIf(r, major, major, h)) return r.bad ? false : skipAndFalse(r);
  if (h->indefinite) {
    skipEntries(r, *h, 0);
    return false;
  }
  if (h->arg > r.n - r.pos) return fail(r);
  return true;
}

bool cborText(CborReader& r, char* out, size_t cap) {
  Head h;
  if (cap == 0 || !stringHead(r, MAJOR_TEXT, &h)) return false;
  const size_t len = (size_t)h.arg;
  size_t keep = len < cap - 1 ? len : cap - 1;
  // Cut where a character ends: a UTF-8 continuation byte (10xxxxxx) at the
  // cut belongs to the character before it.
  if (keep < len) while (keep > 0 && (r.p[r.pos + keep] & 0xC0) == 0x80) keep--;
  memcpy(out, r.p + r.pos, keep);
  out[keep] = '\0';
  r.pos += len;
  return true;
}

bool cborBytes(CborReader& r, uint8_t* out, size_t cap, size_t* len) {
  Head h;
  if (!stringHead(r, MAJOR_BYTES, &h)) return false;
  const size_t n = (size_t)h.arg;
  r.pos += n;
  if (n > cap) return false;
  memcpy(out, r.p + r.pos - n, n);
  *len = n;
  return true;
}

static bool containerBegin(CborReader& r, uint8_t major, CborContainer* c) {
  Head h;
  if (!headIf(r, major, major, &h)) return r.bad ? false : skipAndFalse(r);
  c->indefinite = h.indefinite;
  c->left = h.indefinite ? 0 : h.arg;
  return true;
}

bool cborMapBegin(CborReader& r, CborContainer* m) { return containerBegin(r, MAJOR_MAP, m); }
bool cborArrayBegin(CborReader& r, CborContainer* a) { return containerBegin(r, MAJOR_ARRAY, a); }

// Whether another entry follows; at the end of an indefinite one the break is consumed.
static bool entryFollows(CborReader& r, CborContainer& c) {
  if (r.bad) return false;
  if (c.indefinite) {
    if (r.pos >= r.n) return fail(r);
    if (r.p[r.pos] != BREAK_BYTE) return true;
    r.pos++;
    return false;
  }
  if (c.left == 0) return false;
  c.left--;
  return true;
}

bool cborMapNextKey(CborReader& r, CborContainer& m, int64_t* key) {
  while (entryFollows(r, m)) {
    if (cborInt(r, key)) return true;
    if (r.bad || !cborSkip(r)) return false;   // a key of another type: skip its value too
  }
  return false;
}

bool cborArrayNext(CborReader& r, CborContainer& a) { return entryFollows(r, a); }
