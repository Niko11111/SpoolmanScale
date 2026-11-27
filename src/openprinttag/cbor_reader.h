#pragma once

// A small pull reader for the CBOR an OpenPrintTag carries (RFC 8949): integers
// with every argument width, byte and text strings, arrays and maps of definite
// and indefinite length, half, single and double floats. Semantic tags and
// simple values are skipped, never interpreted. Pure: no Arduino, tested on
// the host (test/test_openprinttag.py).
//
// Every read either takes the item it expected or skips whatever item is there
// instead and returns false, so a field of an unexpected type never puts the
// reader out of step with the map around it. Malformed input (an item running
// past the end, nesting deeper than CBOR_DEPTH_MAX) sets bad, after which
// every call returns false.

#include <stddef.h>
#include <stdint.h>

#define CBOR_DEPTH_MAX 8

struct CborReader {
  const uint8_t* p;
  size_t n;      // bytes the reader may look at
  size_t pos;
  bool bad;
};

inline CborReader cborReader(const uint8_t* p, size_t n) { return CborReader{p, n, 0, false}; }

// Within a map or array of indefinite length, the next byte is its end.
bool cborAtBreak(const CborReader& r);

// One whole item, nested ones included.
bool cborSkip(CborReader& r);

// An unsigned or negative integer.
bool cborInt(CborReader& r, int64_t* out);
// An integer or a float.
bool cborNumber(CborReader& r, double* out);
// A text string, cut to cap - 1 bytes (at a UTF-8 character boundary) and terminated.
bool cborText(CborReader& r, char* out, size_t cap);
// A byte string of at most cap bytes; a longer one is skipped and false.
bool cborBytes(CborReader& r, uint8_t* out, size_t cap, size_t* len);

// Walking a map or an array: begin, then next until it returns false.
struct CborContainer {
  bool indefinite;
  uint64_t left;   // entries still to come when definite
};
bool cborMapBegin(CborReader& r, CborContainer* m);
bool cborArrayBegin(CborReader& r, CborContainer* a);
// The next key of a map. Entries whose key is not an integer are skipped. The
// caller reads or skips the value before asking again. False at the end of the
// map (which is then consumed) or on malformed input.
bool cborMapNextKey(CborReader& r, CborContainer& m, int64_t* key);
// Whether another array element follows (the end is consumed when not).
bool cborArrayNext(CborReader& r, CborContainer& a);
