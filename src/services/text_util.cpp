#include "text_util.h"

#include <string.h>

void utf8Cut(const char* s, size_t max_bytes, char* out, size_t out_size) {
  if (!out || !out_size) return;
  out[0] = '\0';
  if (!s) return;
  size_t n = strlen(s);
  if (n > max_bytes) n = max_bytes;
  if (n >= out_size) n = out_size - 1;
  // Back off to the start of the sequence the cut landed in: a continuation
  // byte is 10xxxxxx.
  while (n > 0 && ((unsigned char)s[n] & 0xC0) == 0x80) n--;
  memcpy(out, s, n);
  out[n] = '\0';
}

static bool isHexDigit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

bool isHexColorWord(const char* s) {
  if (!s) return false;
  if (*s == '#') s++;
  size_t n = strlen(s);
  // Six digits is RRGGBB, eight is RRGGBBAA. Three would be the CSS short
  // form, but it is also the length of a real name, and "fab" as a colour
  // name is likelier than "fab" as a colour.
  if (n != 6 && n != 8) return false;
  for (size_t i = 0; i < n; i++) {
    if (!isHexDigit(s[i])) return false;
  }
  return true;
}

void colorNameClean(const char* in, char* out, size_t out_size) {
  if (!out || !out_size) return;
  out[0] = '\0';
  if (!in || !in[0]) return;
  if (isHexColorWord(in)) return;

  size_t n = strlen(in);
  // A trailing "(11101)" is the manufacturer's article number, which several
  // catalogues glue onto the colour name. The detail card shows the article
  // number under its own caption, and on a bay tile it is what pushes a name
  // past the width, so it goes.
  if (n > 2 && in[n - 1] == ')') {
    size_t open = n - 1;
    while (open > 0 && in[open - 1] != '(') open--;
    if (open > 0) {
      bool digits = (open < n - 1);
      for (size_t i = open; i < n - 1 && digits; i++) {
        if (in[i] < '0' || in[i] > '9') digits = false;
      }
      if (digits) {
        n = open - 1;                            // drop the '(' as well
        while (n > 0 && in[n - 1] == ' ') n--;   // and the space before it
      }
    }
  }

  utf8Cut(in, n, out, out_size);
}
