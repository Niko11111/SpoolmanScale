#include "text_util.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

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

bool nameStartsWithMaterial(const char* name, const char* material) {
  if (!name || !name[0]) return false;
  if (!material || !material[0]) return true;   // nothing left to prefix with
  return strncasecmp(name, material, strlen(material)) == 0;
}

// The material as a whole word anywhere in the name: product names carry it
// in the middle - "Hyper PLA Gelb", "Silk PLA Weiss", "High Speed Matte PLA" -
// and read "PLA Hyper PLA Gelb" with the material put in front.
static bool nameHasMaterialWord(const char* name, const char* material) {
  const size_t ml = strlen(material);
  if (!ml) return false;
  for (const char* q = name; *q; q++) {
    if (strncasecmp(q, material, ml) != 0) continue;
    const bool start_ok = (q == name) || q[-1] == ' ' || q[-1] == '-';
    const char e = q[ml];
    if (start_ok && (e == '\0' || e == ' ' || e == '-' || e == '+')) return true;
  }
  return false;
}

// Besides a name that repeats the whole material, a name may repeat its
// subtype: Spoolman libraries hold "PLA Tough+" with "Tough+ Cyan" and
// "PETG Translucent" with "Translucent Gray", which read "PLA Tough+ Tough+
// Cyan". The words the two share are written once, and only whole words.
// snprintf cuts at a byte: a last character it cut in half is dropped.
static void dropCutUtf8Tail(char* s) {
  const size_t n = strlen(s);
  size_t j = n;
  while (j > 0 && ((unsigned char)s[j - 1] & 0xC0) == 0x80) j--;
  if (j == 0) return;
  const unsigned char lead = (unsigned char)s[j - 1];
  const size_t want = lead >= 0xF0 ? 4 : lead >= 0xE0 ? 3 : lead >= 0xC0 ? 2 : 1;
  if (n - (j - 1) < want) s[j - 1] = '\0';
}

static void joinMaterialNameRaw(const char* material, const char* name, char* out, size_t out_size) {
  if (!name) name = "";
  if (!material) material = "";
  if (nameStartsWithMaterial(name, material) || nameHasMaterialWord(name, material)) {
    snprintf(out, out_size, "%s", name);
    return;
  }
  for (const char* p = strchr(material, ' '); p; p = strchr(p + 1, ' ')) {
    const char* tail = p + 1;
    const size_t n = strlen(tail);
    if (n && strncasecmp(name, tail, n) == 0 && (name[n] == '\0' || name[n] == ' ')) {
      snprintf(out, out_size, "%s%s", material, name + n);
      return;
    }
  }
  // No name: the material alone, without a trailing space.
  snprintf(out, out_size, "%s%s%s", material, name[0] ? " " : "", name);
}

void joinMaterialName(const char* material, const char* name, char* out, size_t out_size) {
  if (!out || !out_size) return;
  joinMaterialNameRaw(material, name, out, out_size);
  dropCutUtf8Tail(out);
}
