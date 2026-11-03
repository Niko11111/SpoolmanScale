#pragma once

#include <stddef.h>
#include <string.h>

// Whether a link a server names for one of its spools may go onto a label. It
// comes from a stranger's answer and ends up in a printed QR code that outlives
// the answer, so anything odd is refused whole: a shortened link is a wrong
// link, and the caller has its own to fall back on. Pure logic: no Arduino, no
// state.

// Room for one, the same a label's QR code has.
#define SPOOL_LINK_LEN  128

// Plain visible ASCII, without what never belongs in a link and could close a
// quote or a tag where the text is shown again.
inline bool spoolLinkCharOk(char c) {
  return c > ' ' && c < 0x7f && c != '"' && c != '\'' && c != '<' && c != '>' &&
         c != '\\' && c != '`';
}

// An http or https address with something after the scheme, at most max_len
// characters long.
inline bool spoolLinkOk(const char* url, size_t max_len) {
  if (!url) return false;
  size_t scheme = 0;
  if (strncmp(url, "https://", 8) == 0) scheme = 8;
  else if (strncmp(url, "http://", 7) == 0) scheme = 7;
  else return false;
  const size_t len = strlen(url);
  if (len <= scheme || len > max_len) return false;
  for (size_t i = 0; i < len; i++)
    if (!spoolLinkCharOk(url[i])) return false;
  return true;
}
