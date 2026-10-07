#include "dried_marker.h"

#include <string.h>

#define DRIED_MARKER_NEW  "[last_dried:"
#define DRIED_MARKER_OLD  "[dried:"
#define DRIED_DAY_LEN     10

// Where the marker starts, where its date starts, and the closing bracket.
// Only a marker whose date is exactly ten characters counts.
static bool findMarker(const char* note, const char** start, const char** day,
                       const char** close) {
  if (!note) return false;
  const char* s = strstr(note, DRIED_MARKER_NEW);
  const char* d = s ? s + strlen(DRIED_MARKER_NEW) : nullptr;
  if (!s) {
    s = strstr(note, DRIED_MARKER_OLD);
    if (!s) return false;
    d = s + strlen(DRIED_MARKER_OLD);
  }
  const char* c = strchr(d, ']');
  if (!c || c - d != DRIED_DAY_LEN) return false;
  *start = s;
  *day   = d;
  *close = c;
  return true;
}

bool driedMarkerParse(const char* note, char* day_out, size_t out_size) {
  if (!day_out || out_size < DRIED_MARKER_DAY_MAX) return false;
  const char *start, *day, *close;
  if (!findMarker(note, &start, &day, &close)) return false;
  memcpy(day_out, day, DRIED_DAY_LEN);
  day_out[DRIED_DAY_LEN] = '\0';
  return true;
}

// Trims spaces at both ends of out, in place.
static void trimSpaces(char* out) {
  size_t len = strlen(out);
  while (len > 0 && out[len - 1] == ' ') out[--len] = '\0';
  size_t lead = 0;
  while (out[lead] == ' ') lead++;
  if (lead) memmove(out, out + lead, len - lead + 1);
}

void driedMarkerStrip(const char* note, char* out, size_t out_size) {
  if (!out || out_size == 0) return;
  out[0] = '\0';
  if (!note) return;

  const char *start, *day, *close;
  const char* tail = nullptr;
  size_t head_len = strlen(note);
  if (findMarker(note, &start, &day, &close)) {
    head_len = (size_t)(start - note);
    tail = close + 1;
    // One space goes with the marker, so "a [m] b" becomes "a b".
    if (*tail == ' ') tail++;
    else if (head_len > 0 && note[head_len - 1] == ' ') head_len--;
  }

  if (head_len >= out_size) head_len = out_size - 1;
  memcpy(out, note, head_len);
  out[head_len] = '\0';
  if (tail) strncat(out, tail, out_size - head_len - 1);
  trimSpaces(out);
}

bool driedMarkerNewer(const char* marker_day, const char* native_day) {
  if (!marker_day || !marker_day[0]) return false;
  if (!native_day || !native_day[0]) return true;
  return strncmp(marker_day, native_day, DRIED_DAY_LEN) > 0;
}
