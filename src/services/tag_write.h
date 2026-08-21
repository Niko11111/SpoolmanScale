#pragma once

#include <Arduino.h>

enum TagFormat : uint8_t {
  TAG_FMT_ACE = 0,        // Anycubic ACE: raw pages, read by the ACE itself
  TAG_FMT_OPENSPOOL = 1,  // OpenSpool: NDEF application/json, what FilaMan resolves
  TAG_FMT_ERASE = 2,      // zero the data pages
};

// Parks a request. The write itself runs in tagWriteTick(), because the NFC
// bus belongs to the loop task and the HTTP handler is not on it.
// link also writes the tag's UID onto the spool record, so presenting it
// selects that spool.
bool tagWriteRequest(int spool_id, TagFormat fmt, bool link);
void tagWriteTick();

const char* tagWriteState();     // idle | pending | ok | error
const char* tagWriteMessage();

// Last reader state, refreshed on the loop task. The HTTP handler must use
// these rather than touching the reader itself: its page reads would race the
// main NFC poll and come back with fields missing.
const char* tagCachedUid();
const char* tagCachedKind();
const char* tagCachedContent();
// linked receives the UID already on the spool record, "" if none. Both
// backends hold a single tag, so linking a second one replaces the first.
bool tagPreview(int spool_id, TagFormat fmt, char *out, size_t out_len,
                char *linked, size_t linked_len);
