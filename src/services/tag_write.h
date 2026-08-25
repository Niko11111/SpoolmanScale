#pragma once

#include <Arduino.h>

enum TagFormat : uint8_t {
  TAG_FMT_ACE = 0,        // Anycubic ACE: raw pages, read by the ACE itself
  TAG_FMT_OPENSPOOL = 1,  // OpenSpool: NDEF application/json, what FilaMan resolves
  TAG_FMT_ERASE = 2,      // zero the data pages
};

// What the last write ended in. The message next to it is English prose meant
// for the web page; the device screen needs an id it can translate, and this
// file cannot include lang.h because T() collides with ArduinoJson.
enum TagWriteResult : uint8_t {
  TW_NONE = 0,        // nothing has run yet
  TW_BUSY,            // parked, waiting for the loop task
  TW_OK,
  TW_ERR_NO_TAG,      // nothing on the reader
  TW_ERR_NOT_NTAG,    // 4 byte UID, read-only for us
  TW_ERR_BACKEND,     // the spool could not be fetched
  TW_ERR_SPACE,       // too small, or no NDEF capability container
  TW_ERR_WRITE,       // a page write failed part way through
};

// Parks a request. The write itself runs in tagWriteTick(), because the NFC
// bus belongs to the loop task and the HTTP handler is not on it.
// link also writes the tag's UID onto the spool record, so presenting it
// selects that spool.
bool tagWriteRequest(int spool_id, TagFormat fmt, bool link);
void tagWriteTick();

// The same write without the detour through the parking slot: fetches the
// spool, builds the record and puts it on the tag. Only for callers that are
// already on the loop task - it talks to the reader and to the backend, so it
// must never be reached from an LVGL callback.
bool tagWriteSpoolNow(int spool_id, TagFormat fmt);

// Whether the tag the main poll is looking at can be written at all. Answered
// from what that poll already found, so it never competes with it for the
// reader. Both UI paths ask before they offer to write.
bool tagIsWritableNtag();

// Parks a scan trigger from FilaMan. The tag on the reader is sent back on
// the next tick, or the request expires.
void tagScanRequest();

// FilaMan's write trigger can carry the tag contents as an OpenSpool record.
// They are parked until the user confirms on the device: the server decided
// what goes on the tag, not the scale. Two fields are corrected on the way in,
// because FilaMan describes the spool for its own protocol rather than for the
// tag - spool_id and location_id are dropped, and sm_id is added, which is
// what points a written tag back at the spool.
// spool_id is the request's own id, used for that sm_id.
void tagRemotePayloadSet(const char *json, int spool_id);
bool tagRemotePayloadPending();
bool tagWriteRemotePayload();

const char* tagWriteState();     // idle | pending | ok | error
const char* tagWriteMessage();
uint8_t     tagWriteResultCode();   // a TagWriteResult, for the device screen

// Last reader state, refreshed on the loop task. The HTTP handler must use
// these rather than touching the reader itself: its page reads would race the
// main NFC poll and come back with fields missing.
const char* tagCachedUid();
const char* tagCachedKind();
const char* tagCachedContent();
// linked receives the UID already on the spool record, "" if none. Both
// backends hold a single tag, so linking a second one replaces the first.
// Field by field view of a tag, so the page can show it as a swatch rather
// than one line of text. Empty strings and zeros mean the format does not
// carry that field.
struct TagInfo {
  char     fmt[12];        // ACE, OpenSpool, blank, unknown
  char     sku[17];
  char     brand[17];
  char     material[17];
  bool     has_color;
  uint8_t  r, g, b;
  uint16_t et_lo, et_hi, bed_lo, bed_hi;
  uint16_t dia_x100, length_m, weight_g;
};

// Serialises a TagInfo as a JSON object, omitting fields the format lacks.
void tagInfoJson(const TagInfo *ti, char *out, size_t out_len);

// Last complete read of the tag on the reader. fmt is empty when there is none.
const TagInfo* tagCachedInfo();

bool tagPreview(int spool_id, TagFormat fmt, char *out, size_t out_len,
                char *linked, size_t linked_len, TagInfo *info = nullptr);
