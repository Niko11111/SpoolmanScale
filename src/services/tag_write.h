#pragma once

#include <Arduino.h>

enum TagFormat : uint8_t {
  TAG_FMT_ACE = 0,        // Anycubic ACE: raw pages, read by the ACE itself
  TAG_FMT_OPENSPOOL = 1,  // OpenSpool: NDEF application/json, what FilaMan resolves
  TAG_FMT_ERASE = 2,      // zero the data pages
  // The same record under FilaMan's own protocol name. Their server offers the
  // choice between the two names and builds identical fields for both, so this
  // differs from OpenSpool in one string and nothing else. It exists so a tag
  // can be labelled the way a FilaMan installation expects to find it.
  TAG_FMT_FILAMAN = 3,
};

// True for the formats that go on the tag as an NDEF JSON record.
#define TAG_FMT_IS_NDEF(f)  ((f) == TAG_FMT_OPENSPOOL || (f) == TAG_FMT_FILAMAN)

// What a tag has to hold before an NDEF record is worth attempting. The record
// is around 150 to 190 bytes depending on how long the brand and material
// names are, plus the TLV wrapper - so an NTAG213 with 144 bytes of user
// memory can never take one, and the only thing offering it there produces is
// "OpenSpool needs 176 bytes, this tag holds 144".
//
// A floor, not a promise: a tag above it can still be too small for a
// particularly long record, and that write reports what happened as before.
// NTAG215 (496) and NTAG216 (872) clear it with room to spare. Those are the
// sizes the capability container reports, the NDEF area rather than the chip.
#define TAGWRITE_NDEF_MIN_BYTES  176

// The format's name for a log line or a status text. Plain ASCII and not
// translated - these are protocol names, and this file cannot include lang.h
// because T() collides with ArduinoJson's template parameter.
const char* tagFormatLabel(uint8_t fmt);

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

// The format the next write will produce, for the question on the screen:
// whatever protocol name the parked record carries, "OpenSpool" when there is
// none, because that is what the scale builds for itself.
const char* tagRemotePayloadProtocol();

// The spool a write just linked, handed over once and then forgotten. The
// display should show what the tag on the reader now points at, but this file
// runs on the service side and must not reach into the UI - appLoop() takes it
// from here and does the lookup.
int tagWriteTakeLinkedSpool();

const char* tagWriteState();     // idle | pending | ok | error
const char* tagWriteMessage();
uint8_t     tagWriteResultCode();   // a TagWriteResult, for the device screen

// The same answer taken apart, for callers that have to say it in the user's
// language. tagWriteMessage() is English prose and stays that way - it goes
// into the log and back to FilaMan - but the web page is translated, and a
// German page reading "Wrote spool 272 (PLA Army Green) as OpenSpool" is the
// one place that showed. This file cannot reach lang.h (T() collides with
// ArduinoJson's template parameter), so it hands out the parts and the page
// puts the sentence together, the same way the device screen already does with
// tagWriteResultCode().
enum TagLinkState : int8_t {
  TAG_LINK_NONE = 0,   // no link was asked for
  TAG_LINK_OK   = 1,
  TAG_LINK_FAIL = -1,
};
struct TagWriteReport {
  uint8_t  code;        // a TagWriteResult
  bool     erase;       // the job was an erase, not a write
  int      spool_id;
  char     name[48];    // the filament name, empty until the spool was fetched
  uint8_t  fmt;         // a TagFormat
  int8_t   link;        // a TagLinkState
  int      link_http;   // the code the link attempt came back with
  char     link_note[48];  // what the backend said about the link, may be empty
};
const TagWriteReport* tagWriteReportData();

// Last reader state, refreshed on the loop task. The HTTP handler must use
// these rather than touching the reader itself: its page reads would race the
// main NFC poll and come back with fields missing.
const char* tagCachedUid();
const char* tagCachedKind();
// What tagCachedKind() says, as a number, for the translated web page.
enum TagKind : uint8_t {
  TAG_KIND_NONE   = 0,
  TAG_KIND_MIFARE = 1,   // 4 byte UID, this firmware only reads those
  TAG_KIND_NTAG   = 2,   // 7 byte UID, writable; tagCachedBytes() has the size
};
uint8_t     tagCachedKindCode();
const char* tagCachedContent();
// User memory of the tag on the reader, 0 when there is none or it reports no
// size. Read on the loop task with everything else, so a web handler can ask
// without touching the reader.
uint16_t    tagCachedBytes();

// How much room a record of this length needs once it is wrapped in the NDEF
// TLV and rounded up to whole pages. The write and the preview both go through
// this, so the page can turn "it did not fit" into "it will not fit" before
// anything is written.
size_t      tagNdefSizeFor(size_t json_len);
// linked receives the UID the spool is already bound to, from any of the tag
// fields or from Spoolman's relation, normalised to plain hex - and only when
// that is a different tag than the one on the reader. Empty means "nothing to
// warn about": either the spool is unbound, or it is bound to exactly the tag
// the user is holding.
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

// Reads the tag on the reader right now instead of waiting for the next tick,
// so tagCachedInfo() answers within the same loop pass. Only for callers on the
// loop task that have just polled and still hold the tag selected - the main
// NFC poll is the one that does, and it is what the cache reads from anyway.
void tagReadInfoNow();

// True when the cached read holds a record worth showing: a format that was
// recognised, rather than an empty tag or bytes nothing could make sense of.
bool tagCachedHasRecord();

// Whether the record on the tag disagrees with the spool it is bound to.
// want receives what that spool would put on a tag right now, so the caller can
// show both sides. Fetches the spool, so loop task only, never a callback.
//
// Compared are material, brand and colour, and each of the three is skipped
// where one side says nothing:
//  - material by family, PLA against PLA - the scale writes the family and
//    other writers put "PLA Basic" there, which is the same filament
//  - brand only when the spool names a vendor; buildAce() falls back to
//    "Generic", which is an absent vendor rather than a different one
//  - colour only when the spool carries one, over the same distance threshold
//    the link flow uses. A spool with no colour reads as black here and is
//    left alone, so a real black-against-red difference goes unreported - the
//    quiet way round of the two.
bool tagDiffersFromSpool(int spool_id, TagFormat fmt, TagInfo *want);

// need receives the bytes the chosen format will occupy on the tag, so the
// caller can compare it against tagCachedBytes() before offering the write.
bool tagPreview(int spool_id, TagFormat fmt, char *out, size_t out_len,
                char *linked, size_t linked_len, TagInfo *info = nullptr,
                uint16_t *need = nullptr);
