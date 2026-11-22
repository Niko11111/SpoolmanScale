#pragma once

#include <stdint.h>

// ============================================================
//  TAG LINK
//
//  Binds the tag lying on the reader to a spool without writing
//  the tag, for the tag page in the browser: a MIFARE card, a
//  Snapmaker or Bambu tag, or an NTAG whose contents should stay.
//
//  The backend write is patchSpoolTag(), the one the link flow on
//  the device ends in, so every kind of tag and every tag source
//  behaves as it does there - a Bambu tag through its tray uuid,
//  anything else through its chip uid, Spoolman's own relation,
//  the list field, the spool cache and the uid index.
//
//  The same queue takes the tag off a spool (More Info's unlink),
//  moves it from the spool that holds it to another, and checks
//  before a write that links that no other spool holds the tag.
//
//  Nothing here touches the reader. The main poll has read the
//  tag and its uid is in g_tag; linking is a request to the
//  backend and nothing else. The HTTP handler only parks it,
//  tagLinkTick() carries it out on the loop task.
// ============================================================

enum TagLinkResult : uint8_t {
  TL_NONE = 0,
  TL_BUSY,        // parked, or waiting for a tag write to finish
  TL_OK,          // linked
  TL_ALREADY,     // the tag already binds this spool, nothing written
  TL_HELD,        // another spool holds the tag, other_spool names it
  TL_CHANGED,     // the tag on the reader is not the one the page showed
  TL_NO_TAG,      // no tag on the reader any more
  TL_NETWORK,     // the server did not answer
  TL_FAILED,      // the server answered and refused
  TL_MISMATCH,    // a Bambu tag that does not describe the spool, nothing written
  TL_UNLINKED,    // the tag was taken off other_spool
  TL_NOT_LINKED,  // no spool holds the tag, there was nothing to take off
  TL_NOT_SHOWN,   // other_spool holds the tag but is not the spool the scale shows
  TL_ON_FILAMENT, // Spoolman binds the tag to filament other_spool, not to a spool
  TL_WRITE_REFUSED, // the write could not be parked, another one is running
  TL_UNLINK_FAILED, // the unlink was sent, and the server still finds other_spool by the tag
};

// What was asked for. The page words the outcome and the question by it.
enum TagLinkJob : uint8_t {
  TLJ_LINK = 0,   // bind the tag to the spool
  TLJ_MOVE,       // take it off the spool that holds it, then bind or write
  TLJ_UNLINK,     // take it off whichever spool holds it
  TLJ_WRITE,      // write and link, once the server says no other spool holds it
};

// Codes and ids rather than a sentence: this file cannot include lang.h (T()
// collides with ArduinoJson), so the page says it in the user's language.
struct TagLinkReport {
  uint8_t code;
  int     spool_id;
  int     other_spool;
  // TL_MISMATCH: what the tag and the spool say, material and colour, for the
  // page's question. Data, not a sentence.
  char    tag_desc[40];
  char    spool_desc[64];
  uint8_t job;          // TagLinkJob
  int     from_spool;   // TLJ_MOVE: the spool the tag was to be taken off
  bool    write;        // a write follows the binding check (TLJ_WRITE, or a move for one)
  uint8_t fmt;          // its TagFormat
  // TLJ_MOVE: the tag is already off from_spool when what followed failed. It
  // then belongs to no spool, which the page has to say.
  bool    unlinked;
};

// Parks a link of the tag the page showed - uid as tagCachedUid() gave it -
// to spool_id. False when a link is already waiting or an argument is empty.
// force: the page has asked about a Bambu tag that does not match the spool
// (TL_MISMATCH) and the answer was to link it all the same.
bool tagLinkRequest(int spool_id, const char* uid, bool force = false);

// A write that links, from the tag page. The server is asked first who holds
// the tag; another spool's tag is not written, the report says TL_HELD and the
// page asks whether to move it. Otherwise the write is handed to
// tagWriteRequest() as it always was. fmt is a TagFormat.
bool tagLinkWriteRequest(int spool_id, const char* uid, uint8_t fmt);

// The page's answer to TL_HELD: take the tag off from_spool, then link it to
// spool_id, or write and link it when write_fmt is a TagFormat (-1: link
// only). Refused on the loop when the server names a holder other than
// from_spool by then. force as for tagLinkRequest().
bool tagLinkMoveRequest(int spool_id, const char* uid, int from_spool, int write_fmt,
                        bool force);

// Takes the tag on the reader off whichever spool holds it. Only the spool
// the scale shows can be unlinked (TL_NOT_SHOWN otherwise): its bindings are
// the ones the last lookup captured. A Bambu tag takes every binding of its
// spool with it, both chips carry the same tray uuid.
bool tagUnlinkRequest(const char* uid);

// From appLoop(), after tagWriteTick(). Waits while a tag write is running.
void tagLinkTick();

const TagLinkReport* tagLinkReportData();

// A write started from the page speaks for the tag from then on, and the
// link's last answer steps back so the page shows the write's. The write's
// state stays "ok" or "error" until the next one, so the page shows a link
// answer that stands before it. Nothing while a request is parked.
void tagLinkReportClear();

// The spool a link has just bound, handed out once so the main screen can show
// it, the way tagWriteTakeLinkedSpool() does for a write. 0 otherwise.
int tagLinkTakeLinkedSpool();

// The link a tag write asks for on Spoolman, made the way the device's own
// link makes it: through patchSpoolTag(), so it reaches Spoolman's own tag
// relation and grows a list field instead of overwriting it. The plain field
// write the other backends use has no key to write to for the relation.
// From the loop only. Answers in HTTP terms for the write's report: 200
// linked, 409 another spool holds the tag, -1 the server was not reached,
// 400 the server refused.
int tagLinkAfterWrite(int spool_id, const char* uid);

// Whether a link leaves the spool's other tags bound: Spoolman's own relation,
// and a list field with appending switched on. Everywhere else the new tag
// takes the place of the old one, and the page's question has to say so.
bool tagLinkKeepsOtherTags();
