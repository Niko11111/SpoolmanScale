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
};

// Codes and ids rather than a sentence: this file cannot include lang.h (T()
// collides with ArduinoJson), so the page says it in the user's language.
struct TagLinkReport {
  uint8_t code;
  int     spool_id;
  int     other_spool;
};

// Parks a link of the tag the page showed - uid as tagCachedUid() gave it -
// to spool_id. False when a link is already waiting or an argument is empty.
bool tagLinkRequest(int spool_id, const char* uid);

// From appLoop(), after tagWriteTick(). Waits while a tag write is running.
void tagLinkTick();

const TagLinkReport* tagLinkReportData();

// The spool a link has just bound, handed out once so the main screen can show
// it, the way tagWriteTakeLinkedSpool() does for a write. 0 otherwise.
int tagLinkTakeLinkedSpool();

// Whether a link leaves the spool's other tags bound: Spoolman's own relation,
// and a list field with appending switched on. Everywhere else the new tag
// takes the place of the old one, and the page's question has to say so.
bool tagLinkKeepsOtherTags();
