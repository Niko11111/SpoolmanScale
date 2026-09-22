#pragma once

// ============================================================
//  TAG VIEW
//
//  What the tag on the reader holds, opened from the NFC chip in
//  the header. A card in the More Info card's measurements, with
//  the two things that can be done to an NTAG from here: erase it,
//  or write the spool the scale shows onto it - the same question
//  a link asks, for when that one was answered with no.
//
//  Reads the cache tag_write.cpp keeps on the loop task and never
//  the reader itself: a read from here would race the main poll.
// ============================================================

// The chip's callback sets show_tag_view_pending (app/deferred_actions.h);
// this builds the card from appLoop(), carries out its buttons, and builds it
// again whenever what it shows has changed - a tag put down or lifted while
// it stands.
void handleTagViewDeferredActions();

bool isTagViewOpen();

// Released asynchronously, so safe from a callback. hideAllOverlays() calls it.
void closeTagView();
