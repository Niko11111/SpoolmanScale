#pragma once

// ============================================================
//  TAG WRITE / ERASE POPUP
//
//  Two questions that only make sense with a tag on the reader,
//  built the same way and answered the same way:
//
//   - after a link the user made on the device: put the spool
//     data on the tag as well
//   - after an unlink: take it off again
//
//  Both hand the work to tagWriteRequest() and report the
//  outcome as its own modal. The status line cannot be used for
//  that: appLoop() repaints it from the NFC poll later in the
//  same pass, so a result written there is gone unread.
//
//  Bambu and MIFARE tags never get here, neither can be written.
// ============================================================

// Asks whether to write the spool onto the tag. No HTTP and no NFC of its own,
// so it is safe to call from appLoop() right after a link.
void showTagWriteAskPopup(int spool_id);

// Asks whether to erase the tag as well. Parked rather than built, because the
// unlink that leads here runs inside an LVGL callback and tears down its own
// screen on the way out.
// Writes the tag for a spool that was just linked, with no question in front
// of it - what g_tagwrite_mode == TAGWRITE_ALWAYS asks for. The result is
// reported exactly as it is after a confirmed question.
void startTagWriteNoAsk(int spool_id);

void requestTagEraseAsk();

// Checks the tag on the reader against the spool it is bound to and offers to
// write it again when the two disagree. Loop task only - it fetches the spool.
// Does nothing unless g_tagmismatch_ask is on.
void tagMismatchTick();

bool isTagWritePopupOpen();

// Closes the overlay once the callback that asked for it has returned, starts
// the write or the erase, and shows the result when it is done. Called from
// appLoop() like the other deferred UI work.
void handleTagWritePopupDeferredActions();
