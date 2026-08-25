#pragma once

// ============================================================
//  TAG WRITE POPUP
//
//  Asked after a link the user made on the device: the spool is
//  known and an NTAG is lying there, so its data can go onto the
//  tag as well. The link itself has already happened - this only
//  ever adds the physical write on top of it.
//
//  Bambu and MIFARE tags never get here, they cannot be written.
// ============================================================

// Builds the overlay. No HTTP and no NFC of its own, so it is safe to call
// from appLoop() right after a link.
void showTagWriteAskPopup(int spool_id);

bool isTagWritePopupOpen();

// Closes the overlay once the callback that asked for it has returned, starts
// the write, and puts the result in the status line when it is done. Called
// from appLoop() like the other deferred UI work.
void handleTagWritePopupDeferredActions();
