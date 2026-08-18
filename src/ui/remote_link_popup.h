#pragma once

// ============================================================
//  REMOTE LINK POPUP
//
//  Shown when FilaMan asked for a link and a tag is on the scale.
//  Confirming reports the UID back to FilaMan, which then sets
//  rfid_uid itself. Nothing is written to the tag.
// ============================================================

// Fetches the spool from the backend and builds the overlay. Does HTTP, so
// call it from appLoop(), never from an LVGL callback.
void showRemoteLinkPopup(int spool_id);

bool isRemoteLinkPopupOpen();

// Deletes the overlay once the callback that asked for it has returned.
// Called from appLoop() like the other deferred UI work.
void handleRemoteLinkDeferredActions();
