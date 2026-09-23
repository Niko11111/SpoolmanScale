#pragma once

#include <stddef.h>

// ============================================================
//  THE CARD WHILE THE LINK LIST COMES IN
//
//  The spool list for linking is loaded on the backend worker now, so the
//  loop keeps running while it comes in - and a wait that can be left can
//  finally offer a way out. The house card that the tag write question, its
//  waiting card and its result stand on: spinner, title, the kilobytes read
//  so far, and Cancel in the row of answers.
//
//  Cancel only raises a flag, the loop takes it with linkWaitCardCancelTake():
//  closing the card from inside its own event handler would delete the
//  button that is handling the event.
// ============================================================

void linkWaitCardShow();
void linkWaitCardHide();
bool linkWaitCardOpen();

// The kilobytes read so far; 0 leaves the line empty. Cheap enough to call
// every loop pass, it only redraws when the number changed.
void linkWaitCardBytes(size_t bytes);

// True once after Cancel was pressed.
bool linkWaitCardCancelTake();
