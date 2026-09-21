#pragma once

// ============================================================
//  THE CARD THAT STANDS WHILE A TAG IS WRITTEN OR ERASED
//
//  Writing a record takes two to three seconds and erasing an NTAG215 about
//  four: 124 pages at some 30 ms each. The loop task does that work itself,
//  so for those seconds nothing moves - and until now nothing on the screen
//  said so either. The question had closed, the main screen stood there as
//  if the matter were settled, and the natural thing to do with a spool one
//  has just answered a question about is to pick it up. A tag lifted off the
//  antenna halfway is a half written tag.
//
//  So this says what is going on and what not to do, from the tap to the
//  result. No button: there is nothing to decide, and nobody could press it.
//
//  Loop task only. Never from an LVGL callback: showing it redraws the screen
//  on the spot, because the very next thing the caller does is block.
// ============================================================

// `erase` picks the wording. Does nothing when the card is already up.
void tagBusyShow(bool erase);

// Takes it down again. Safe to call when it is not there.
void tagBusyHide();
