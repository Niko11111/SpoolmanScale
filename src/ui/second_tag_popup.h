#pragma once

// ============================================================
//  SECOND TAG POPUP
//
//  Shown right after a link succeeded, while the spool is still on the pad
//  and the user's hands are already on it: turn it over, put the chip on the
//  other flange on the reader, and it joins the same spool.
//
//  It replaces a part with a flow. What the community asked for was a second
//  reader, one per side of the case, so a spool with two chips is recognised
//  whichever way round it lies. The hardware has one reader and one antenna,
//  and no firmware changes that.
//
//  Only a further tag is collected, never a further spool: the spool is the
//  one the link just went to, remembered when the popup opens. A tag that
//  belongs to somebody else is refused by the backend and reported, not
//  stolen.
// ============================================================

// How long the question stands. Generous on purpose - turning a spool over,
// finding the second chip and getting it onto the pad is not a two second job,
// and the only cost of waiting is a popup nobody is looking at.
#define SECOND_TAG_COUNTDOWN_MS  30000

// Builds the overlay. Pure LVGL, no HTTP, safe to call from appLoop().
//
// `first_uid` is the tag that was just linked - the chip uid, not a tray uuid.
// It is what a newly seen tag is compared against, so putting the same tag
// back does not count as an answer.
void showSecondTagPopup(int spool_id, const char* first_uid);

bool isSecondTagPopupOpen();

// Watches the reader, ticks the countdown, and links whatever turned up.
// Called from appLoop(): the link costs HTTP requests, which is exactly what
// an LVGL callback must not carry.
void handleSecondTagDeferredActions();
