#pragma once

#include <stdint.h>

void updateLinkButton();

// The status line's resting text while a tag lies on the pad: found, found
// more than once, archived or unknown. The NFC poll repaints it every half
// second, so it stands aside while a message about the same tag is held.
void paintTagStatus();

// A message an action puts on the status line, a link that did not go
// through say. The repaint above used to write over it within half a second,
// so nobody ever saw one. Held while the same tag stays on the pad, for
// STATUS_MESSAGE_HOLD_MS; a different tag ends it at once.
void statusMessageShow(const char* text, uint32_t color);

// Shows or hides every way into the AMS view: the header chip on any device,
// and on one without a load cell zone 4's right half, which also decides where
// the note sits as a result.
//
// Called from updateHeaderStatus(), which already runs on every backend switch
// - the way in belongs to FilaMan and BamBuddy, and the backend can be changed
// while the main screen exists - and from amsPresenceTick() when the printer's
// answer arrives, which is minutes after the header was built.
void updateAmsAffordance();
