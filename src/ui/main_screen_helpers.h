#pragma once

void updateLinkButton();

// Shows or hides every way into the AMS view: the header chip on any device,
// and on one without a load cell zone 4's right half, which also decides where
// the note sits as a result.
//
// Called from updateHeaderStatus(), which already runs on every backend switch
// - the way in belongs to FilaMan and BamBuddy, and the backend can be changed
// while the main screen exists - and from amsPresenceTick() when the printer's
// answer arrives, which is minutes after the header was built.
void updateAmsAffordance();
