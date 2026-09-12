#pragma once

void updateLinkButton();

// Places zone 4's right half on a device with no load cell: whether the AMS
// button is there, and where the note sits as a result. Does nothing at all on
// a device that has a scale, where neither object was built.
//
// Called from updateHeaderStatus(), which already runs on every backend switch
// - the button belongs to FilaMan and BamBuddy, and the backend can be changed
// while the main screen exists.
void updateAmsAffordance();
