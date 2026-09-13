#pragma once

void closeConfirmPopup();
void showConfirmPopup(const char* msg, int action);
bool isConfirmPopupOpen();
// Runs whatever a popup button parked - the weight, tare, archive and cap
// writes. Called from appLoop().
void handleConfirmPopupDeferredActions();
// Every dialog this file owns, for the navigation. Closed, not hidden: a
// question nobody can see any more must not keep uiModalWaiting() true.
void closeConfirmPopups();

// Asked when BamBuddy's own inventory would clamp the measurement to the
// label weight. Built from appLoop(), never from a write path.
void showBamBuddyCapPopup(float measured_g, float label_g);
