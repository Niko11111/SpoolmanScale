#pragma once

void closeConfirmPopup();
void showConfirmPopup(const char* msg, int action);
bool isConfirmPopupOpen();

// Asked when BamBuddy's own inventory would clamp the measurement to the
// label weight. Built from appLoop(), never from a write path.
void showBamBuddyCapPopup(float measured_g, float label_g);
