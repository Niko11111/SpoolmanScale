#pragma once

void showMoreInfoScreen();
void requestLocationPicker(bool from_popup);
void handleMoreInfoDeferredActions();

// Both More Info pickers, released from hideAllOverlays(). Without this a
// picker left open survives a navigation change and sits on top of whatever
// comes next.
void hideMoreInfoOverlays();
