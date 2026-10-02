#pragma once

void showMoreInfoScreen();
void requestLocationPicker(bool from_popup);
// The location button itself. Like requestLocationPicker(), but it opens the
// picker for an archived spool too: tapped, the location is asked for. The
// automatic offers call requestLocationPicker() and leave archived spools out.
void tapLocationButton(bool from_popup);
void handleMoreInfoDeferredActions();

// Both More Info pickers, released from hideAllOverlays(). Without this a
// picker left open survives a navigation change and sits on top of whatever
// comes next.
void hideMoreInfoOverlays();
// Frees the unlink confirmation, for the navigation.
void closeMoreInfoPopups();
