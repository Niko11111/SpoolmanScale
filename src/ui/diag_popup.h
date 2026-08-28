#pragma once

#include "services/diagnostics.h"

// The detail behind the banner: what the device thinks is wrong, why the
// symptom looks the way it does, and which wire or button to reach for.
//
// Shaped like showInfoPopup(..., INFO_WARN) and deliberately not built on it:
// that one has a single button nailed to a fixed position, and half of these
// findings need a second one that leads somewhere. Everything a button does is
// deferred through a pending flag - a popup that opened a screen from inside
// its own callback would be deleting the object the event belongs to.
void showDiagPopup(DiagCode c);
