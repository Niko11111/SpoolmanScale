#pragma once

#include <stdint.h>
#include <lvgl.h>

#include "services/spool_color.h"
#include "ui/color_tile_popup.h"

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

// Material, maker and colour swatch of a Bambu tag that does not match its
// spool, from whichever side tagSpoolLookupShowsSpool() names. Temperature and
// everything else stay as they are. Nothing but repainting three labels.
void applyTagSpoolView();

// The main screen's colour swatch, painted and remembered for the colour tile
// it opens. Every paint of that swatch goes through here, or the tile would
// show another colour than the square it was opened from. `second` is a two
// colour spool's other colour, nullptr for one colour.
void mainSwatchPaint(const SpoolColor& c, const SpoolColor* second);

// The second colour of the Bambu tag on the pad when `shown` is the tag's own
// colour, nullptr otherwise: a server colour that won is one colour only.
const SpoolColor* tagSecondColor(const SpoolColor& shown);

// What the tile shows for the main screen's swatch: the colour remembered
// above and the filament name on screen.
ColorTileSpec mainSwatchTileSpec();

// Makes the status line the switch between the two: tappable, and only
// answering while tag and spool differ. Once, where the line is built.
void tagSpoolViewAttach(lv_obj_t* status_label);

// The nozzle temperature once the backend has answered, from the filament's
// x_extruder_temp_min and settings_extruder_temp (0 for none). The backend
// wins over the tag on the pad, which counts only when the backend has no
// value; spoolTempShown() holds the rule. `maker_tag` is a Bambu, Creality or
// Snapmaker tag decoded into g_tag. Nothing known on either side leaves the
// label as it is.
void mainShowBackendTemp(int backend_lo, int backend_hi, bool maker_tag);

// Shows or hides every way into the AMS view: the header chip on any device,
// and on one without a load cell zone 4's right half, which also decides where
// the note sits as a result.
//
// Called from updateHeaderStatus(), which already runs on every backend switch
// - the way in belongs to FilaMan and BamBuddy, and the backend can be changed
// while the main screen exists - and from amsPresenceTick() when the printer's
// answer arrives, which is minutes after the header was built.
void updateAmsAffordance();

// Whether the AMS button on a device without a load cell offers the shown
// spool for a bay rather than just the view. No network: the backend mode,
// the spool on screen and, for FilaMan, an empty spool weight to report the
// stored weight with. Read by the button's callback and by its caption, so
// the two cannot disagree.
bool amsMainCanAssign();

// The button's caption and the fill behind it: "AMS" view, "Into AMS", or the
// seconds a FilaMan window has left with the fill draining along. Called on
// every loop pass and cheap when nothing changed.
void updateAmsMainButton();
