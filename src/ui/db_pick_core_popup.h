#pragma once

#include "services/tag_create.h"

// ============================================================
//  WHICH EMPTY SPOOL?
//
//  The picker's last question, for a database whose entries weigh no
//  spool (BamBuddy's colours): without the empty spool the card cannot
//  subtract it and books the spool as full. The backend's spool catalog
//  (services/filament_db.h, fdbCoreChoices()) often names several for one
//  maker - Overture 237 g in plastic, 150 g in cardboard - so the user
//  picks; the one the inventory used last is first and green. "None of
//  these" goes on without one. Built on demand over the picker; its buttons
//  only park the answer, dbPickCoreTick() carries it out from the loop.
// ============================================================

// Takes over the input of a picked entry. Asks when its maker has two or
// more empty spools, takes the only one without asking. False when there
// is nothing to ask: the caller opens the card with *in as it is now.
bool dbPickCoreAsk(TagCreateInput* in);

bool dbPickCoreOpen();
void dbPickCoreClose();

// From the loop: opens the card with the chosen spool, or closes back to
// the list.
void dbPickCoreTick();
