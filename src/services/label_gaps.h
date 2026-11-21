#pragma once

#include <stdint.h>

#include "services/backend.h"
#include "services/label_render.h"

// ============================================================
//  THE FIELDS A SPOOL LEAVES EMPTY
//
//  A switch on the label page can be on and still print nothing:
//  the spool has no location, the backend no drying. The page
//  says so beside the switch, and these two masks tell it which:
//  the fields this spool has no value for, and the fields a
//  backend never sends, so no spool of it will. Bits are
//  LabelField bits. Pure: no NVS, no network, no language table.
// ============================================================

// The fact fields this spool would print nothing for, under these options
// (LO_DATE_ADDED asks for the added date alone). The own line is the page's,
// not the spool's, and is never in it.
uint32_t labelEmptyFields(const SpoolLabelData& spool, uint32_t options);

// The fields this backend has no place for at all.
uint32_t labelBackendLacks(BackendMode mode);

// Whether this backend names a spool's colour, so the label page offers the
// name next to the hex code: BamBuddy and FilaMan do, Spoolman does not.
bool labelBackendHasColorName(BackendMode mode);
