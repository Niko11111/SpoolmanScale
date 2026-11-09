#pragma once

// ============================================================
//  A NEW SPOOL WITHOUT A TAG
//
//  Started from the Spool by ID pad ("+ New spool") for a spool that has no
//  tag at all. The copy flow's entry then runs as it does for a blank tag -
//  a template from the list, a template by its id, or New from database -
//  and only its end differs: finishCopyFlow() shows the new spool by its id
//  (app/id_spool.h) and a card with its number, instead of linking a tag.
//
//  The mode counts only while no tag data stands. A tag put down halfway is
//  linked as always once its lookup gave it a UID; before that there is
//  nothing to link, and the card with the number comes all the same. A mode
//  left over by a flow that was cancelled can never turn a flow with a tag
//  into one without.
// ============================================================

// Loop task only: clears what a lifted tag left on the display, so nothing
// of it steers the flow, and opens New / Copy in this mode.
void copyTaglessStart();

// The entries that start from a tag reset the mode.
void copyTaglessEnd(const char* why);

// True while the mode is on and no tag data stands.
bool copyTaglessActive();

// For finishCopyFlow(): ends the mode and says whether the spool just
// created is to be shown without a tag - true unless a tag with a UID to
// link turned up meanwhile.
bool copyTaglessTake();
