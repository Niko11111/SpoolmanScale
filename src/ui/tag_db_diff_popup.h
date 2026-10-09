#pragma once

#include <lvgl.h>

#include "services/tag_db_match.h"

// ============================================================
//  TAG AND DATABASE DISAGREE
//
//  Over the new-spool card, when the backend's filament database knows the
//  tag's filament but says something else about it (services/tag_db_match.h):
//  one row per value, the tag's beside the database's, and two answers.
//  Keeping the tag is the first one; the tag is trusted more. Built on
//  demand, its buttons only park the answer, tagDbDiffPopupTick() hands it
//  on and deletes the box from the loop.
// ============================================================

// `done` gets true when the database's values are to be taken.
void showTagDbDiffPopup(const TagDbDiff* diffs, int n, void (*done)(bool take_db));

bool tagDbDiffPopupOpen();
void closeTagDbDiffPopup();

// From the loop: carries out the answer the buttons parked.
void tagDbDiffPopupTick();
