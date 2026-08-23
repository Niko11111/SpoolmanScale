#pragma once

// ============================================================
//  AUTO AMS ASSIGNMENT SCREEN
//
//  Mode picker plus the window length, reached from the FilaMan "More
//  options" screen. Both settings that live on the server are read when the
//  screen opens and written when they are changed.
// ============================================================

// Builds the overlay. Reads from and writes to FilaMan, so this must only
// ever run from appLoop() by way of show_ams_assign_pending, never from an
// LVGL callback.
void buildAmsAssignScreen();

// Human readable name of the active mode, for the row in "More options".
const char* amsModeName();
