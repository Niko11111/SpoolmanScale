#pragma once

// ============================================================
//  FILAMAN FIELDS SCREEN
//
//  Which field carries the tag, and how much of FilaMan's Bambu Lab plugin
//  the scale keeps up to date. Reached from the FilaMan "More options"
//  screen, and the counterpart to the extra fields menu Spoolman has.
//
//  Nothing here reads the server: all three rows describe what this firmware
//  does, not what the server holds. So unlike the AMS screen it can be built
//  straight from a callback - it is deferred anyway, because a screen must
//  not be built from inside the callback of the screen it replaces.
// ============================================================

void buildFilaManFieldsScreen();
