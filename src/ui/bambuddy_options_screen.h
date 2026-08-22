#pragma once

// ============================================================
//  BAMBUDDY OPTIONS
//
//  Settings that only mean anything in BamBuddy mode, reached
//  from the filament manager screen. Same idea as the FilaMan
//  options screen next to it.
// ============================================================

void buildBamBuddyOptionsScreen();

// Where the drying date goes. Its own screen because the choice is three way
// and "More options" is a list of settings, not the settings themselves.
void buildBamBuddyDriedScreen();
