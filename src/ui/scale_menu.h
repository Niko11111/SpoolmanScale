#pragma once

void buildScaleSubScreen();

// Remembers where the list was scrolled to, for the rebuild that follows a
// toggle. Call it immediately before deleting the screen.
void scaleSubScrollRemember();

// Drops the remembered list without keeping its offset. For the paths that
// delete the screen and do not rebuild it - navigating away, not toggling.
void scaleSubScrollForget();

// The tag write screen behind the scale menu's "write tag" row: the switch
// and the format on one screen. Built here rather than in a file of its own,
// the way the BamBuddy drying screen sits with its options screen.
void buildTagWriteScreen();
