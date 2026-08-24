#pragma once

void showLanguageScreen();

// Deletes the screen if it is up. Used by the time zone screen, which takes
// its place rather than covering it.
void closeLanguageScreen();
