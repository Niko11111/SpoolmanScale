#pragma once

void buildConnectionScreen();
// Deletes the screen together with its 2 s IP refresh timer and the label the
// timer writes. Every delete of scr_connection goes through here.
void closeConnectionScreen();
