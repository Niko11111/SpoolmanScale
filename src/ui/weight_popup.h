#pragma once

// The popup behind the weight button: one large button that sends the weight,
// the two switches that change what it sends, and the rare things a spool on
// the pad can be asked for one level further down (Options).
void showWeightPopup();

// Both levels; safe from a callback, the deletes are asynchronous.
void closeWeightPopups();

// Either level is on screen. Automatic weighing waits while it is.
bool isWeightPopupOpen();

// Every loop pass. Closes the popup unsent once another spool is loaded: its
// numbers and its button belong to the spool it was opened for.
void weightPopupTick();
