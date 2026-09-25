#pragma once

#include "services/label_printer.h"

// ============================================================
//  THE PRINT CARD
//
//  One card for a print from start to answer. While the session runs it
//  says where it stands - preparing, looking for the printer, connecting,
//  sending, printing - and then turns into the answer in the same place:
//  confirmed by the printer, sent without a confirmation, or not printed
//  and why. A confirmed print closes on its own after a few seconds; a
//  problem waits for OK.
//
//  The session blocks the loop, so while it runs the card is drawn by
//  printCardTick(), which the session calls as its progress callback.
// ============================================================

// Opens the card in its busy state, "preparing the label".
void printCardShow();

// The session's progress callback: follows bleSessionPhase() and redraws,
// at most every few tens of milliseconds.
void printCardTick();

// The answer. text_id is labelPrintResultString(result) for a failure.
void printCardResult(LabelPrintResult result);

bool printCardOpen();

// From appLoop(): closes the card when OK or the countdown asked for it,
// never from the card's own callback.
void printCardLoop();
