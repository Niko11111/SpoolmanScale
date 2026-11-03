#pragma once

// A server refused a weight because it knows no empty weight for the spool and
// will not guess one. Says so and offers the entry, since that is what it takes.
void showTareMissingPopup();

// Counts as a modal: it waits for an answer like the other questions.
bool isTareMissingOpen();

// Every loop pass. Closes it once another spool is loaded: the entry it offers
// would go to that spool.
void tareMissingTick();
