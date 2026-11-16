#pragma once

// ============================================================
//  PRICE PAD
//
//  A keypad for what a spool cost, as the large popup over a card's
//  Options (spool_options_popup.h): digits, one point, two decimals. Empty is a valid answer and means "no price". The currency
//  is the one the server keeps, so none is shown. Built on demand and freed
//  again; its own buttons only park their answer, pricePadTick() hands it on
//  and deletes the pad from the loop.
// ============================================================

// Opens the pad with `current` filled in (0: empty). `done` is called from the
// loop either way: with ok and the price, 0 for an emptied field, or without
// ok after Back, the price then as it was.
void showPricePad(float current, void (*done)(bool ok, float price));

bool pricePadOpen();
void closePricePad();

// From the loop: carries out OK or Back, which the pad's buttons parked.
void pricePadTick();
