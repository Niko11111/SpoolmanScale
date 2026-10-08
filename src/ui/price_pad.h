#pragma once

// ============================================================
//  PRICE PAD
//
//  A keypad for what a spool cost, over everything else: digits, one point,
//  two decimals. Empty is a valid answer and means "no price". The currency
//  is the one the server keeps, so none is shown. Built on demand and freed
//  again; its own buttons only park their answer, pricePadTick() hands it on
//  and deletes the pad from the loop.
// ============================================================

// Opens the pad with `current` filled in (0: empty). `done` gets the price,
// 0 for an emptied field; on Cancel it is not called.
void showPricePad(float current, void (*done)(float price));

bool pricePadOpen();
void closePricePad();

// From the loop: carries out OK or Cancel, which the pad's buttons parked.
void pricePadTick();
