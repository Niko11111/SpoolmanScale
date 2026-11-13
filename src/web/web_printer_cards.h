#pragma once

#include <Arduino.h>

#include "services/label_printer.h"

// The printer page's own look and its two card pickers. The page builds the
// layout and the script; the pieces that are the same for every visit live
// here, so the page file stays about what it does.

// One <style> block: the Bluetooth bar, the device tile, the scan list and
// the card pickers, all on the shared colour variables.
void webPrinterPageStyle(String& h);

// The manual's page of printers, where the shop links live: never in the
// firmware (Nikolai, 21.10.2026). The manual has German and English; French
// readers get the English page. The anchors name its recommended models.
const __FlashStringHelper* webPrinterDocsUrl();
#define DOCS_ANCHOR_M220 "#phomemo-m220"
#define DOCS_ANCHOR_M2   "#niimbot-m2"

// The model picker, id 'pm'. With a printer set up it is one row naming the
// model and a button to change it; without one, or once that button is
// pressed, the recommended models stand as cards with the way to buy them,
// and the rest fold away under one line, by brand and name. data-m is the
// model the route takes, data-b and data-n its brand and name; the current
// one starts marked.
void webPrinterModelPicker(String& h, const LabelPrinterConfig& c);

// A card per label size, its outline drawn to scale, the planned ones greyed.
// data-fit lists the models that take a size, so the script shows the ones
// the picked model can print on without asking the scale again.
void webPrinterStockCards(String& h, const LabelPrinterConfig& c);
