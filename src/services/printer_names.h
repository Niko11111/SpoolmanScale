#pragma once

#include <stddef.h>

// ============================================================
//  PRINTER NAMES
//
//  A printer profile can stand for several models that take the
//  same bytes ("B1, B21, B203"). Not all of them have been printed
//  on: those are listed apart, so a picker can mark each model on
//  its own. Pure text work, no profile table, so it runs on the host.
// ============================================================

// The separator between models in a profile's name and in its list of
// untried ones.
#define PRINTER_NAME_SEPARATOR ", "

// Called once per model in a name, in order. The text is not terminated:
// len says how long it is.
typedef void (*PrinterNameFn)(const char* model, size_t len, bool untried, void* ctx);

// Walks "PM245-BT, PM241-BT" model by model; a model is untried when it is
// in the untried list exactly as written. A null list means all are tried.
void printerNameEach(const char* names, const char* untried, PrinterNameFn fn, void* ctx);

// Fills order[0..n) with 0..n-1 sorted for a picker: brands in the order they
// first appear, inside a brand by name. Stable for equal entries.
void printerSortByBrand(const char* const* brands, const char* const* names, int* order, int n);
