#pragma once

// ============================================================
//  A NUMBER AT ANY HEIGHT
//
//  Draws digits from their outlines (label_digits_data.h), for a
//  spool's number that should fill what a label has left. The
//  label fonts stop at 48 px and each size costs flash; the
//  outlines of all ten digits cost under 3 KB and come out sharp
//  at any size, on 203 and 300 dpi alike.
//
//  Pure logic, in dots: the caller says what a row of dots means.
//  Only the characters 0-9 count, anything else is skipped.
// ============================================================

// A row of `w` dots starting at x, y. `ctx` is the caller's.
typedef void (*LabelDigitRun)(int x, int y, int w, void* ctx);

// The width of the digits, from the first ink to the last, at this height.
int labelDigitsWidth(const char* digits, int height);
// The tallest height, at most max_h, at which the digits fit max_w.
int labelDigitsFitHeight(const char* digits, int max_w, int max_h);
// Where the digits go: their first ink at x, their top at y.
struct LabelDigitsAt { int x, y, height; };
void labelDigitsDraw(const char* digits, const LabelDigitsAt& at, LabelDigitRun run, void* ctx);
