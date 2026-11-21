#pragma once

#include <stddef.h>

// ============================================================
//  TEXT UTILITIES
//
//  String handling that is neither LVGL nor backend, so both
//  sides can reach it. It lived in ui_common until an AMS parser
//  needed the colour name cleaned before it was stored rather
//  than each time it was drawn - see colorNameClean() below for
//  why that distinction cost a closing bracket.
// ============================================================

// At most max_bytes of s into out, never cutting through a multi-byte UTF-8
// sequence. "%.8s" cut "Köln" between the two bytes of the ö and a box stood
// where the letter was.
void utf8Cut(const char* s, size_t max_bytes, char* out, size_t out_size);

// True when a "colour name" is really a colour written as a number:
// "009BD8", "#ffffff", "FF00FF00". FilaMan's Spoolman import writes the hex
// code into manufacturer_color_name, and that field is what the display API
// hands out as color_name - so a bay can arrive carrying "009BD8" where a
// name belongs.
bool isHexColorWord(const char* s);

// The colour name as it should be kept: empty when there is none or when it
// is only a hex code, and without the article number some catalogues append,
// so "Charcoal (11101)" becomes "Charcoal".
//
// Called where the name enters the firmware, not where it is drawn. Cleaning
// on the way out was a bug: "Charcoal (11101)" is exactly 16 characters,
// AMS_COLOR_NAME_MAX is 16, and the parser's strncpy therefore stored
// "Charcoal (11101" without the closing bracket - after which there was no
// bracket left to strip and the tile showed the stump.
void colorNameClean(const char* in, char* out, size_t out_size);

// How many bytes of the name stay when its colour name comes off the end,
// matched word for word: case, accents, hyphens and an article number
// "(11101)" do not count. "PLA+ High Flow Fire Engine Red" with "Fire Engine
// Red" keeps "PLA+ High Flow", "PLA Jade-White" with "Jade White" keeps "PLA",
// "Matte - Charcoal (11101)" with "Charcoal" keeps "Matte". The whole name
// where it does not end with the colour name ("PLA Weiss" with "White"), or
// is nothing but it: a label that prints the colour name on its own line
// takes it out of the title only where the title keeps something.
size_t nameColorNameCut(const char* name, const char* color);

// True when the filament name already opens with the material. Spoolman's own
// naming does this, and BamBuddy's mapping always does ("PETG HF Orange"), so
// prefixing the material a second time would read "PETG PETG HF Orange".
bool nameStartsWithMaterial(const char* name, const char* material);

// Material and filament name as one line, without saying anything twice: a
// name that holds the whole material as a word anywhere ("Hyper PLA Gelb")
// stays as it is, and a name that repeats the material's subtype ("PLA
// Tough+" with "Tough+ Cyan") has the shared words written once.
void joinMaterialName(const char* material, const char* name, char* out, size_t out_size);
