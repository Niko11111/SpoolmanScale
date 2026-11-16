#pragma once

#include <lvgl.h>

#include "services/spool_choice.h"

// ============================================================
//  THE EMPTY SPOOL LISTS UNDER A CARD'S OPTIONS
//
//  Three pages of the large popup, built into a box spool_options_popup.cpp
//  made: which empty spool (automatic and the last ones), the makers of the
//  built-in catalog, and one maker's spools. Two columns of tiles, the name
//  over the weight, the way the BamBuddy core picker draws them
//  (db_pick_core_popup.cpp). A tap is handed to the owner as a number; the
//  owner changes pages from the loop, never from the tap itself.
// ============================================================

// What a tap on a page means. A tile answers with its index: on the first
// page 0 is Automatic, then the last choices and the user's own (the macros
// below), on the makers' page the maker, on a maker's page the spool. The
// buttons answer below 0.
#define SPICK_TAP_MAKERS  (-1)
#define SPICK_TAP_TYPE    (-2)
#define SPICK_TAP_BACK    (-3)
#define SPICK_TAP_KEEP    (-4)   // the choice already made
#define SPICK_TAP_RECENT(i)  (1 + (i))
#define SPICK_TAP_MINE(i)    (100 + (i))
#define SPICK_TAP_SERVER(i)  (200 + (i))
// A letter of the makers' strip: 0 for a digit, 1-26 for A-Z.
#define SPICK_LETTERS     27
#define SPICK_TAP_LETTER(letter)  (-100 - (letter))
#define SPICK_LETTER_OF_TAP(tap)  (-100 - (tap))
typedef void (*SpoolPickTap)(int tap);

// What the first page shows.
struct SpoolPickList {
  const SpoolChoice* current;   // the card's choice, inactive for Automatic
  const SpoolChoice* recent;    // SPOOL_RECENT_MAX of them, inactive ones skipped
  int auto_tare_g;              // what Automatic weighs against, 0 when unknown
  int auto_from;                // STR_ id: where that comes from
  int auto_name;                // STR_ id of the first tile, 0 for Automatic
  const SpoolChoice* mine;      // the user's own (services/spool_mine.h)
  int mine_n;
  const SpoolChoice* server;    // the backend's (backendServerSpools())
  int server_n;
};

void spoolPickBuildList(lv_obj_t* box, const SpoolPickList& list, SpoolPickTap tap);
// The makers whose name starts with `letter`, under a strip of every letter
// that leads one: 77 tiles at once would not fit the LVGL pool, a letter's
// are nine at most. `mark` is a maker framed in green (the card's own), -1
// for none.
void spoolPickBuildMakers(lv_obj_t* box, int letter, int mark, SpoolPickTap tap);
// The letter a maker's name starts with; for -1 the first letter in use.
int spoolPickLetterOf(int maker);
void spoolPickBuildMaker(lv_obj_t* box, int maker, const SpoolChoice* current, SpoolPickTap tap);

// "Plastic | 1 kg", "Cardboard | 750 g", "Spool": what tells a maker's
// spools apart, for a tile and the Options row.
void spoolPickKindText(const SpoolChoice& c, char* out, size_t out_size);
