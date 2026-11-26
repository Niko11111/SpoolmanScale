#pragma once

#include <stdint.h>

// ============================================================
//  WHAT A SPOOL CREATED OFF THE PAD STARTS WITH
//
//  Read off the pad once, when a spool is created: the full weight to file,
//  what is left on it, and a word on how the reading was taken. Pure
//  arithmetic, no backend. The tag card, the database pick and the copy flow
//  all go through it, so one rule decides for all three.
//
//  The rule (decided 24.10.2026): the empty spool is the trustworthy number
//  and the filament is measured against it. A full spool whose empty weight
//  someone stored (on the filament, the brand, a catalog entry, the copy's
//  template) files its measured net as its full weight - the label is what
//  the maker promised, the pad says what is there. A full spool on Bambu's
//  fixed 250 g core keeps the label as its full weight: the real cores vary
//  by 11 g, as much as the fill the measurement is after. The measured net is
//  filed as what is left either way. Nothing on the pad, or more than a full
//  spool can weigh, files the label as full and says so.
// ============================================================

// How far the empty spool's weight is to be trusted.
enum TareQuality : uint8_t {
  TARE_Q_NONE = 0,   // nothing known
  TARE_Q_DEFAULT,    // a maker's fixed figure, Bambu's 250 g core
  TARE_Q_KNOWN       // stored by someone: filament, brand, catalog, template
};

// How far an empty spool weight is to be trusted. `fixed_default` says the
// tag brought a maker's fixed figure of `default_g`; a stored weight that
// says exactly that figure is that figure and nothing more. The scale itself
// files the 250 g core on the brand and the filament it creates, so from the
// second Bambu spool on the entry would otherwise pass as a measurement.
TareQuality spoolTareQuality(int tare_g, bool fixed_default, int default_g);

// What the reading says about the spool on the pad.
enum StartVerdict : uint8_t {
  START_NOT_WEIGHED = 0,  // nothing on the pad, or no more than the empty spool
  START_NO_TARE,          // a spool on the pad, but nothing to subtract from it
  START_FULL,             // within the tolerance around the label
  START_PARTIAL,          // used: below the label
  START_OVER              // above what a full spool can weigh: a box, two spools
};

struct SpoolStart {
  int          initial_g;    // the full weight to file
  float        remaining_g;  // what the spool starts with
  float        net_g;        // the reading minus the empty spool; -1 when not weighed
  int          label_g;      // the inputs, echoed for the card's line
  int          tare_g;
  StartVerdict verdict;
};

// gross_g: the pad's reading. tare_g: the empty spool, 0 when unknown.
// label_g: the maker's filament weight, 0 when none. The band for "full"
// comes from app_config.h (START_FULL_TOL_PCT, START_FULL_TOL_MIN_G) and
// widens by START_TARE_DEFAULT_SLACK_G on a default tare.
SpoolStart spoolStartValues(float gross_g, int tare_g, TareQuality tare_q, int label_g);

// The full weight taken for a spool nothing names one for: a net reading
// within the full band of a nominal size (NEWTAG_LABEL_CHOICES) is that size,
// anything else a used spool of NEWTAG_LABEL_ASSUMED_G, or of the smallest
// size above it that holds the reading (with its band and the default-tare
// slack, so 1040 g is still a 1000 g spool). NEWTAG_LABEL_ASSUMED_G for no reading
// (net_g below START_MIN_NET_G, -1 when not weighed).
int spoolAssumedLabelG(float net_g);

// One word for the log.
const char* spoolStartVerdictName(StartVerdict v);
