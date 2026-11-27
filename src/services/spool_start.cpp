#include "services/spool_start.h"

#include <math.h>

#include "app_config.h"

// Filed as full: the label as the full weight and as what is left.
static SpoolStart asFull(int label_g, int tare_g, float net_g, StartVerdict verdict) {
  SpoolStart s;
  s.initial_g   = label_g;
  s.remaining_g = (float)label_g;
  s.net_g       = net_g;
  s.label_g     = label_g;
  s.tare_g      = tare_g;
  s.verdict     = verdict;
  return s;
}

// How far a net reading may lie from the label and still be a full spool.
static float fullBand(int label_g) {
  return fmaxf((float)label_g * START_FULL_TOL_PCT / 100.0f, START_FULL_TOL_MIN_G);
}

TareQuality spoolTareQuality(int tare_g, bool fixed_default, int default_g) {
  if (tare_g <= 0) return TARE_Q_NONE;
  if (fixed_default && tare_g == default_g) return TARE_Q_DEFAULT;
  return TARE_Q_KNOWN;
}

SpoolStart spoolStartValues(float gross_g, int tare_g, TareQuality tare_q, int label_g) {
  if (tare_g <= 0 || tare_q == TARE_Q_NONE) {
    // Without an empty spool the reading cannot be split into spool and
    // filament. An empty pad is still told from a spool on it, for the card.
    const StartVerdict v = gross_g < START_MIN_NET_G ? START_NOT_WEIGHED : START_NO_TARE;
    return asFull(label_g, 0, -1.0f, v);
  }
  const float net = gross_g - (float)tare_g;
  if (net < START_MIN_NET_G) return asFull(label_g, tare_g, -1.0f, START_NOT_WEIGHED);

  float tol = fullBand(label_g);
  if (tare_q == TARE_Q_DEFAULT) tol += START_TARE_DEFAULT_SLACK_G;
  if (label_g > 0 && net > (float)label_g + tol) return asFull(label_g, tare_g, net, START_OVER);

  SpoolStart s = asFull(label_g, tare_g, net, START_FULL);
  s.remaining_g = net;
  if (label_g > 0 && net < (float)label_g - tol) {
    s.verdict = START_PARTIAL;          // used: the label stays the full weight
  } else if (tare_q == TARE_Q_KNOWN || label_g <= 0) {
    s.initial_g = (int)lroundf(net);    // full, against an empty spool someone stored
  }
  return s;
}

int spoolAssumedLabelG(float net_g) {
  static const int sizes[NEWTAG_LABEL_COUNT] = NEWTAG_LABEL_CHOICES;
  if (!(net_g >= START_MIN_NET_G)) return NEWTAG_LABEL_ASSUMED_G;
  for (int g : sizes)
    if (fabsf(net_g - (float)g) <= fullBand(g)) return g;
  // A reading just above a size is that size on a stored empty spool a little
  // too light, as spoolStartValues() allows on a default one.
  for (int g : sizes)
    if (g >= NEWTAG_LABEL_ASSUMED_G && net_g <= (float)g + fullBand(g) + START_TARE_DEFAULT_SLACK_G)
      return g;
  return sizes[NEWTAG_LABEL_COUNT - 1];
}

const char* spoolStartVerdictName(StartVerdict v) {
  switch (v) {
    case START_NOT_WEIGHED: return "not weighed";
    case START_NO_TARE:     return "no tare";
    case START_FULL:        return "full";
    case START_PARTIAL:     return "partial";
    case START_OVER:        return "over";
  }
  return "?";
}
