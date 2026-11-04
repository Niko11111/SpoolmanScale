#include "services/label_facts.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "lang.h"
#include "services/backend.h"
#include "services/text_util.h"

static bool hasText(const char* s) { return s && s[0]; }

// Whether a colour is six hex digits, which the label writes with its '#'.
static bool isHex6(const char* s) {
  if (strlen(s) != 6) return false;
  for (int i = 0; i < 6; i++)
    if (!isxdigit((unsigned char)s[i])) return false;
  return true;
}

// The date as the layout wants it: the first use where the backend
// recorded one, else the day the spool was added; or always the latter.
// False when the backend gave neither.
static bool dateFact(const SpoolLabelData& spool, const LabelLayout& layout, LabelFact* out) {
  const bool added_only = labelLayoutOption(layout, LO_DATE_ADDED);
  if (!added_only && spool.first_used[0]) { *out = LabelFact{ T(STR_LBL_L_FIRST), spool.first_used }; return true; }
  if (spool.added[0]) { *out = LabelFact{ T(STR_LBL_L_ADDED), spool.added }; return true; }
  return false;
}

// The temperatures as one fact: "Nozzle 240-270 °C", or with the bed
// "Nozzle/bed 220/55 °C". False when the backend gave no nozzle.
static bool tempFact(const SpoolLabelData& spool, char* value, size_t n, LabelFact* out) {
  if (spool.nozzle_max <= 0) return false;
  char nozzle[16];
  if (spool.nozzle_min > 0) snprintf(nozzle, sizeof(nozzle), "%d-%d", spool.nozzle_min, spool.nozzle_max);
  else snprintf(nozzle, sizeof(nozzle), "%d", spool.nozzle_max);
  if (spool.bed_temp > 0) snprintf(value, n, "%s/%d \xC2\xB0" "C", nozzle, spool.bed_temp);
  else snprintf(value, n, "%s \xC2\xB0" "C", nozzle);
  *out = LabelFact{ T(spool.bed_temp > 0 ? STR_LBL_L_TEMPS : STR_LBL_L_NOZZLE), value };
  return true;
}

// What the filament wants in the dryer, "85 °C / 8 h". False when neither the
// backend nor the tag named both.
static bool dryingFact(const SpoolLabelData& spool, char* value, size_t n, LabelFact* out) {
  if (spool.dry_temp_c <= 0 || spool.dry_hours <= 0) return false;
  snprintf(value, n, "%d \xC2\xB0" "C / %d h", spool.dry_temp_c, spool.dry_hours);
  *out = LabelFact{ T(STR_LBL_L_DRYING), value };
  return true;
}

// Appends a fact while the list has room; the value is copied in.
static void addFact(LabelFactList* l, int capacity, const LabelFact& f) {
  if (l->n >= capacity || l->n >= LABEL_MAX_FACTS) return;
  const char* value = nullptr;
  // Cut on a character boundary: a location or the own line can be longer
  // than the room, and half an umlaut prints as a box.
  if (hasText(f.value)) {
    utf8Cut(f.value, sizeof(l->values[0]) - 1, l->values[l->n], sizeof(l->values[0]));
    value = l->values[l->n];
  }
  char joined[sizeof(l->lines[0]) * 2];
  // "Added: 30.04.26", with the colon as the language sets it.
  if (hasText(f.caption) && value) snprintf(joined, sizeof(joined), T(STR_LBL_FACT_FMT), f.caption, value);
  else snprintf(joined, sizeof(joined), "%s", hasText(f.caption) ? f.caption : (value ? value : ""));
  char* line = l->lines[l->n];
  utf8Cut(joined, sizeof(l->lines[0]) - 1, line, sizeof(l->lines[0]));
  l->facts[l->n] = LabelFact{ f.caption, value };
  l->line_ptrs[l->n] = line;
  l->n++;
}

// The facts after the date, each off by default: the weights, the
// temperatures and the drying, where the spool is kept and when it was
// dried, the own line.
static void addSpoolExtras(LabelFactList* out, int capacity, const LabelLayout& layout,
                           const SpoolLabelData& spool) {
  char grams[16];
  if (labelLayoutHas(layout, LF_SPOOL_WEIGHT) && spool.spool_weight_g > 0) {
    snprintf(grams, sizeof(grams), "%.0f g", spool.spool_weight_g);
    addFact(out, capacity, LabelFact{ T(STR_LBL_L_EMPTY), grams });
  }
  if (labelLayoutHas(layout, LF_NET_WEIGHT) && spool.net_weight_g > 0) {
    snprintf(grams, sizeof(grams), "%.0f g", spool.net_weight_g);
    addFact(out, capacity, LabelFact{ T(STR_LBL_L_NET), grams });
  }
  char temps[32];
  LabelFact t;
  if (labelLayoutHas(layout, LF_TEMPS) && tempFact(spool, temps, sizeof(temps), &t))
    addFact(out, capacity, t);
  char dry[24];
  if (labelLayoutHas(layout, LF_DRYING) && dryingFact(spool, dry, sizeof(dry), &t))
    addFact(out, capacity, t);
  if (labelLayoutHas(layout, LF_LOCATION) && spool.location[0])
    addFact(out, capacity, LabelFact{ T(STR_LBL_L_STORED), spool.location });
  if (labelLayoutHas(layout, LF_DRIED) && spool.dried[0])
    addFact(out, capacity, LabelFact{ T(STR_LBL_L_DRIED), spool.dried });
  // The own line has no caption: it prints large, like a value.
  if (labelLayoutHas(layout, LF_FREE_TEXT) && labelLayoutFreeText()[0])
    addFact(out, capacity, LabelFact{ nullptr, labelLayoutFreeText() });
}

void labelSpoolFacts(const LabelLayout& layout, const SpoolLabelData& spool, int capacity,
                     LabelFactList* out) {
  *out = LabelFactList{};
  // What stays true for the spool's whole life: where it is kept, the colour
  // and when it came into use. The rest and the place change, and a label
  // that shows them is wrong a week later (Nikolai, 25.09.2026).
  char id[12];
  char color[sizeof(spool.color) + 1];
  snprintf(id, sizeof(id), "#%d", spool.id);
  snprintf(color, sizeof(color), isHex6(spool.color) ? "#%s" : "%s", spool.color);
  // The compact arrangement moves the maker down here, as the first fact.
  if (layout.preset == LABEL_PRESET_COMPACT && labelLayoutHas(layout, LF_VENDOR) &&
      spool.vendor[0])
    addFact(out, capacity, LabelFact{ nullptr, spool.vendor });
  if (labelLayoutHas(layout, LF_SPOOL_ID) && !labelPresetIsBigId(layout.preset))
    addFact(out, capacity, LabelFact{ backendName(), id });
  if (labelLayoutHas(layout, LF_COLOR) && spool.color[0])
    addFact(out, capacity, LabelFact{ T(STR_LBL_L_COLOR), color });
  if (labelLayoutHas(layout, LF_ARTICLE) && spool.article[0])
    addFact(out, capacity, LabelFact{ T(STR_LBL_ARTICLE_NO_SHORT), spool.article });
  LabelFact date;
  if (labelLayoutHas(layout, LF_DATE) && dateFact(spool, layout, &date)) addFact(out, capacity, date);
  addSpoolExtras(out, capacity, layout, spool);
  if (labelLayoutHas(layout, LF_BRAND)) addFact(out, capacity, LabelFact{ "SpoolmanScale", nullptr });
}

void labelFilamentFacts(const LabelLayout& layout, const SpoolLabelData& spool, int capacity,
                        LabelFactList* out) {
  *out = LabelFactList{};
  char color[sizeof(spool.color) + 1];
  snprintf(color, sizeof(color), isHex6(spool.color) ? "#%s" : "%s", spool.color);
  if (layout.preset == LABEL_PRESET_COMPACT && labelLayoutHas(layout, LF_VENDOR) &&
      spool.vendor[0])
    addFact(out, capacity, LabelFact{ nullptr, spool.vendor });
  if (labelLayoutHas(layout, LF_COLOR) && spool.color[0])
    addFact(out, capacity, LabelFact{ T(STR_LBL_L_COLOR), color });
  if (labelLayoutHas(layout, LF_ARTICLE) && spool.article[0])
    addFact(out, capacity, LabelFact{ T(STR_LBL_ARTICLE_NO_SHORT), spool.article });
  // In the page's order, which is the order they give way in.
  char grams[16];
  if (labelLayoutHas(layout, LF_NET_WEIGHT) && spool.net_weight_g > 0) {
    snprintf(grams, sizeof(grams), "%.0f g", spool.net_weight_g);
    addFact(out, capacity, LabelFact{ T(STR_LBL_L_NET), grams });
  }
  char temps[32];
  LabelFact t;
  if (labelLayoutHas(layout, LF_TEMPS) && tempFact(spool, temps, sizeof(temps), &t))
    addFact(out, capacity, t);
  char dry[24];
  if (labelLayoutHas(layout, LF_DRYING) && dryingFact(spool, dry, sizeof(dry), &t))
    addFact(out, capacity, t);
  if (labelLayoutHas(layout, LF_FREE_TEXT) && labelLayoutFreeText()[0])
    addFact(out, capacity, LabelFact{ nullptr, labelLayoutFreeText() });
  if (labelLayoutHas(layout, LF_BRAND)) addFact(out, capacity, LabelFact{ "SpoolmanScale", nullptr });
}
