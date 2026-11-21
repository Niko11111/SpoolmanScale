#include "services/label_capacity.h"

#include <stdio.h>

#include "app/label_link.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/backend.h"
#include "services/label_facts.h"
#include "services/label_render.h"

// The spool numbers whose links bound the code: the shortest link draws the
// largest code (fewer modules, each of more dots), and on a narrow label a
// long one may not fit at all. A label holds its lines only where both do.
static const int REFERENCE_IDS[] = { 1, 9999 };

// The worst case of the spools the table was measured with (sim fixtures 4,
// 7, 12 and 21): a short maker and name, which the header sets in its largest
// fonts and so makes tallest (a long name is set smaller), the longest fact
// lines and every fact filled. No link of its own: the code carries the one
// this scale prints, built from its server's address.
static SpoolLabelData referenceSpool(int id) {
  SpoolLabelData s{};
  s.id = id;
  snprintf(s.name, sizeof(s.name), "Tough+ Black");
  snprintf(s.vendor, sizeof(s.vendor), "Bambu Lab");
  snprintf(s.material, sizeof(s.material), "PLA Tough+");
  snprintf(s.color, sizeof(s.color), "88FF22");
  // As long as a colour name gets in the inventories seen so far, for a layout
  // that prints the name (LO_COLOR_NAME).
  snprintf(s.color_name, sizeof(s.color_name), "Translucent Light Blue");
  snprintf(s.article, sizeof(s.article), "12104");
  snprintf(s.first_used, sizeof(s.first_used), "03.03.26");
  snprintf(s.added, sizeof(s.added), "26.02.26");
  snprintf(s.location, sizeof(s.location), "Trockenbox");
  snprintf(s.dried, sizeof(s.dried), "10.03.26");
  s.spool_weight_g = 251;
  s.net_weight_g = 1000;
  s.nozzle_max = 245;
  s.bed_temp = 55;
  s.dry_temp_c = 55;
  s.dry_hours = 8;
  return s;
}

// The layout with every fact on, so there are always six lines to try. The
// own line is the page's text, not the spool's; the code stays as set.
static LabelLayout referenceLayout(const LabelLayout& layout) {
  LabelLayout ref = layout;
  const uint32_t code = layout.fields & (1u << LF_QR);
  ref.fields = (labelKindFields(LABEL_KIND_SPOOL) & ~(1u << LF_FREE_TEXT) & ~(1u << LF_QR)) | code;
  return ref;
}

static bool holdsLines(const LabelPrinterConfig& printer, const LabelLayout& ref, int lines,
                       bool code_needed) {
  for (int id : REFERENCE_IDS)
    if (labelSpoolFitsLines(printer, ref, referenceSpool(id), lines, code_needed) != lines) return false;
  return true;
}

static int measuredLines(const LabelPrinterConfig& printer, const LabelLayout& ref, bool code_needed) {
  for (int n = LABEL_MAX_FACTS; n > 0; n--)
    if (holdsLines(printer, ref, n, code_needed)) return n;
  return 0;
}

// Where the code fits with no line at all, the renderer leaves it off: the
// label then holds what it holds without one. Measured with the code still
// asked for, since the renderer lays the lines out as for a label with a code
// (one column), not as for one without (two where they fit).
int labelFactCapacityMeasured(const LabelPrinterConfig& printer, const LabelLayout& layout) {
  const LabelLayout ref = referenceLayout(layout);
  const int lines = measuredLines(printer, ref, true);
  if (lines > 0 || !(ref.fields & (1u << LF_QR))) return lines;
  return measuredLines(printer, ref, false);
}

// FNV-1a: the server's address in the key without keeping a copy of it.
static uint32_t textHash(const char* s) {
  uint32_t h = 2166136261u;
  for (; s && *s; s++) h = (h ^ (uint8_t)*s) * 16777619u;
  return h;
}

// What one measurement depends on. The language: its captions are the lines.
// The server's address and the backend: the code's link is built from both,
// and the backend names the spool number's caption.
struct CapacityKey {
  uint8_t model, preset, id_share, lang, backend;
  uint16_t width_mm, length_mm;
  uint32_t options, link;
  bool code;
};

static bool sameKey(const CapacityKey& a, const CapacityKey& b) {
  return a.model == b.model && a.preset == b.preset && a.id_share == b.id_share &&
         a.lang == b.lang && a.backend == b.backend && a.width_mm == b.width_mm && a.length_mm == b.length_mm &&
         a.options == b.options && a.link == b.link && a.code == b.code;
}

// The label page asks for the spool's and the filament's label in turn, each
// with and without a code: four answers cover it without measuring again.
#define CAPACITY_CACHE_SIZE 4
struct CapacityEntry { CapacityKey key; int capacity; bool used; };
static CapacityEntry s_cache[CAPACITY_CACHE_SIZE];
static int s_cache_next = 0;

static int cachedMeasure(const LabelPrinterConfig& printer, const LabelLayout& layout) {
  const CapacityKey key{ (uint8_t)printer.model, layout.preset, layout.id_share, (uint8_t)g_lang,
                         (uint8_t)backendMode(),
                         printer.media_width_mm, printer.media_length_mm, layout.options,
                         textHash(labelLinkBase()), labelLayoutHasCode(layout) };
  for (const CapacityEntry& e : s_cache)
    if (e.used && sameKey(e.key, key)) return e.capacity;
  const int capacity = labelFactCapacityMeasured(printer, layout);
  s_cache[s_cache_next] = CapacityEntry{ key, capacity, true };
  s_cache_next = (s_cache_next + 1) % CAPACITY_CACHE_SIZE;
  logSDf("Label: %ux%u mm unchecked, preset %u options %02x code %d: %d fact lines measured",
         (unsigned)printer.media_width_mm, (unsigned)printer.media_length_mm,
         (unsigned)layout.preset, (unsigned)layout.options, key.code ? 1 : 0, capacity);
  return capacity;
}

int labelFactCapacityFor(const LabelPrinterConfig& printer, const LabelLayout& layout) {
  if (labelPrinterIsTape(printer.model) ||
      labelMediaChecked(printer.media_width_mm, printer.media_length_mm))
    return labelFactCapacity(layout, printer.media_width_mm, printer.media_length_mm);
  return cachedMeasure(printer, layout);
}

LabelMediaStatus labelMediaStatusFor(LabelPrinterModel model, uint16_t width_mm, uint16_t length_mm) {
  const LabelMediaStatus status = labelMediaStatus(labelPrinterMediaRange(model), width_mm, length_mm);
  if (status != LABEL_MEDIA_UNCHECKED || labelPrinterIsTape(model)) return status;
  LabelPrinterConfig probe{};
  probe.model = model;
  probe.media_width_mm = width_mm;
  probe.media_length_mm = length_mm;
  LabelLayout plain = labelLayoutDefault(LABEL_KIND_SPOOL);
  plain.fields &= ~(1u << LF_QR);
  return labelFactCapacityFor(probe, plain) > 0 ? status : LABEL_MEDIA_TOO_SMALL;
}
