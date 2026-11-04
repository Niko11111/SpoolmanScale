#include "services/label_layout.h"

#include <stdio.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "services/prefs_store.h"
#include "services/text_util.h"

// NVS keys, 15 characters at most: the spool's from before, the filament's
// beside them.
struct LayoutKeys { const char* version; const char* preset; const char* fields; const char* options; const char* id_share; };
static const LayoutKeys LL_KEYS[LABEL_KIND_COUNT] = {
  { "lbl_ver",  "lbl_preset",  "lbl_fields",  "lbl_opts",  "lbl_idshare" },
  { "lblf_ver", "lblf_preset", "lblf_fields", "lblf_opts", "lblf_idshare" },
};
#define LL_KEY_TEXT    "lbl_text"

static const uint32_t FIELD_MASK  = (1u << LABEL_FIELD_COUNT) - 1;
static const uint32_t OPTION_MASK = (1u << LABEL_OPTION_COUNT) - 1;
// What the label printed before the editor: every field up to the brand.
static const uint32_t DEFAULT_FIELDS = (1u << (LF_BRAND + 1)) - 1;
static const uint32_t FILAMENT_FIELDS =
    (1u << LF_VENDOR) | (1u << LF_MATERIAL) | (1u << LF_NAME) | (1u << LF_COLOR) |
    (1u << LF_ARTICLE) | (1u << LF_NET_WEIGHT) | (1u << LF_TEMPS) | (1u << LF_FREE_TEXT) |
    (1u << LF_QR) | (1u << LF_BRAND) | (1u << LF_DRYING);
static const uint32_t FILAMENT_DEFAULT_FIELDS =
    (1u << LF_VENDOR) | (1u << LF_MATERIAL) | (1u << LF_NAME) | (1u << LF_COLOR) |
    (1u << LF_TEMPS) | (1u << LF_QR);

static LabelLayout s_layout[LABEL_KIND_COUNT]{};
static bool s_loaded[LABEL_KIND_COUNT] = {};
static char s_text[LABEL_FREE_TEXT_BYTES] = "";
static bool s_text_loaded = false;

LabelLayout labelLayoutDefault(LabelKind kind) {
  LabelLayout l{};
  l.preset = LABEL_PRESET_STANDARD;
  l.fields = kind == LABEL_KIND_FILAMENT ? FILAMENT_DEFAULT_FIELDS : DEFAULT_FIELDS;
  l.options = 0;
  return l;
}

uint32_t labelKindFields(LabelKind kind) {
  return kind == LABEL_KIND_FILAMENT ? FILAMENT_FIELDS : FIELD_MASK;
}

static LabelKind knownKind(LabelKind kind) {
  return kind < LABEL_KIND_COUNT ? kind : LABEL_KIND_SPOOL;
}

// A filament has no spool number to print large.
static void fitKind(LabelLayout* l, LabelKind kind) {
  l->fields &= labelKindFields(kind);
  if (kind == LABEL_KIND_FILAMENT && labelPresetIsBigId(l->preset)) l->preset = LABEL_PRESET_STANDARD;
}

LabelLayout labelLayoutSanitized(const LabelLayout& in) {
  LabelLayout l = in;
  if (l.preset >= LABEL_PRESET_COUNT) l.preset = LABEL_PRESET_STANDARD;
  l.fields &= FIELD_MASK;
  l.options &= OPTION_MASK;
  if (l.id_share) l.id_share = labelIdShareFor(l.id_share, l.preset);
  return l;
}

bool labelLayoutHas(const LabelLayout& layout, LabelField field) {
  return (layout.fields >> field) & 1u;
}

bool labelLayoutOption(const LabelLayout& layout, LabelOption option) {
  return (layout.options >> option) & 1u;
}

bool labelPresetHasQr(uint8_t preset) {
  return preset != LABEL_PRESET_TEXT_ONLY && !labelPresetIsBigId(preset);
}

bool labelLayoutHasCode(const LabelLayout& layout) {
  return labelLayoutHas(layout, LF_QR) && labelPresetHasQr(layout.preset);
}

// The rolls come 30 mm along the feed, 40 or 50 across. Measured in the
// simulator on 40 x 30 and 50 x 30, flat and upright, with the longest
// lines of the fixture spools: what each arrangement prints without a line
// running into the margin or the code shrinking under its readable size.
#define LL_LONG_ROLL_MM 50
enum CapacityRow { CAP_FLAT_40, CAP_FLAT_50, CAP_UPRIGHT_40, CAP_UPRIGHT_50, CAP_ROWS };
static const uint8_t FACT_CAPACITY[CAP_ROWS][LABEL_PRESET_COUNT] = {
  // standard, compact, big code, material big, text only, big number on top,
  // big number on the right (the last three never have a code)
  { 5, 6, 6, 3, 5, 3, 3 },   // 40 x 30
  { 5, 6, 6, 3, 5, 3, 3 },   // 50 x 30
  { 3, 4, 2, 2, 6, 6, 6 },   // 30 x 40
  { 5, 6, 4, 3, 6, 6, 6 },   // 30 x 50
};
// The same with the code switched off: the facts get its room, in two
// columns where they fit. Flat, a date line is too wide for half the label,
// so the sixth line has no room there.
static const uint8_t FACT_CAPACITY_NO_CODE[CAP_ROWS][LABEL_PRESET_COUNT] = {
  { 5, 6, 5, 5, 5, 3, 3 },
  { 5, 6, 5, 5, 5, 3, 3 },
  { 6, 6, 6, 6, 6, 6, 6 },
  { 6, 6, 6, 6, 6, 6, 6 },
};

int labelFactCapacity(const LabelLayout& layout, uint16_t width_mm, uint16_t length_mm) {
  const uint8_t preset = layout.preset < LABEL_PRESET_COUNT ? layout.preset : LABEL_PRESET_STANDARD;
  const uint16_t longer = width_mm > length_mm ? width_mm : length_mm;
  const bool long_roll = longer >= LL_LONG_ROLL_MM;
  const CapacityRow row = labelLayoutOption(layout, LO_PORTRAIT)
      ? (long_roll ? CAP_UPRIGHT_50 : CAP_UPRIGHT_40)
      : (long_roll ? CAP_FLAT_50 : CAP_FLAT_40);
  return labelLayoutHasCode(layout) ? FACT_CAPACITY[row][preset]
                                    : FACT_CAPACITY_NO_CODE[row][preset];
}

uint32_t labelFactFields(uint8_t preset) {
  uint32_t m = (1u << LF_SPOOL_ID) | (1u << LF_COLOR) | (1u << LF_DATE) | (1u << LF_BRAND) |
               (1u << LF_ARTICLE) | (1u << LF_SPOOL_WEIGHT) | (1u << LF_NET_WEIGHT) |
               (1u << LF_TEMPS) | (1u << LF_LOCATION) | (1u << LF_DRIED) | (1u << LF_FREE_TEXT) |
               (1u << LF_DRYING);
  // The compact arrangement sets the maker among the facts.
  if (preset == LABEL_PRESET_COMPACT) m |= 1u << LF_VENDOR;
  // The big number is the spool's id, and no line besides it.
  if (labelPresetIsBigId(preset)) m &= ~(1u << LF_SPOOL_ID);
  return m;
}

LabelLayout labelLayoutLoad(LabelKind kind) {
  kind = knownKind(kind);
  if (s_loaded[kind]) return s_layout[kind];
  const LayoutKeys& k = LL_KEYS[kind];
  LabelLayout l = labelLayoutDefault(kind);
  // Nothing stored yet: the default, for a spool the label from before.
  if (prefsGetUInt(k.version, 0) != 0) {
    l.preset = (uint8_t)prefsGetUInt(k.preset, LABEL_PRESET_STANDARD);
    l.fields = prefsGetUInt(k.fields, l.fields);
    l.options = prefsGetUInt(k.options, 0);
    l.id_share = (uint8_t)prefsGetUInt(k.id_share, 0);
  }
  s_layout[kind] = labelLayoutSanitized(l);
  fitKind(&s_layout[kind], kind);
  s_loaded[kind] = true;
  return s_layout[kind];
}

bool labelLayoutSave(const LabelLayout& in, LabelKind kind) {
  kind = knownKind(kind);
  const LayoutKeys& k = LL_KEYS[kind];
  LabelLayout l = labelLayoutSanitized(in);
  fitKind(&l, kind);
  bool ok = true;
  ok = prefsPutUInt(k.preset, l.preset) && ok;
  ok = prefsPutUInt(k.fields, l.fields) && ok;
  ok = prefsPutUInt(k.options, l.options) && ok;
  ok = prefsPutUInt(k.id_share, l.id_share) && ok;
  // Last, so a version only stands next to a complete set.
  ok = prefsPutUInt(k.version, LABEL_LAYOUT_VERSION) && ok;
  if (ok) { s_layout[kind] = l; s_loaded[kind] = true; }
  logSDf("Label: %s layout preset %u fields %04x options %02x %s",
         kind == LABEL_KIND_FILAMENT ? "filament" : "spool", (unsigned)l.preset,
         (unsigned)l.fields, (unsigned)l.options, ok ? "saved" : "NOT saved");
  return ok;
}

const char* labelLayoutFreeText() {
  if (s_text_loaded) return s_text;
  utf8Cut(prefsGetString(LL_KEY_TEXT, "").c_str(), sizeof(s_text) - 1, s_text, sizeof(s_text));
  s_text_loaded = true;
  return s_text;
}

bool labelLayoutSaveFreeText(const char* text) {
  char cut[LABEL_FREE_TEXT_BYTES];
  utf8Cut(text ? text : "", sizeof(cut) - 1, cut, sizeof(cut));
  const bool ok = prefsPutString(LL_KEY_TEXT, cut);
  if (ok) { snprintf(s_text, sizeof(s_text), "%s", cut); s_text_loaded = true; }
  logSDf("Label: free text of %u bytes %s", (unsigned)strlen(cut), ok ? "saved" : "NOT saved");
  return ok;
}
