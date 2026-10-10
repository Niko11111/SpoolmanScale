#include "services/label_layout.h"

#include "hardware/sd_logger.h"
#include "services/prefs_store.h"

// NVS keys, 15 characters at most.
#define LL_KEY_VERSION "lbl_ver"
#define LL_KEY_PRESET  "lbl_preset"
#define LL_KEY_FIELDS  "lbl_fields"
#define LL_KEY_OPTIONS "lbl_opts"

static const uint32_t FIELD_MASK  = (1u << LABEL_FIELD_COUNT) - 1;
static const uint32_t OPTION_MASK = (1u << LABEL_OPTION_COUNT) - 1;
// What the label printed before the editor: every field up to the brand.
static const uint32_t DEFAULT_FIELDS = (1u << (LF_BRAND + 1)) - 1;

static LabelLayout s_layout{};
static bool s_loaded = false;

LabelLayout labelLayoutDefault() {
  LabelLayout l{};
  l.preset = LABEL_PRESET_STANDARD;
  l.fields = DEFAULT_FIELDS;
  l.options = 0;
  return l;
}

LabelLayout labelLayoutSanitized(const LabelLayout& in) {
  LabelLayout l = in;
  if (l.preset >= LABEL_PRESET_COUNT) l.preset = LABEL_PRESET_STANDARD;
  l.fields &= FIELD_MASK;
  l.options &= OPTION_MASK;
  return l;
}

bool labelLayoutHas(const LabelLayout& layout, LabelField field) {
  return (layout.fields >> field) & 1u;
}

bool labelLayoutOption(const LabelLayout& layout, LabelOption option) {
  return (layout.options >> option) & 1u;
}

LabelLayout labelLayoutLoad() {
  if (s_loaded) return s_layout;
  LabelLayout l = labelLayoutDefault();
  // Nothing stored yet: the default, which is the label from before.
  if (prefsGetUInt(LL_KEY_VERSION, 0) != 0) {
    l.preset = (uint8_t)prefsGetUInt(LL_KEY_PRESET, LABEL_PRESET_STANDARD);
    l.fields = prefsGetUInt(LL_KEY_FIELDS, l.fields);
    l.options = prefsGetUInt(LL_KEY_OPTIONS, 0);
  }
  s_layout = labelLayoutSanitized(l);
  s_loaded = true;
  return s_layout;
}

bool labelLayoutSave(const LabelLayout& in) {
  const LabelLayout l = labelLayoutSanitized(in);
  bool ok = true;
  ok = prefsPutUInt(LL_KEY_PRESET, l.preset) && ok;
  ok = prefsPutUInt(LL_KEY_FIELDS, l.fields) && ok;
  ok = prefsPutUInt(LL_KEY_OPTIONS, l.options) && ok;
  // Last, so a version only stands next to a complete set.
  ok = prefsPutUInt(LL_KEY_VERSION, LABEL_LAYOUT_VERSION) && ok;
  if (ok) { s_layout = l; s_loaded = true; }
  logSDf("Label: layout preset %u fields %02x options %02x %s", (unsigned)l.preset,
         (unsigned)l.fields, (unsigned)l.options, ok ? "saved" : "NOT saved");
  return ok;
}
