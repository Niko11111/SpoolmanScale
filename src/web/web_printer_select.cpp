#include "web/web_printer_select.h"

// Last on purpose: T() is a macro, see the pages.
#include "lang.h"

void webPrinterModelOptions(String& h, const LabelPrinterConfig& c) {
  for (int i = 0; i < LABEL_PRINTER_MODEL_COUNT; i++) {
    const LabelPrinterModel m = LABEL_PRINTER_MODELS[i];
    const LabelPrinterProfile& p = labelPrinterProfile(m);
    h += F("<option value='");
    h += String((int)m);
    h += F("'");
    if (c.model == m) h += F(" selected");
    h += F(">");
    h += p.brand; h += ' '; h += p.name;
    if (p.experimental) { h += ' '; h += T(STR_PRN_EXPERIMENTAL); }
    h += F("</option>");
  }
}

// The models that take a size, space separated, as the printer page's stock
// cards carry them: the label page's script hides the sizes the picked model
// cannot print on (a 12 mm tape size only a D110 takes).
static void fitList(String& h, const LabelMediaSize& s) {
  bool first = true;
  for (int i = 0; i < LABEL_PRINTER_MODEL_COUNT; i++) {
    if (!labelPrinterTakesMedia(LABEL_PRINTER_MODELS[i], s.width_mm, s.length_mm)) continue;
    if (!first) h += ' ';
    h += String((int)LABEL_PRINTER_MODELS[i]);
    first = false;
  }
}

void webPrinterMediaOptions(String& h, const LabelPrinterConfig& c) {
  bool listed = false;
  for (int i = 0; i < LABEL_MEDIA_SIZE_COUNT; i++) {
    const LabelMediaSize& s = LABEL_MEDIA_SIZES[i];
    const bool cur = s.width_mm == c.media_width_mm && s.length_mm == c.media_length_mm;
    listed = listed || cur;
    h += F("<option value='");
    h += String(s.width_mm); h += 'x'; h += String(s.length_mm);
    h += F("' data-fit='");
    fitList(h, s);
    h += F("'");
    if (cur) h += F(" selected");
    h += F(">");
    h += String(s.width_mm); h += F(" x "); h += String(s.length_mm); h += F(" mm</option>");
  }
  if (!listed) {
    // A size set elsewhere and not in the table: shown so it is not
    // silently replaced, inert so it cannot be picked again.
    h += F("<option value='' selected disabled>");
    h += String(c.media_width_mm); h += F(" x "); h += String(c.media_length_mm); h += F(" mm</option>");
  }
}
