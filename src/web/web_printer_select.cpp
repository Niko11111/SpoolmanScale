#include "web/web_printer_select.h"

#include "app_config.h"

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

void webPrinterFitList(String& h, uint16_t width_mm, uint16_t length_mm) {
  bool first = true;
  for (int i = 0; i < LABEL_PRINTER_MODEL_COUNT; i++) {
    if (!labelPrinterTakesMedia(LABEL_PRINTER_MODELS[i], width_mm, length_mm)) continue;
    if (!first) h += ' ';
    h += String((int)LABEL_PRINTER_MODELS[i]);
    first = false;
  }
}

// One size as an option; an unchecked one says so after its size.
static void mediaOption(String& h, const LabelMediaSize& s, const LabelPrinterConfig& c) {
  h += F("<option value='");
  h += String(s.width_mm); h += 'x'; h += String(s.length_mm);
  h += F("' data-fit='");
  webPrinterFitList(h, s.width_mm, s.length_mm);
  h += F("'");
  if (s.width_mm == c.media_width_mm && s.length_mm == c.media_length_mm) h += F(" selected");
  h += F(">");
  h += String(s.width_mm); h += F(" x "); h += String(s.length_mm); h += F(" mm");
  if (!labelMediaChecked(s.width_mm, s.length_mm)) {
    h += F(" (");
    h += T(STR_PRN_MEDIA_UNCHECKED);
    h += ')';
  }
  h += F("</option>");
}

void webPrinterMediaOptions(String& h, const LabelPrinterConfig& c) {
  for (int i = 0; i < LABEL_MEDIA_SIZE_COUNT; i++) mediaOption(h, LABEL_MEDIA_SIZES[i], c);
  const LabelMediaSize own = labelPrinterCustomMedia();
  // The own size, unless it is one of the suggested rolls anyway.
  if (own.width_mm && !labelMediaSuggested(own.width_mm, own.length_mm)) mediaOption(h, own, c);
  for (int i = 0; i < LABEL_MEDIA_SUGGESTED_COUNT; i++) mediaOption(h, LABEL_MEDIA_SUGGESTED[i], c);
}

void webPrinterWishLink(String& h) {
  h += F("<a href='" WEBSITE_URL);
  h += g_lang == LANG_DE ? F(WEBSITE_WISH_PATH_DE) : F(WEBSITE_WISH_PATH_EN);
  h += F("?fw=" FW_VERSION "' target='_blank' rel='noopener'>");
  h += T(STR_W_P_WISH_LINK);
  h += F(" &rarr;</a>");
}
