#include "tag_create.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "../app/app_state.h"
#include "../bambu/material_match.h"
#include "tag_create_bambu.h"

// Room behind a colour name for FilaMan's " (10101)".
#define TAG_CREATE_ARTICLE_SUFFIX_MAX  8

void tagFilamentPlanClear(TagFilamentPlan* plan) {
  if (plan) memset(plan, 0, sizeof(*plan));
}

// One per kind of tag that can become a spool, tried in this order. Each
// answers false for a scan that is not its own. A new kind is a file of its
// own (tag_create_bambu.cpp is the pattern) and a line here.
typedef bool (*TagCreateBuilder)(TagCreateInput* out);
static const TagCreateBuilder TAG_CREATE_BUILDERS[] = {
  tagCreateInputFromBambu,
};

bool tagCreateInputFromTag(TagCreateInput* in) {
  if (!in) return false;
  for (TagCreateBuilder build : TAG_CREATE_BUILDERS) {
    memset(in, 0, sizeof(*in));
    if (build(in)) return true;
  }
  memset(in, 0, sizeof(*in));
  return false;
}

void tagCreateSplitProduct(TagCreateInput* in) {
  in->subtype[0] = '\0';
  const size_t n = strlen(in->material);
  const char* p = in->product;
  if (n && strncasecmp(p, in->material, n) == 0 && (p[n] == ' ' || p[n] == '-')) {
    snprintf(in->subtype, sizeof(in->subtype), "%s", p + n + 1);
    return;
  }
  // Not led by the base: split at the first separator, the way the link
  // list reads a tag's material.
  extractBambuSubtype(p, in->subtype, sizeof(in->subtype));
}

void tagCreateColorsFromTag(TagCreateInput* in) {
  in->color_hex[0] = in->color2_hex[0] = in->rgba[0] = '\0';
  if (!g_tag.color.valid) return;
  snprintf(in->rgba, sizeof(in->rgba), "%06X%02X",
           (unsigned)g_tag.color.rgb, (unsigned)g_tag.color.alpha);
  // A clear filament names no hue; 000000 would make it black.
  if (spoolColorNamesHue(g_tag.color))
    snprintf(in->color_hex, sizeof(in->color_hex), "%06X", (unsigned)g_tag.color.rgb);
  if (g_tag.color_count >= 2 && g_tag.color2.valid && spoolColorNamesHue(g_tag.color2))
    snprintf(in->color2_hex, sizeof(in->color2_hex), "%06X", (unsigned)g_tag.color2.rgb);
}

bool tagCreateStartsWithWord(const char* text, const char* word) {
  if (!text || !word || !word[0]) return false;
  const size_t n = strlen(word);
  if (strncasecmp(text, word, n) != 0) return false;
  return text[n] == '\0' || text[n] == ' ' || text[n] == '-';
}

// "PLA Tough+ Cyan" names the material too; what follows it counts.
static const char* afterMaterial(const char* name, const char* material) {
  if (!material[0] || !tagCreateStartsWithWord(name, material)) return name;
  name += strlen(material);
  while (*name == ' ' || *name == '-') name++;
  return name;
}

bool tagCreateNameMatches(const char* name, const TagCreateInput& in) {
  if (!name || !name[0]) return false;
  name = afterMaterial(name, in.material);
  // A product without a subtype ("PLA" alone) has nothing more to compare.
  if (!in.subtype[0]) return true;
  if (tagCreateStartsWithWord(name, in.subtype)) return true;
  // The plain line by its colour alone, and only by the whole name: "Black"
  // is PLA Basic, "Tough+ Black" has the same colour and is not.
  return tagCreatePlainLine(in) && in.color_name_en[0] &&
         tagCreateStartsWithWord(name, in.color_name_en) &&
         strlen(name) <= strlen(in.color_name_en) + TAG_CREATE_ARTICLE_SUFFIX_MAX;
}

bool tagCreatePlainLine(const TagCreateInput& in) {
  return in.plain_line[0] && strcasecmp(in.subtype, in.plain_line) == 0;
}

bool tagCreateSubgroupMatches(const char* subgroup, const char* designation,
                              const TagCreateInput& in) {
  // Equal, not contained: "tough" is in "tough-plus" and is another product.
  if (subgroup && subgroup[0]) return bambuSubtypeEquals(subgroup, in.subtype);
  // Created by hand, without a subgroup: read like a Spoolman name.
  return tagCreateNameMatches(designation, in);
}

bool tagCreateArticleInText(const char* text, const char* article) {
  if (!text || !article || !article[0]) return false;
  char needle[16];
  snprintf(needle, sizeof(needle), "(%s)", article);
  return strstr(text, needle) != nullptr;
}

bool tagCreateSameHex(const char* a, const char* b) {
  if (!a || !b) return false;
  if (*a == '#') a++;
  if (*b == '#') b++;
  // Six digits decide; an alpha pair behind them does not.
  if (strlen(a) < 6 || strlen(b) < 6) return false;
  return strncasecmp(a, b, 6) == 0;
}

static const char* colorWord(const TagCreateInput& in) {
  return in.color_name_en[0] ? in.color_name_en : in.color_hex;
}

void tagCreateSpoolmanName(const TagCreateInput& in, char* out, size_t out_size) {
  if (in.subtype[0] && !tagCreatePlainLine(in)) snprintf(out, out_size, "%s %s", in.subtype, colorWord(in));
  else                                          snprintf(out, out_size, "%s", colorWord(in));
}

void tagCreateFilamanColorName(const TagCreateInput& in, char* out, size_t out_size) {
  if (in.article[0]) snprintf(out, out_size, "%s (%s)", colorWord(in), in.article);
  else               snprintf(out, out_size, "%s", colorWord(in));
}

// "Tough+" as the FilamentDB writes it: "Tough Plus" in the designation,
// "tough-plus" as the subgroup.
static void subtypeSpelled(const char* subtype, bool as_subgroup, char* out, size_t out_size) {
  size_t o = 0;
  for (const char* p = subtype; *p && o + 6 < out_size; p++) {
    if (*p == '+') {
      const char* plus = as_subgroup ? "-plus" : " Plus";
      memcpy(out + o, plus, 5);
      o += 5;
    } else if (as_subgroup) {
      out[o++] = *p == ' ' ? '-' : (char)tolower((unsigned char)*p);
    } else {
      out[o++] = *p;
    }
  }
  out[o] = '\0';
}

void tagCreateFilamanSubgroup(const TagCreateInput& in, char* out, size_t out_size) {
  subtypeSpelled(in.subtype, true, out, out_size);
}

void tagCreateFilamanDesignation(const TagCreateInput& in, char* out, size_t out_size) {
  char color[64];
  tagCreateFilamanColorName(in, color, sizeof(color));
  if (!in.subtype[0] || tagCreatePlainLine(in)) { snprintf(out, out_size, "%s", color); return; }
  char words[32];
  subtypeSpelled(in.subtype, false, words, sizeof(words));
  snprintf(out, out_size, "%s - %s", words, color);
}
