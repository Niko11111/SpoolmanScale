// Own colours over the chosen palette: an accent, a ground tone and its
// strength, and whether the palette follows the backend.
//
// The tone works in OKLCH, where L is the lightness the eye sees. Every
// colour it touches keeps its L and only changes hue and chroma, which is why
// a tone cannot make text harder to read: contrast follows lightness. The web
// interface does the same sums in app.js (TC), so its preview shows what the
// scale will show.
#include "ui/theme.h"

#include <math.h>

#include "services/backend.h"
#include "services/prefs_store.h"

#define PREF_ACCENT    "ui_accent"     // uint32, NO_ACCENT when none
#define PREF_TONE      "ui_tone"       // int, UI_TONE_NONE or a hue
#define PREF_STRENGTH  "ui_tone_str"   // uchar, 0..UI_TONE_STRENGTH_MAX
#define PREF_FOLLOW    "ui_follow"     // bool
#define NO_ACCENT      0xFFFFFFFFu

// Least chroma a tinted colour gets, so a grey palette takes the tone at all.
// Text gets less: it should read as grey with a hint, not as coloured.
#define CHROMA_MIN_SURFACE  0.03f
#define CHROMA_MIN_TEXT     0.012f
// A fill behind accent text takes the accent's hue, at most this saturated.
#define CHROMA_MAX_ACCENT_FILL  0.06f
#define CHROMA_MAX_ACCENT_TEXT  0.10f
#define CHROMA_GAMUT_STEP   0.002f
#define HUE_FULL_CIRCLE     360

// Black and white stay as they are: no hue to turn.
#define LIGHTNESS_BLACK  0.002f
#define LIGHTNESS_WHITE  0.998f

struct TintRole {
  uint32_t* var;
  bool text;
};

// The neutral roles: what a tone turns. The same list stands in app.js.
static const TintRole TINT_ROLES[] = {
  { &UI_COL_GROUND, false },       { &UI_COL_SURFACE, false },
  { &UI_COL_ROW, false },          { &UI_COL_ROW_PRESSED, false },
  { &UI_COL_LINE, false },         { &UI_COL_LINE_SOFT, false },
  { &UI_COL_DIVIDER, false },      { &UI_COL_POPUP_BORDER, false },
  { &UI_COL_EMPTY, false },        { &UI_COL_SCRIM, false },
  { &UI_COL_RULE, false },         { &UI_COL_DISABLED_BG, false },
  { &UI_COL_QUIET_BG_PRESSED, false },
  { &UI_COL_DISABLED_TEXT, true }, { &UI_COL_UNAVAILABLE, true },
  { &UI_COL_INK, true },           { &UI_COL_INK_2, true },
  { &UI_COL_INK_SOFT, true },      { &UI_COL_CAPTION, true },
  { &UI_COL_INK_FAINT, true },     { &UI_COL_INK_BRIGHT, true },
  { &UI_COL_OFF_TEXT, true },      { &UI_COL_ID_TEXT, true },
};

// ---- colour sums ---------------------------------------------
struct Oklch { float l, c, h; };

static float toLinear(uint8_t v) {
  float c = v / 255.0f;
  return c <= 0.04045f ? c / 12.92f : powf((c + 0.055f) / 1.055f, 2.4f);
}

static uint8_t toByte(float c) {
  if (c < 0.0f) c = 0.0f;
  if (c > 1.0f) c = 1.0f;
  c = c <= 0.0031308f ? 12.92f * c : 1.055f * powf(c, 1.0f / 2.4f) - 0.055f;
  return (uint8_t)lroundf(c * 255.0f);
}

static Oklch toOklch(uint32_t rgb) {
  float r = toLinear((rgb >> 16) & 0xFF), g = toLinear((rgb >> 8) & 0xFF), b = toLinear(rgb & 0xFF);
  float l = cbrtf(0.4122214708f * r + 0.5363325363f * g + 0.0514459929f * b);
  float m = cbrtf(0.2119034982f * r + 0.6806995451f * g + 0.1073969566f * b);
  float s = cbrtf(0.0883024619f * r + 0.2817188376f * g + 0.6299787005f * b);
  float L = 0.2104542553f * l + 0.7936177850f * m - 0.0040720468f * s;
  float A = 1.9779984951f * l - 2.4285922050f * m + 0.4505937099f * s;
  float B = 0.0259040371f * l + 0.7827717662f * m - 0.8086757660f * s;
  float h = atan2f(B, A) * 180.0f / (float)M_PI;
  if (h < 0) h += HUE_FULL_CIRCLE;
  return { L, sqrtf(A * A + B * B), h };
}

static void toLinearRgb(const Oklch& o, float out[3]) {
  float A = o.c * cosf(o.h * (float)M_PI / 180.0f), B = o.c * sinf(o.h * (float)M_PI / 180.0f);
  float l = o.l + 0.3963377774f * A + 0.2158037573f * B;
  float m = o.l - 0.1055613458f * A - 0.0638541728f * B;
  float s = o.l - 0.0894841775f * A - 1.2914855480f * B;
  l = l * l * l; m = m * m * m; s = s * s * s;
  out[0] =  4.0767416621f * l - 3.3077115913f * m + 0.2309699292f * s;
  out[1] = -1.2684380046f * l + 2.6097574011f * m - 0.3413193965f * s;
  out[2] = -0.0041960863f * l - 0.7034186147f * m + 1.7076147010f * s;
}

// Lowers the chroma until the colour exists in sRGB, then rounds to bytes.
static uint32_t fromOklch(Oklch o) {
  float rgb[3];
  for (;;) {
    toLinearRgb(o, rgb);
    bool inside = true;
    for (float v : rgb) if (v < -1e-4f || v > 1.0f + 1e-4f) inside = false;
    if (inside || o.c <= 0.0f) break;
    o.c -= CHROMA_GAMUT_STEP;
    if (o.c < 0.0f) o.c = 0.0f;
  }
  return ((uint32_t)toByte(rgb[0]) << 16) | ((uint32_t)toByte(rgb[1]) << 8) | toByte(rgb[2]);
}

static float luminance(uint32_t rgb) {
  return 0.2126f * toLinear((rgb >> 16) & 0xFF) + 0.7152f * toLinear((rgb >> 8) & 0xFF) +
         0.0722f * toLinear(rgb & 0xFF);
}

static float contrast(uint32_t a, uint32_t b) {
  float x = luminance(a), y = luminance(b);
  return (fmaxf(x, y) + 0.05f) / (fminf(x, y) + 0.05f);
}

static uint32_t tint(uint32_t colour, int tone, float k, bool text) {
  Oklch o = toOklch(colour);
  if (o.l < LIGHTNESS_BLACK || o.l > LIGHTNESS_WHITE) return colour;
  if (tone == UI_TONE_NONE) {
    o.c *= k;
  } else {
    o.c = fmaxf(o.c, text ? CHROMA_MIN_TEXT : CHROMA_MIN_SURFACE) * k;
    o.h = (float)tone;
  }
  return fromOklch(o);
}

// A fill keeps its lightness and takes the accent's hue.
static uint32_t towardAccent(uint32_t fill, uint32_t accent) {
  Oklch f = toOklch(fill), a = toOklch(accent);
  f.h = a.h;
  f.c = fminf(a.c, CHROMA_MAX_ACCENT_FILL);
  return fromOklch(f);
}

// Text keeps its lightness and takes the accent's hue, a little more of it
// than a fill: a caption is thin, a pale tint would not show.
static uint32_t towardAccentText(uint32_t ink, uint32_t accent) {
  Oklch f = toOklch(ink), a = toOklch(accent);
  f.h = a.h;
  f.c = fminf(a.c, CHROMA_MAX_ACCENT_TEXT);
  return fromOklch(f);
}

// ---- stored choice -------------------------------------------
// What runs, as opposed to what is stored for the next boot.
static UiThemeCustom s_active = { false, 0, UI_TONE_NONE, UI_TONE_STRENGTH_SAME, false };

UiThemeCustom uiThemeCustomActive() { return s_active; }

UiThemeCustom uiThemeCustomStored() {
  UiThemeCustom c;
  uint32_t a = prefsGetUInt(PREF_ACCENT, NO_ACCENT);
  c.has_accent = a <= UI_RGB_MASK;
  c.accent = c.has_accent ? a : 0;
  int t = prefsGetInt(PREF_TONE, UI_TONE_NONE);
  c.tone = (t >= 0 && t < HUE_FULL_CIRCLE) ? (int16_t)t : UI_TONE_NONE;
  uint8_t s = prefsGetUChar(PREF_STRENGTH, UI_TONE_STRENGTH_SAME);
  c.strength = s <= UI_TONE_STRENGTH_MAX ? s : UI_TONE_STRENGTH_SAME;
  c.follow = prefsGetBool(PREF_FOLLOW, false);
  return c;
}

bool uiThemeCustomStore(const UiThemeCustom& c) {
  bool ok = prefsPutUInt(PREF_ACCENT, c.has_accent ? (c.accent & UI_RGB_MASK) : NO_ACCENT);
  ok = prefsPutInt(PREF_TONE, c.tone) && ok;
  ok = prefsPutUChar(PREF_STRENGTH, c.strength) && ok;
  ok = prefsPutBool(PREF_FOLLOW, c.follow) && ok;
  return ok;
}

UiThemeId uiThemeResolve(UiThemeId chosen, bool follow) {
  if (!follow) return chosen;
  const bool dark = chosen == UI_THEME_DARK || chosen == UI_THEME_SPOOLMAN_DARK ||
                    chosen == UI_THEME_FILAMAN_DARK;
  switch (backendMode()) {
    case BACKEND_FILAMAN:  return dark ? UI_THEME_FILAMAN_DARK  : UI_THEME_FILAMAN_LIGHT;
    case BACKEND_SPOOLMAN: return dark ? UI_THEME_SPOOLMAN_DARK : UI_THEME_SPOOLMAN_LIGHT;
    default:               return dark ? UI_THEME_DARK          : UI_THEME_LIGHT;
  }
}

void uiThemeApplyCustom(const UiThemeCustom& c) {
  s_active = c;
  if (c.tone != UI_TONE_NONE || c.strength != UI_TONE_STRENGTH_SAME) {
    const float k = (float)c.strength / UI_TONE_STRENGTH_SAME;
    for (const TintRole& r : TINT_ROLES) *r.var = tint(*r.var, c.tone, k, r.text);
  }
  if (c.has_accent) {
    UI_COL_ACCENT = c.accent;
    UI_COL_LV_PRIMARY = c.accent;
    UI_COL_ON_ACCENT = contrast(UI_COL_ON_ACCENT_DARK, c.accent) >= contrast(UI_COL_ON_ACCENT_LIGHT, c.accent)
                       ? UI_COL_ON_ACCENT_DARK : UI_COL_ON_ACCENT_LIGHT;
    UI_COL_ACCENT_CHIP = towardAccent(UI_COL_ACCENT_CHIP, c.accent);

    // Where the accent reaches beyond the house colour. Captions and lines
    // take its hue at their own lightness; the blue of a secondary action
    // becomes the accent; the main screen's main action is filled with it.
    // Green for a good state, amber and red keep their meaning.
    UI_COL_CAPTION   = towardAccentText(UI_COL_CAPTION, c.accent);
    UI_COL_INK_FAINT = towardAccentText(UI_COL_INK_FAINT, c.accent);
    UI_COL_DIVIDER   = towardAccent(UI_COL_DIVIDER, c.accent);
    UI_COL_RULE      = towardAccent(UI_COL_RULE, c.accent);
    UI_COL_LINE      = towardAccent(UI_COL_LINE, c.accent);
    UI_COL_CHIP         = towardAccent(UI_COL_CHIP, c.accent);
    UI_COL_POPUP_BORDER = towardAccent(UI_COL_POPUP_BORDER, c.accent);
    UI_COL_STATUS_BLUE  = c.accent;
    UI_COL_ALT_TEXT     = c.accent;
    UI_COL_WEIGHT_BG         = c.accent;
    UI_COL_WEIGHT_BG_PRESSED = uiShade(c.accent, UI_SHADE_PRESSED);
    UI_COL_WEIGHT_TEXT  = UI_COL_ON_ACCENT;
    UI_COL_WEIGHT_AUTO  = UI_COL_ON_ACCENT;
    UI_COL_WEIGHT_SENT  = UI_COL_ON_ACCENT;
    UI_COL_WEIGHT_COUNT = UI_COL_ON_ACCENT;
  }
}
