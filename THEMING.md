# Theming and the web UI

How to keep new screens and pages working with the runtime theme. Written for
whoever adds the next feature.

---

## 1. Colouring a new device screen

Never write a colour literal. Use the token table:

```cpp
#include "theme.h"

lv_obj_set_style_bg_color(btn, tc(TH_SURFACE_2), 0);
lv_obj_set_style_text_color(lbl, tc(TH_TEXT), 0);
```

`tc()` returns an `lv_color_t`. Where a colour has to live in a variable or a
struct field, use the raw table instead — `lv_color_hex()` takes a `uint32_t`,
so this works in every position `tc()` cannot:

```cpp
uint32_t col = ok ? g_theme[TH_SUCCESS_BG] : g_theme[TH_TILE_BG];
lv_obj_set_style_bg_color(o, lv_color_hex(col), 0);
```

**Do not do arithmetic on a theme colour.** The old settings tiles derived their
pressed state with `lv_color_hex(tiles[i].col + 0x101010)`. On a light palette
that overflows the green channel into the red byte and produces garbage. Pick a
second token instead.

The 20 tokens are named for the *role* they play (`TH_BG`, `TH_ACCENT`,
`TH_TEXT_MUTED`), not the colour they happen to be, so they still make sense
under a light or amber palette. See `src/ui/theme.h` for the full list.

A long tail of ~70 one-off accents is still hardcoded — status colours used
once or twice. Those are deliberate: folding them in would mean either 70 more
tokens or quietly changing colours. Add new ones as tokens if they are
structural, or leave them literal if they are genuinely one-off.

---

## 2. Adding a new overlay screen

Pass your slot to `buildOverlayScreen()` and there is nothing else to register:

```cpp
lv_obj_t *scr_my_screen = nullptr;

void buildMyScreen() {
  releaseScreen(&scr_my_screen);
  scr_my_screen = buildOverlayScreen(&scr_my_screen);   // <- registers itself
  buildSubHeader(scr_my_screen, "My Screen", back_cb);
  ...
}
```

That single `&scr_my_screen` gets you both behaviours that used to be
hand-maintained lists in two different files:

- **hidden by `hideAllOverlays()`** — the corner X calls `showMainScreen()`,
  which only hides what it knows about. An unregistered screen makes the X look
  broken: the main screen appears *underneath* while yours stays on top.
- **dropped by `themeInvalidateScreens()`** — colours are baked into LVGL styles
  when a screen is built, so an unregistered screen keeps the old palette
  forever after a theme change.

Neither failure points at the missing line, which is why it is automatic now.

If your screen builds its own container instead of using the helper, call
`overlayRegister(&scr_my_screen)` once and you get the same treatment.

**Do not keep a private copy of the overlay list.** `factor_screen.cpp` used to,
so it could avoid hiding the screen it had just revealed, and it drifted eight
screens behind. Call `hideAllOverlays()` first, then clear your own hidden flag:

```cpp
buildMyScreen();
hideAllOverlays();
lv_obj_clear_flag(scr_my_screen, LV_OBJ_FLAG_HIDDEN);
```

---

## 3. Why the main screen needs a restart

`themeInvalidateScreens()` deliberately does not touch the main screen.
`buildUI()` creates its widgets directly on `lv_scr_act()`, and
`spool_flow.cpp` holds **16 static pointers** to children of that screen with no
complete public teardown. Cleaning the active screen would free objects that
module still references, and the next spool scan would use them.

So the main screen adopts a palette change on the next boot. The web UI has a
**Restart device** button for exactly this. If you ever want live repainting,
give `spool_flow.cpp` a full teardown first.

The gain control (`displaySetUiGain`) is different: it transforms pixels in the
LVGL flush callback, so it applies everywhere immediately, main screen included,
with no restart.

---

## 4. Adding a theme token

Five places. All but one are enforced by `static_assert` in `theme.cpp`, so a
forgotten one is a build error naming the array:

1. the `ThemeColor` enum in `theme.h`
2. `g_theme[]` default
3. `TOKEN_ID[]` — short id, used as the web form field name
4. `TOKEN_LABEL[]` — human label
5. every row of `PRESETS[][]` — **not enforced**, see below

**The one the compiler cannot catch:** a short `PRESETS` row zero-fills
silently, because C++ offers no way to assert the inner dimension of a 2D array.
Add a colour to *all* `THEME_PRESET_COUNT` rows by hand or the new token renders
black on every preset except whichever row you did update.

**The share string needs nothing when you add a token.** It is keyed by name and
carries the build that wrote it:

```
SMS5:fw=v0.6.1-beta.6,bg=0a1020,accent=28d49a,...,gain=100
```

A string from an older build still applies. The colours it names are set, the
ones it does not mention keep their current value, and names this build no
longer has are ignored. The import line says which of those happened and names
both versions when they differ, so a partial apply cannot be mistaken for a full
one.

`fw` and `gain` are reserved — do not add a token with either short id.

Only bump the tag if the *format* changes: the separators, or the meaning of a
field. An earlier version of this was positional and had to be bumped on every
token change, which meant every shared palette stopped working on upgrade.

---

### Checking a palette is readable

Adding or editing a preset means checking the text still reads on it. There is a
tool for that, and CI runs it before every build:

```
python3 tools/check_theme_contrast.py
```

It reads the palette straight out of `theme.{h,cpp}` — so it cannot drift from
the firmware — and prints the WCAG contrast ratio for every foreground/background
pair the UI actually draws, per preset. Anything under **4.5:1** fails; 3.0–4.5
is flagged `!` because it is only acceptable for large text, and most of this UI
is 12–16px.

If a new screen draws a combination that is not already covered, add it to
`PAIRS` at the top of the tool. It only knows what it has been told.

**The Default preset ships four pairs below the threshold** (`TEXT_DIM on BG` at
1.81 being the worst). Those are the original colours and are deliberately
unchanged — altering them would redesign the device's established look rather
than fix a regression. CI therefore runs with `--allow Default`. Remove that flag
if you decide to raise them.

Fixing a failure is mechanical: darken the foreground on a light background, or
lighten it on a dark one, until it clears. Remember one token is drawn on several
backgrounds, so solve for the worst pair, not the one you noticed.

---

## 5. Adding a web page

Use the shared shell so the page carries the same logo, palette, tabs, community
links and disclaimer as everything else:

```cpp
#include "web_shell.h"

String myPage() {
  String h;
  h += webShellHead("My Page");     // doctype, CSS, logo, version line
  h += F("<style>/* page-specific only */</style>");
  h += webShellNav("/mypage");      // tab strip, highlights the current path
  h += webShellLinks();             // Ko-fi / GitHub / Discord / MakerWorld
  h += F("<div class='card'><h2>Title</h2>...</div>");
  h += webShellFoot();              // disclaimer, </body></html>
  return h;
}
```

Then add the path and label to the arrays in `webShellNav()`
(`src/services/web_shell.cpp`) so it appears as a tab.

**Pages get clean URLs, data goes under `/api/`.** `/logs` is a page;
`/api/logs` is the JSON it fetches. They used to collide, and browsing `/logs`
returned raw JSON.

**Gate it.** Every handler checks its gate at request time, because
`WebServer::stop()` does not free handlers so route sets cannot be swapped by
re-registering:

```cpp
srv.on("/mypage", HTTP_GET, [&srv]() {
  if (!webMaintenanceEnabled()) {
    webSendDisabled(srv, "My page", "Settings > System > Web interface");
    return;
  }
  srv.send(200, "text/html", myPage());
});
```

Three levels exist: the master switch (port 80 at all), the maintenance gate
(`/ota`, `/update`, logs, FilaMan, limits, drying) and the theme gate
(`/theme`). All three live on **Settings → System → Web interface** on the
device. Anything that writes firmware or changes settings belongs behind a gate;
read-only status does not.

Also note `startOtaServer()` registers routes once, guarded by
`routes_registered`. It is called every time the OTA screen opens, and handlers
are never freed, so re-registering would pile up allocations.

---

## 6. Gotchas worth knowing

**LVGL line heights exceed the nominal size.** `lv_font_montserrat_ext_12` needs
about 16px. A row at y=86 in a 100px container gets its descenders clipped.
Budget by line height, not font size.

**The shell caps content at 480px.** Right for a status page, wrong for a wide
editor. `/theme` overrides `.nav,.links,.card{max-width:1180px}` locally rather
than changing the shell for everyone.

**Balance your tags.** An unclosed `<div>` inside the 2-column `.links` grid
turns every card that follows into a grid cell. Worth a quick
`grep -o '<div' | wc -l` against `</div>` when a layout looks strange.

**Boot time is not a constant.** An SD card adds roughly 20 seconds. Anything
that waits for the device to come back should read `sd` from `/status.json` and
budget accordingly — measured boot-to-serving is 4-8s without one.
