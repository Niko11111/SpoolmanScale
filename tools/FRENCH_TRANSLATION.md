# French translation: how it works and how to keep it up to date

<!-- Fork addition – Nanostra (Frédéric Dubus) -->

SpoolmanScale started out in German and English. **French** came in as a third language with PR #33,
on the display and in the web interface. This page was written on the fork that built it, so
"upstream" below means this repository. It explains the one real problem we hit (accents), how we solved it without moving a
single pixel of the German and English screens, how we checked that, and how to keep the French texts
in step when the firmware changes.

If you only want to change a French text, jump to [Common tasks](#6-common-tasks).

---

## 1. Adding a language was the easy part

SpoolmanScale already has a clean translation layer. Every text lives in one table, `src/lang.cpp`:
one row per text, one column per language. The code asks for `T(STR_SOMETHING)` and gets the text in
the current language. The web pages use the same table.

So adding French means adding a **third column**. No text had to be hunted down in the code.

## 2. The real problem: the fonts had no French accents

The display fonts contain ASCII, `°`, `•` and the seven German letters `Ä Ö Ü ß ä ö ü`. Nothing else.
When a letter is missing, LVGL draws an empty box. "Réglages" would show up as "R□glages".

The obvious fix is to regenerate the fonts with more letters. **We did not do that, on purpose.** The
font converter computes the line height from the letters it is given. The repository already shows it:
adding the German letters moved the line height from 15 to 16 px at size 12, and from 22 to 23 px at
size 20. French capitals like `É` sit higher, and `ç` hangs lower. Regenerating would change the line
heights again, and since every screen places its labels in absolute pixels, the German and English
layouts would move.

### What we did instead: small supplement fonts

- **7 new files**, `src/fonts/lv_font_fr_supp_NN.c`, one per font size the firmware really uses (10,
  12, 14, 16, 18, 20, 24). Same TTF (Montserrat Medium, shipped with LVGL 8.3.11), same size, same
  4 bpp as the existing fonts.
- **1 line in each existing font**: `.fallback = &lv_font_fr_supp_NN,` instead of `NULL`.
- **7 declarations** in `src/lv_conf.h`, so the existing fonts can see the new ones.

LVGL only looks into a fallback font for a letter the main font does not have. The line height and the
baseline always come from the main font. German and English text never even reaches the supplement.

**Letters covered**: the Latin-1 letters that were missing (`À Â Ç É È Ê Ë Î Ï Ô Ù Û`… and their
lower case), plus `Œ œ Ÿ « » ’ …`, the no-break space, `×` and `÷`. `Å` is left out: it is so tall it
would be clipped, and no filament vendor seems to need it. A nice side effect: a spool called "Café" in
Spoolman now displays correctly, in every language.

**Cost**: 39 376 bytes of flash for the seven supplements (measured, see [section 4](#4-how-we-checked-that-nothing-broke)).

**Two small side effects**, both measured:

- Kerning is not applied between a letter of the main font and a letter of the supplement. Texts with
  accents are a tiny bit wider (usually less than a pixel, at most about 3 px at size 24). The width
  checker below takes this into account.
- For `À Â È É Ê Î Ô Ù Û Ç ç`, the faintest row of anti-aliased pixels of the accent can be cut, on
  the first line of a label only. `python tools/gen_fr_fonts.py --audit` lists exactly where.

## 3. The code changes

The rest of the change is small:

| File | Change |
|---|---|
| `src/lang.h` | `LANG_FR = 2`, `LANG_COUNT`, `STRINGS[][3]`, `langText()`, nine new ids at the end (the captions below) |
| `src/lang.cpp` | the third column |
| `src/services/app_settings.cpp` | the language read from NVS is range-checked instead of cast blindly |
| `src/services/time_service.cpp` | French defaults to the same time zone as German (CET) |
| `src/web/web_portal.cpp` | `<html lang="fr">` on the setup portal |
| `src/ui/language_screen.cpp`, `src/ui/setup_welcome_screen.cpp` | three buttons instead of two |
| `src/ui/main_screen.cpp`, `src/ui/more_info_screen.cpp` | the "Material" caption comes from the table |
| `status_picker.cpp`, `wifi_info.cpp`, `wifi_setup_screen.cpp`, `spoolman_screen.cpp`, `more_info_screen.cpp`, `language_screen.cpp`, the three number pads | "Status", "Gateway", "Name", "%s Server", "%s UUID", "Language / Sprache" and the "DEL" key were literals because German and English agree on them; they now come from the table, with German and English keeping exactly the same text |

`T()` stays a macro, but it now goes through a small function, `langText()`: **if a French cell is
empty, the English text is shown instead**. A row written with only German and English still compiles
into a three-column table, and its missing cell is a null pointer; on this board a null `%s` restarts
the device instead of printing "(null)". With the fallback, you can keep adding rows exactly as before.
It even made the firmware smaller (4 052 bytes), because a function call is shorter than the table lookup it replaces at every call site.

**What you will see on the display**: the two language screens show three buttons, `Deutsch`,
`English`, `Français`. The `DE` / `EN` prefixes were dropped to make room; nothing below the buttons
moves. In German and English, everything else looks exactly as before.

**In the web interface**: nothing changes in German and English. No CSS was touched.

## 4. How we checked that nothing broke

| Check | Result |
|---|---|
| German and English texts | **byte-identical** to upstream. `lang_fr.py emit` re-reads the file it wrote and refuses to finish otherwise |
| The table parser | `lang_fr.py roundtrip` rebuilds the upstream `lang.cpp` **byte for byte** |
| The 7 existing fonts | glyph data unchanged (90 097 bytes), line heights and baselines unchanged: only the `.fallback` line differs |
| Where the table lives | still in flash, not in RAM |
| Every French text | `lang_fr.py check --strict`: 0 errors (list below) |
| Size, against upstream `dev` (v0.7.4-beta.2) | flash **+83 004 bytes**: fonts +39 360, third column and code +516, French texts and captions +43 128. RAM +64 bytes |
| Hard width budgets | `fit_check.py --gate`: 70 budgets, one per real widget, 0 over |
| Every width warning | traced in the code to its real widget: what showed was shortened and got a budget |
| On the device | a WT32-SC01 Plus captured every screen and state of the display (Spoolman, FilaMan and BamBuddy, with and without load cell) and the 7 web pages at 360 and 1100 px, in German and English, before and after the French work, compared pixel by pixel. Display: 1,713 of 1,740 captures identical, the other 27 are the two language screens. Web: identical apart from texts changed by #30 and #31 in the meantime, and two pages captured before they had finished loading. The French screens were reviewed one by one on the same captures |

What `check` verifies for every French text, from the most serious to the least:

- the `printf` conversions (`%d`, `%s`, `%.1f`…) are **the same, in the same order** as in German. A
  swapped pair is not a typo, it is a crash;
- a literal percent is written `%%`;
- web placeholders like `{n}` appear the same way and **never twice** (`replace` only replaces the
  first one);
- leading `LV_SYMBOL_…` icons, line breaks and HTML tags are kept;
- no bare `&` where the text ends up in `innerHTML`;
- the text fits its **buffer in bytes** (an accented letter takes 2 bytes);
- every character exists in the fonts;
- where a widget's width is known (`ui_budgets.tsv`), the text fits it. **This one fails the check.**

It also **warns** when a line is wider than both German and English. Be careful with that one: it is a
hint, not a guarantee. Most of those lines wrap or sit in a scrolling popup and are fine, but a few
land in a fixed-width label and get cut. French ran over the German/English width in several hundred lines;
we checked every one of them against its widget, fixed the ones that showed, and turned each of those
widgets into a hard budget. The warnings are printed last, sorted by how much wider they are.

## 5. The tools

All tools are plain Python 3 scripts in `tools/`. Each one starts with a detailed header.

| File | What it is | Most used command |
|---|---|---|
| `lang_fr.jsonl` | **The source of truth for French.** One JSON line per text, in table order | (edited through `apply`) |
| `lang_fr.py` | Keeps the working file and `src/lang.cpp` in sync, and checks the French | `check --strict` |
| `fit_check.py` | Measures a text in pixels exactly as LVGL does, from the real font tables | `--measure 16 "Étalonnage"` |
| `ui_budgets.tsv` | Hard width limits for the places where "not wider than German or English" is not enough | (read by `--gate`) |
| `gen_fr_fonts.py` | Builds the supplement fonts and reports clipped glyphs | `--audit` |

In `lang_fr.jsonl`, only `fr` (the translation), `note` (why a choice was made) and `st` (status) are
written by hand. Everything else (German, English, where the text is used, its budgets) is rebuilt from
the sources by `seed`.

`lang_fr.py` modes:

```sh
python tools/lang_fr.py roundtrip   # prove the parser on the current lang.cpp (run it first)
python tools/lang_fr.py seed        # refresh German, English and call sites; French is kept
python tools/lang_fr.py dump        # the texts still to translate, with their limits
python tools/lang_fr.py apply       # read {"STR_X": "texte"} as JSON on stdin
python tools/lang_fr.py check       # all the checks; --strict also demands every row in French
python tools/lang_fr.py emit        # write src/lang.cpp with its three columns
python tools/lang_fr.py report      # progress per group, and the tightest buffers
```

`fit_check.py` and `lang_fr.py` read the fonts from `src/fonts/`. `lang_fr.py` also needs LVGL under
`.pio/libdeps/` to resolve the icon symbols, so build the firmware once first. `gen_fr_fonts.py
--build` additionally needs `lv_font_conv` 1.5.3 (`npm i -g lv_font_conv@1.5.3`); the other modes do
not.

## 6. Common tasks

### Change a French text

```sh
echo '{"STR_BTN_EMPTY_SPOOL": "Bobine vide<NL>(mesurer bobine + moyeu)"}' | python tools/lang_fr.py apply
python tools/lang_fr.py check --strict
python tools/lang_fr.py emit
pio run -e wt32-sc01-plus
```

`<NL>` stands for a line break: a backslash does not survive the shell reliably.

### Upstream changed some texts (after a rebase or a merge)

`src/lang.cpp` is the file upstream edits most, so a conflict there is normal. **Never resolve it by
hand**: take upstream's version and let the tool put the French column back.

```sh
git checkout upstream/dev -- src/lang.cpp   # upstream's version, as is
python tools/lang_fr.py seed                # new German/English picked up, French kept
python tools/lang_fr.py check               # lists new texts and texts whose German changed
#   translate what it lists, with apply
python tools/lang_fr.py emit                # the third column is back
git add src/lang.cpp tools/lang_fr.jsonl
```

Avoid `--ours` / `--theirs` here: during a rebase their meaning is swapped, and the mistake is silent.

A text that is not translated yet is emitted with its **English** text, so the firmware always builds
and stays usable.

### Add a new text (for maintainers who do not speak French)

Nothing changes in how you work: append the row at the end of the table as usual, with German and
English. The French cell may stay missing - `T()` shows the English there until someone translates it.

If you want to fill it at once, copy the English into the third cell, or run:

```sh
python tools/lang_fr.py seed    # picks up the new row
python tools/lang_fr.py emit    # writes it with the English in the French column
```

`python tools/lang_fr.py check` lists the rows still missing their French cell.

### Regenerate the supplement fonts

Only needed if the letter set changes:

```sh
python tools/gen_fr_fonts.py --all
```

## 7. Known limits

- **Going back to a firmware without French.** The language is stored as a number. If the device is
  set to French (`2`) and a firmware that only knows `0` and `1` is installed, that firmware reads a
  column that does not exist, and the screens show garbled text. **Switch the language to German or
  English before installing a firmware from before French was added (v0.7.3 and older).**
- **Decimal point.** Numbers formatted by the code keep a dot (`1.5`): there is no locale support in
  the firmware, and translating cannot change that.
- **A few server-side English words** in the web interface (for example some log page messages and
  uptime units) are written directly in the code rather than in the table. They stay in English in
  every language; this was not changed here.
