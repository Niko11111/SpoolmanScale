#pragma once

#include <lvgl.h>

// ============================================================
//  THEME
//
//  The one table for what the panel looks like: colours, type
//  sizes, radii, the house measurements of a button. Every colour
//  in src/ui and src/app is named here; the ratchet counts one
//  written as a number (inline_color_hex, raw_color_hex). A second
//  palette - light, or one per backend - is a second copy of the
//  colour block and a switch, not a hunt through the tree.
//
//  Names say what a colour is for, not what it looks like:
//  UI_COL_CAPTION rather than "dim blue". A palette that swaps
//  the blue for grey changes one line and every caption follows.
//  Two names may share a value when their roles differ (INK_FAINT
//  and RULE): a palette can then set them apart. A name that
//  carries a widget (UI_COL_COPY_*) is a colour only that widget
//  uses.
//
//  For a palette chosen at runtime these become variables. Keep
//  them out of #if, constexpr and static initialisers so that
//  step stays a change to this file.
// ============================================================

// ---- surfaces ------------------------------------------------
#define UI_COL_GROUND          0x0a1020   // the screen behind everything
#define UI_COL_SURFACE         0x0c1828   // a popup's box, a picker's box, inputs, quiet buttons, list bodies
#define UI_COL_ROW             0x1a2030   // a settings row, a divider, a quiet button: cancel, delete a value
#define UI_COL_ROW_PRESSED     0x1a3050   // the same row under the finger, and its border
#define UI_COL_LINE            0x1a3870   // dividers, the slider track, a quiet border
#define UI_COL_LINE_SOFT       0x1e2a44   // the fainter border of an input; a neutral answer beside a green one
#define UI_COL_POPUP_BORDER    0x2a4080   // the frame of a question; a blue action pressed
#define UI_COL_EMPTY           0x182238   // an empty bay, the keyboard, More, "got it"
#define UI_COL_CHIP            0x102040   // a header chip that is a button; a blue action: dried, this spool, new spool
#define UI_COL_SCRIM           0x000000   // behind a popup, at UI_OPA_SCRIM

#define UI_OPA_SCRIM           LV_OPA_70

// Steps added to a tile's own colour for its pressed state and its border.
#define UI_SHADE_PRESSED       0x101010
#define UI_SHADE_BORDER        0x181818

// ---- text ----------------------------------------------------
#define UI_COL_INK             0xe8f0ff   // titles and values
#define UI_COL_INK_2           0xc8d8f0   // body text
#define UI_COL_INK_SOFT        0x8fa8c8   // secondary body text, still readable
#define UI_COL_CAPTION         0x4a6fa0   // captions and hints
#define UI_COL_RULE            0x2a4060   // rules and inactive bars; as text it is INK_FAINT
#define UI_COL_INK_FAINT       0x2a4060   // header captions and the faintest hints
#define UI_COL_VALUE_BLUE      0x8ab0d8   // dates and similar quiet values
#define UI_COL_INK_MAX         0xffffff   // what must be typed exactly: a network password
#define UI_COL_INK_BRIGHT      0xf0f0f0   // a spool's material and name, a list row
#define UI_COL_ON_ACCENT       0x0a1020   // a label on a button filled with the accent
#define UI_COL_OFF_TEXT        0x8098b8   // the label of an option not chosen
#define UI_COL_ID_TEXT         0x4a7080   // a UUID and similar machine values
#define UI_COL_STATUS_BLUE     0x5090e0   // a neutral status line, a date with no drying mode
#define UI_COL_HDR_OFF         0x606060   // a header icon whose device is not there
#define UI_COL_DISABLED_BG     0x111820   // a button that cannot be used now, a switch that is off
#define UI_COL_DISABLED_TEXT   0x2a3848   // its label, and an option that is off

// ---- meaning -------------------------------------------------
#define UI_COL_ACCENT          0x28d49a   // the house green: active, found, ok
#define UI_COL_OK_BG           0x1a4020   // a confirming button
#define UI_COL_OK_BG_PRESSED   0x2a7030
#define UI_COL_OK_TEXT         0x80ffb0   // its label
#define UI_COL_OK_TEXT_2       0x40c080   // the smaller confirming label
#define UI_COL_WARN            0xf0b838   // amber: attention, waiting, the scale's own figure
#define UI_COL_BAD             0xe04040   // red: wrong, failed
#define UI_COL_BAD_TEXT        0xff8080   // a red label on a dark button
#define UI_COL_BAD_BG          0x3a1410   // a declining or destructive button
#define UI_COL_BAD_BG_PRESSED  0x602020
// A settings row that deletes something: the factory reset's row in the
// system screen (TONE_DANGER there), dark red with the pressed red as border.
#define UI_COL_DANGER_ROW      0x180a0e
#define UI_COL_DANGER_TEXT     0xff6060
#define UI_COL_ARCHIVED        0x808080   // an archived spool, a weight nobody reported
#define UI_COL_ARCHIVE_TEXT    0xffb060   // archiving: its label, the bin icon
#define UI_COL_ARCHIVE_BG      0x3a1a00
#define UI_COL_ARCHIVE_BG_PRESSED 0x6a3000   // also its border
#define UI_COL_RESTORE_BG_PRESSED 0x156040
#define UI_COL_DRY             0x5ad1ff   // drying: the drop icon
#define UI_COL_SIGNAL_LOW      0xe06020   // weak WiFi in the header
#define UI_COL_SIGNAL_LOW_LIST 0xff8000   // weak WiFi in the network list
#define UI_COL_ALERT_BG_PRESSED 0x5a2418
#define UI_COL_ALERT_TEXT      0xffb0a0

// ---- buttons by role -----------------------------------------
#define UI_COL_GO_BG           0x1a3020   // the green fill: go ahead, an active choice, the current row, restore
#define UI_COL_GO_BG_PRESSED   0x2a5030   // also its border
#define UI_COL_QUIET_BG_PRESSED 0x2a3040   // a quiet button pressed, a switch that is off pressed
#define UI_COL_CHOICE_BG       0x0a2a40   // a chosen language or date format
#define UI_COL_CHOICE_BG_PRESSED 0x1a4060
#define UI_COL_AMBER_BG        0x2a2010   // tare, the factor keys, the vendor answer
#define UI_COL_AMBER_BG_PRESSED 0x4a4020
#define UI_COL_AMBER_LINE      0x3a3010   // their border, and a hint row's
#define UI_COL_AMBER_ROW       0x1a1a08   // a hint row
#define UI_COL_CAUTION_BG      0x3a2800   // go ahead despite a warning; a caution row's border
#define UI_COL_CAUTION_BG_PRESSED 0x5a4000
#define UI_COL_CAUTION_ROW     0x161206   // a settings row that needs care
#define UI_COL_CLOSE_LINE      0x601010   // the border of a close or unlink button
#define UI_COL_PICKED_BG       0x1a4030   // a chosen answer: backend, raise capacity, a matching link, a keypad's OK
#define UI_COL_ALT_TEXT        0x80c8ff   // a blue answer's label: empty spool, new spool
#define UI_COL_KEY_DEL         0x1a1020   // the delete key of a number pad
#define UI_COL_MATCH_BG_PRESSED 0x18705a
#define UI_COL_NFC_FRAME       0x3a6ea8   // the frame of the NFC reset question

// One widget each
#define UI_COL_LINK_BG         0x1e3000   // main screen: link a spool
#define UI_COL_LINK_BG_PRESSED 0x2e5000
#define UI_COL_LINK_LINE       0x4a7800
#define UI_COL_LINK_TEXT       0xb8e030
#define UI_COL_COPY_BG         0x00222a   // main screen: copy a spool
#define UI_COL_COPY_BG_PRESSED 0x003a48
#define UI_COL_COPY_LINE       0x00b8d4
#define UI_COL_COPY_TEXT       0x20d8f8
#define UI_COL_WEIGHT_SENT     0x40ff80   // the weight button once the value is sent
#define UI_COL_WEIGHT_COUNT    0x60f0c0   // its countdown
#define UI_COL_AMS_YES_TEXT    0x80ffa0   // AMS assignment question
#define UI_COL_AMS_NO_TEXT     0xffa0a0
#define UI_COL_AMS_NO_PRESSED  0x702020
#define UI_COL_FILAMENT_BG     0x0a2820   // weight question: this filament
#define UI_COL_BAG_BG_PRESSED  0x2a6030
#define UI_COL_KOFI_BG         0x1a2800   // info screen tiles
#define UI_COL_KOFI_INK        0xa0d840
#define UI_COL_DISCORD_BG      0x12103a
#define UI_COL_DISCORD_INK     0x8090ff
#define UI_COL_MAKERWORLD_BG   0x1a0a18
#define UI_COL_MAKERWORLD_INK  0xc060e0

// ---- content -------------------------------------------------
// Fixed colours next to data, not part of the look: a palette may
// leave them alone. Colours that come from a spool are never here.
#define UI_COL_ON_BRIGHT_FILL  0x000000   // a label on a light filament colour
#define UI_COL_ON_DARK_FILL    0xffffff   // a label on a dark one
#define UI_COL_QR_DARK         0x000000   // a QR code must stay black on white to scan
#define UI_COL_QR_LIGHT        0xffffff
#define UI_COL_SWATCH_NONE     0x333333   // a spool without a colour
#define UI_COL_SWATCH_GLASS    0xdce6f0   // a transparent filament

// ---- type ----------------------------------------------------
#define UI_FONT_CAPTION        (&lv_font_montserrat_ext_12)
#define UI_FONT_SMALL          (&lv_font_montserrat_ext_14)
#define UI_FONT_BODY           (&lv_font_montserrat_ext_16)
#define UI_FONT_TITLE          (&lv_font_montserrat_ext_18)
#define UI_FONT_HEADLINE       (&lv_font_montserrat_ext_20)
#define UI_FONT_ICON           (&lv_font_montserrat_ext_24)

// ---- shapes --------------------------------------------------
#define UI_RADIUS_BOX          12   // a popup's box, a settings tile
#define UI_RADIUS_ROW          10   // a settings row
#define UI_RADIUS_BTN          8
#define UI_RADIUS_INPUT        6
#define UI_TOUCH_MIN           44   // the smallest thing a finger is asked to hit
#define UI_POPUP_W             400  // a two button question
#define UI_POPUP_BTN_W         170
#define UI_POPUP_BTN_H         56

// ---- the card: question, waiting, result ---------------------
// One footprint for the three stages of something the user set off: the
// question, the card that stands while it runs, and the result. Measured off
// the tag write question (BOX_H and BTN_Y in tag_write_popup.cpp), so each
// stage appears exactly where the one before stood and only its contents
// change. The row of answers is where the waiting card's bar runs and where
// the result's OK button counts down.
#define UI_CARD_H              260
#define UI_CARD_ICON_Y          14
#define UI_CARD_TITLE_Y         52
#define UI_CARD_TEXT_Y          98
#define UI_CARD_TEXT_PAD        40   // what the text stays clear of, left and right together
#define UI_CARD_ROW_X           12   // the answer row's inset, left and right
#define UI_CARD_ROW_Y          186   // its top, UI_POPUP_BTN_H high
