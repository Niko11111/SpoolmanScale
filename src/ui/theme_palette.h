// The palettes: one line per colour, one value per palette side by side.
//
// Included several times with a different UI_COLOUR() each: theme.h
// turns every line into a variable UI_COL_<name>, theme.cpp into one table
// per palette that it fills them from. A colour is added here and nowhere else.
// Columns in UiThemeId order: dark, light, Spoolman dark, Spoolman light,
// FilaMan dark, FilaMan light.
// Light and the backend palettes were chosen against the simulator and
// then the panel, which shows less contrast in the bright range than a
// monitor: cards lighter than a tinted ground, outlines and text strong.
//
//        name                  dark      light     sm dark   sm light  fm dark   fm light
// ---- surfaces ------------------------------------------------
UI_COLOUR(GROUND,                0x0a1020, 0xdde3ec, 0x1f1f1f, 0xe9e6e0, 0x0c1612, 0xebe6dc)   // the screen behind everything
UI_COLOUR(SURFACE,               0x0c1828, 0xf4f6fa, 0x252525, 0xf8f7f5, 0x13261d, 0xfbfaf7)   // a popup's box, a picker's box, inputs, quiet buttons, list bodies
UI_COLOUR(ROW,                   0x1a2030, 0xf8fafd, 0x2e2e2e, 0xfbfaf8, 0x183225, 0xfdfcfa)   // a settings row, a divider, a quiet button: cancel, delete a value
UI_COLOUR(ROW_PRESSED,           0x1a3050, 0x7d8db3, 0x3d3d3d, 0x9a958b, 0x24473a, 0x8fa094)   // the same row under the finger, and its border
UI_COLOUR(LINE,                  0x1a3870, 0x7383ad, 0x424242, 0x8a857b, 0x2c4a3c, 0x7d8a80)   // dividers, the slider track, a quiet border
UI_COLOUR(LINE_SOFT,             0x1e2a44, 0x95a2c3, 0x333333, 0xb3aea4, 0x22392d, 0xaab5ac)   // the fainter border of an input; a neutral answer beside a green one
UI_COLOUR(DIVIDER,               0x1a2030, 0x6f7ea3, 0x2e2e2e, 0x8a857b, 0x1f3a2c, 0x7d8a80)   // the separators of the main and more-info screens
UI_COLOUR(POPUP_BORDER,          0x2a4080, 0x6072ad, 0x4a4239, 0x8a857b, 0x2f6a50, 0x6b7d70)   // the frame of a question; a blue action pressed
UI_COLOUR(EMPTY,                 0x182238, 0xe8ecf2, 0x262626, 0xe0ddd6, 0x142a20, 0xe4ded2)   // an empty bay, the keyboard, More, "got it"
UI_COLOUR(CHIP,                  0x102040, 0xcddcf5, 0x2e2e2e, 0xefcfb4, 0x12304a, 0xcfe2f4)   // a header chip that is a button; a blue action: dried, this spool, new spool
UI_COLOUR(ACCENT_CHIP,           0x1a3050, 0xcfe6d6, 0x3d3d3d, 0xf3e2d4, 0x24473a, 0xe2f3ea)   // a chip with a label in the accent: reload, the printer's name
UI_COLOUR(SCRIM,                 0x000000, 0x8090a8, 0x000000, 0x57544e, 0x000000, 0x5a6158)   // behind a popup, at UI_OPA_SCRIM

// ---- text ----------------------------------------------------
UI_COLOUR(INK,                   0xe8f0ff, 0x0e141d, 0xececec, 0x141414, 0xe9f3ec, 0x1a231e)   // titles and values
UI_COLOUR(INK_2,                 0xc8d8f0, 0x0f1c2b, 0xc9c9c9, 0x232323, 0xcfe0d6, 0x22302a)   // body text
UI_COLOUR(INK_SOFT,              0x8fa8c8, 0x172e44, 0xa7a7a7, 0x3a3a3a, 0xa7bcb0, 0x34463b)   // secondary body text, still readable
UI_COLOUR(CAPTION,               0x4a6fa0, 0x20436b, 0x959595, 0x3f3f3f, 0x8fa89b, 0x3f5247)   // captions and hints
UI_COLOUR(RULE,                  0x2a4060, 0x8594b5, 0x3a3a3a, 0xbdb9b1, 0x2c4a3c, 0xb6bdb3)   // rules and inactive bars; as text it is INK_FAINT
UI_COLOUR(INK_FAINT,             0x2a4060, 0x3a4a66, 0x7a7a7a, 0x5a5a5a, 0x6f8a7c, 0x56645b)   // header captions and the faintest hints
UI_COLOUR(VALUE_BLUE,            0x8ab0d8, 0x002d48, 0xe6c89c, 0x5c4020, 0x9fd8ff, 0x1e5f9e)   // dates and similar quiet values
UI_COLOUR(INK_MAX,               0xffffff, 0x0e0e0e, 0xffffff, 0x000000, 0xffffff, 0x000000)   // what must be typed exactly: a network password
UI_COLOUR(INK_BRIGHT,            0xf0f0f0, 0x141414, 0xf2f2f2, 0x111111, 0xf2f8f4, 0x111611)   // a spool's material and name, a list row
UI_COLOUR(ON_ACCENT,             0x0a1020, 0xffffff, 0x1f1f1f, 0xffffff, 0x0b120e, 0xffffff)   // a label on a button filled with the accent
UI_COLOUR(OFF_TEXT,              0x8098b8, 0x1d344b, 0xa7a7a7, 0x525252, 0xa7bcb0, 0x4d5d53)   // the label of an option not chosen
UI_COLOUR(ID_TEXT,               0x4a7080, 0x274755, 0x8a8a8a, 0x5a5a5a, 0x7f9a8c, 0x56645b)   // a UUID and similar machine values
UI_COLOUR(STATUS_BLUE,           0x5090e0, 0x0055a8, 0xe6c89c, 0x5c3510, 0x6cc6ff, 0x1f6aa8)   // a neutral status line, a date with no drying mode
UI_COLOUR(HDR_OFF,               0x606060, 0x484848, 0x606060, 0x9a9a9a, 0x5a665f, 0x9aa29b)   // a header icon whose device is not there
UI_COLOUR(DISABLED_BG,           0x111820, 0xd9dfe9, 0x1c1c1c, 0xe6e4df, 0x101d17, 0xe4e0d8)   // a button that cannot be used now, a switch that is off
UI_COLOUR(DISABLED_TEXT,         0x2a3848, 0x505b6b, 0x4a4a4a, 0xa3a09a, 0x33473c, 0xa3a69e)   // its label, and an option that is off
UI_COLOUR(UNAVAILABLE,           0x4a6fa0, 0x566078, 0x666666, 0x6a645a, 0x5f7a6c, 0x6a7268)   // an option that cannot be chosen now

// ---- meaning -------------------------------------------------
UI_COLOUR(ACCENT,                0x28d49a, 0x006b35, 0xff9442, 0x9a4312, 0x4ee3a2, 0x0f7a52)   // the house colour: titles, active choices, sliders, links
UI_COLOUR(GOOD,                  0x28d49a, 0x006b35, 0x5fe06f, 0x1f6b22, 0x86efac, 0x15803d)   // a good state: found, connected, enough left, saved
UI_COLOUR(OK_BG,                 0x1a4020, 0x85a987, 0x2a352a, 0xdfeadb, 0x1a4a33, 0xd9ecdf)   // a confirming button
UI_COLOUR(OK_BG_PRESSED,         0x2a7030, 0x389449, 0x3f6b3f, 0xbcd4b6, 0x2a6e4e, 0xb3d8bf)
UI_COLOUR(OK_TEXT,               0x80ffb0, 0x006b2c, 0x8ff29a, 0x1f5f22, 0x86efac, 0x136b33)   // its label
UI_COLOUR(OK_TEXT_2,             0x40c080, 0x005c2c, 0x5fe06f, 0x1f5f22, 0x5fd69a, 0x136b33)   // the smaller confirming label
UI_COLOUR(WARN,                  0xf0b838, 0x945000, 0xffd23a, 0x8a5000, 0xf7c86a, 0x8a5a00)   // amber: attention, waiting, the scale's own figure
UI_COLOUR(BAD,                   0xe04040, 0xc9252c, 0xe05a42, 0xb3261e, 0xef4444, 0xb91c1c)   // red: wrong, failed
UI_COLOUR(BAD_TEXT,              0xff8080, 0xb01520, 0xff6e5c, 0xa5140e, 0xfca5a5, 0xa5140e)   // a red label on a dark button
UI_COLOUR(BAD_BG,                0x3a1410, 0xdcbcb5, 0x36261f, 0xf6ddd6, 0x3a1616, 0xf6ddd6)   // a declining or destructive button
UI_COLOUR(BAD_BG_PRESSED,        0x602020, 0xc58f89, 0x5a3028, 0xecbcb0, 0x5e2424, 0xecbcb0)
// A settings row that deletes something: the factory reset's row in the
// system screen (TONE_DANGER there), dark red with the pressed red as border.
UI_COLOUR(DANGER_ROW,            0x180a0e, 0xf4ebed, 0x2a1f1d, 0xfaece8, 0x241414, 0xfaece8)
UI_COLOUR(DANGER_TEXT,           0xff6060, 0xce1731, 0xd98a7a, 0xa33a28, 0xfca5a5, 0xa33a28)
UI_COLOUR(ARCHIVED,              0x808080, 0x0e0e0e, 0x808080, 0x707070, 0x808080, 0x707070)   // an archived spool, a weight nobody reported
UI_COLOUR(ARCHIVE_TEXT,          0xffb060, 0x9c5700, 0xd0a479, 0x8a5a2a, 0xf3a05f, 0x8a5a2a)   // archiving: its label, the bin icon
UI_COLOUR(ARCHIVE_BG,            0x3a1a00, 0xdbbca5, 0x33302c, 0xf0e3d3, 0x33261a, 0xf0e3d3)
UI_COLOUR(ARCHIVE_BG_PRESSED,    0x6a3000, 0xbf8359, 0x4a4239, 0xe0c7a8, 0x54391f, 0xe0c7a8)   // also its border
UI_COLOUR(RESTORE_BG_PRESSED,    0x156040, 0x36a876, 0x3f6b3f, 0xbcd4b6, 0x2a6e4e, 0xb3d8bf)
UI_COLOUR(DRY,                   0x5ad1ff, 0x0075a2, 0x7fb8d8, 0x2a7fa8, 0x6cc6ff, 0x1f6aa8)   // drying: the drop icon
UI_COLOUR(SIGNAL_LOW,            0xe06020, 0xbf3800, 0xe09050, 0xb85a20, 0xf3a05f, 0xb85a20)   // weak WiFi in the header
UI_COLOUR(SIGNAL_LOW_LIST,       0xff8000, 0xbb3e00, 0xe09050, 0xb85a20, 0xf3a05f, 0xb85a20)   // weak WiFi in the network list
UI_COLOUR(ALERT_BG_PRESSED,      0x5a2418, 0xc89585, 0x5a3028, 0xecbcb0, 0x5e2424, 0xecbcb0)
UI_COLOUR(ALERT_TEXT,            0xffb0a0, 0x340000, 0xe8b0a0, 0x7a2a1a, 0xfcc5b5, 0x7a2a1a)

// ---- buttons by role -----------------------------------------
UI_COLOUR(GO_BG,                 0x1a3020, 0x9ccaa6, 0x263526, 0xc4e0bd, 0x1d4a36, 0xc7e6d3)   // the green fill: go ahead, an active choice, the current row, restore
UI_COLOUR(GO_BG_PRESSED,         0x2a5030, 0x5f9a69, 0x3f6b3f, 0x7fae77, 0x2f6a50, 0x7fb894)   // also its border
UI_COLOUR(QUIET_BG_PRESSED,      0x2a3040, 0xa9afbf, 0x383838, 0xe0ddd6, 0x24392e, 0xe0dbd0)   // a quiet button pressed, a switch that is off pressed
UI_COLOUR(CHOICE_BG,             0x0a2a40, 0xacc1d9, 0x35291f, 0xf3e2d4, 0x1a4436, 0xd3eee0)   // a chosen language or date format
UI_COLOUR(CHOICE_BG_PRESSED,     0x1a4060, 0x809aba, 0x4a3424, 0xe6c9b0, 0x2a5e4a, 0xb3d8c4)
UI_COLOUR(AMBER_BG,              0x2a2010, 0xe8cf96, 0x33302c, 0xeed49a, 0x33301c, 0xf2e2b8)   // tare, the factor keys, the vendor answer
UI_COLOUR(AMBER_BG_PRESSED,      0x4a4020, 0x9d9172, 0x4a4239, 0xe3d3a4, 0x4d4628, 0xe6d29a)
UI_COLOUR(AMBER_LINE,            0x3a3010, 0xb8964a, 0x4a4239, 0xb08a3a, 0x5a4f2a, 0xb08a3a)   // their border, and a hint row's
UI_COLOUR(AMBER_ROW,             0x1a1a08, 0xdcdccb, 0x2a2723, 0xf7f0dc, 0x1c1e12, 0xf7f0dc)   // a hint row
UI_COLOUR(CAUTION_BG,            0x3a2800, 0xceb691, 0x3a3226, 0xf0dfc0, 0x3e3218, 0xf0dfc0)   // go ahead despite a warning; a caution row's border
UI_COLOUR(CAUTION_BG_PRESSED,    0x5a4000, 0xa68853, 0x544632, 0xe3c78e, 0x5a4824, 0xe3c78e)
UI_COLOUR(CAUTION_ROW,           0x161206, 0xebe7de, 0x26231f, 0xf8f1e4, 0x1a1a10, 0xf8f1e4)   // a settings row that needs care
UI_COLOUR(CLOSE_LINE,            0x601010, 0xc38d81, 0x5a3028, 0xd9a194, 0x5e2424, 0xd9a194)   // the border of a close or unlink button
UI_COLOUR(PICKED_BG,             0x1a4030, 0x84a695, 0x2a3a2a, 0xdcebd9, 0x1d4a36, 0xd3ecdc)   // a chosen answer: backend, raise capacity, a matching link, a keypad's OK
UI_COLOUR(ALT_TEXT,              0x80c8ff, 0x00274c, 0xc9c9c9, 0x3a3a3a, 0x9fd8ff, 0x1e5f9e)   // a blue answer's label: empty spool, new spool
UI_COLOUR(KEY_DEL,               0x1a1020, 0xede2f0, 0x2a2323, 0xf1e4e1, 0x1e2420, 0xf1e4e1)   // the delete key of a number pad
UI_COLOUR(MATCH_BG_PRESSED,      0x18705a, 0x009978, 0x3f6b3f, 0x9fc298, 0x2f7a58, 0x9fcfb2)
UI_COLOUR(NFC_FRAME,             0x3a6ea8, 0x14609e, 0x4a4239, 0x9e9a91, 0x2f6a8f, 0x6b8fb0)   // the frame of the NFC reset question

// One widget each
UI_COLOUR(LINK_BG,               0x1e3000, 0xaebe92, 0x35291f, 0xf3e2d4, 0x1a4436, 0xd3eee0)   // main screen: link a spool
UI_COLOUR(LINK_BG_PRESSED,       0x2e5000, 0x75904e, 0x4a3424, 0xe6c9b0, 0x2a5e4a, 0xb3d8c4)
UI_COLOUR(LINK_LINE,             0x4a7800, 0x346a00, 0x8a6a4d, 0xb25c26, 0x3fa77a, 0x0f7a52)
UI_COLOUR(LINK_TEXT,             0xb8e030, 0x417600, 0xff9442, 0x8f4a1d, 0x4ee3a2, 0x0f6a47)
UI_COLOUR(COPY_BG,               0x00222a, 0xb9d5de, 0x262626, 0xf3f1ed, 0x0f2a3a, 0xdbeaf6)   // main screen: copy a spool
UI_COLOUR(COPY_BG_PRESSED,       0x003a48, 0x87adbb, 0x333333, 0xdcd9d3, 0x1a4058, 0xb8d3ea)
UI_COLOUR(COPY_LINE,             0x00b8d4, 0x007895, 0x5a5a5a, 0x8a8680, 0x6cc6ff, 0x2b7bc7)
UI_COLOUR(COPY_TEXT,             0x20d8f8, 0x007999, 0xc9c9c9, 0x3a3a3a, 0x6cc6ff, 0x1f6aa8)
UI_COLOUR(WEIGHT_BG,             0x1a3020, 0x9ccaa6, 0xff9442, 0x9a4312, 0x4ee3a2, 0x0f7a52)   // main screen: the weight button, the screen's main action
UI_COLOUR(WEIGHT_BG_PRESSED,     0x2a5030, 0x5f9a69, 0xffa452, 0x8a3302, 0x5ef3b2, 0x006a42)   // also its border
UI_COLOUR(WEIGHT_TEXT,           0x40c080, 0x005c2c, 0x1f1f1f, 0xffffff, 0x0b120e, 0xffffff)   // its label
UI_COLOUR(WEIGHT_AUTO,           0x28d49a, 0x006b35, 0x1f1f1f, 0xffffff, 0x0b120e, 0xffffff)   // its label while the weight goes out by itself
UI_COLOUR(WEIGHT_SENT,           0x40ff80, 0x008100, 0x1f1f1f, 0xffffff, 0x0b120e, 0xffffff)   // the weight button once the value is sent
UI_COLOUR(WEIGHT_COUNT,          0x60f0c0, 0x007c50, 0x1f1f1f, 0xffffff, 0x0b120e, 0xffffff)   // its countdown
UI_COLOUR(AMS_YES_TEXT,          0x80ffa0, 0x007c20, 0x8fd18f, 0x2f6a2f, 0x86efac, 0x15803d)   // AMS assignment question
UI_COLOUR(AMS_NO_TEXT,           0xffa0a0, 0xa84a4e, 0xd98a7a, 0xa33a28, 0xfca5a5, 0xa33a28)
UI_COLOUR(AMS_NO_PRESSED,        0x702020, 0xba7b75, 0x5a3028, 0xecbcb0, 0x5e2424, 0xecbcb0)
UI_COLOUR(FILAMENT_BG,           0x0a2820, 0xb0ccc3, 0x263526, 0xe3eedf, 0x183a2c, 0xe3eedf)   // weight question: this filament
UI_COLOUR(BAG_BG_PRESSED,        0x2a6030, 0x52a65a, 0x3f6b3f, 0xbcd4b6, 0x2a6e4e, 0xb3d8bf)
UI_COLOUR(KOFI_BG,               0x1a2800, 0xbdcba5, 0x1a2800, 0xbdcba5, 0x1a2800, 0xbdcba5)   // info screen tiles
UI_COLOUR(KOFI_INK,              0xa0d840, 0x327800, 0xa0d840, 0x327800, 0xa0d840, 0x327800)
UI_COLOUR(DISCORD_BG,            0x12103a, 0xe2d7e9, 0x12103a, 0xe2d7e9, 0x12103a, 0xe2d7e9)
UI_COLOUR(DISCORD_INK,           0x8090ff, 0x3b60d2, 0x8090ff, 0x3b60d2, 0x8090ff, 0x3b60d2)
UI_COLOUR(MAKERWORLD_BG,         0x1a0a18, 0xf2e6f2, 0x1a0a18, 0xf2e6f2, 0x1a0a18, 0xf2e6f2)
UI_COLOUR(MAKERWORLD_INK,        0xc060e0, 0x9f34c4, 0xc060e0, 0x9f34c4, 0xc060e0, 0x9f34c4)

// ---- LVGL default theme --------------------------------------
// What a widget shows where this code sets nothing: scrollbars, the
// focus ring, parts of the keyboard. Dark keeps the values LVGL 8.3
// starts with (lv_palette_main BLUE and RED), so that theme is unchanged.
UI_COLOUR(LV_PRIMARY,            0x2196f3, 0x007d46, 0xbe682f, 0xb25c26, 0x4ee3a2, 0x1c9b6b)
UI_COLOUR(LV_SECONDARY,          0xf44336, 0xdb3b3c, 0xc4503a, 0xb7402c, 0xef4444, 0xb91c1c)
