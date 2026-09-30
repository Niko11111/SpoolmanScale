// The palette: one line per colour, dark and light side by side.
//
// Included several times with a different UI_COLOUR() each: theme.h
// turns every line into a variable UI_COL_<name>, theme.cpp into the two
// tables it fills them from. A colour is added here and nowhere else.
// Light is a first draft derived by role; it is tuned against the
// simulator, not on paper.
//
//        name                 dark      light
// ---- surfaces ------------------------------------------------
UI_COLOUR(GROUND,                 0x0a1020, 0xeef2f8)   // the screen behind everything
UI_COLOUR(SURFACE,                0x0c1828, 0xe3eaf4)   // a popup's box, a picker's box, inputs, quiet buttons, list bodies
UI_COLOUR(ROW,                    0x1a2030, 0xdbdeed)   // a settings row, a divider, a quiet button: cancel, delete a value
UI_COLOUR(ROW_PRESSED,            0x1a3050, 0xc2cde6)   // the same row under the finger, and its border
UI_COLOUR(LINE,                   0x1a3870, 0xb4bddf)   // dividers, the slider track, a quiet border
UI_COLOUR(LINE_SOFT,              0x1e2a44, 0xccd2e9)   // the fainter border of an input; a neutral answer beside a green one
UI_COLOUR(POPUP_BORDER,           0x2a4080, 0xacb2d9)   // the frame of a question; a blue action pressed
UI_COLOUR(EMPTY,                  0x182238, 0xd7dcee)   // an empty bay, the keyboard, More, "got it"
UI_COLOUR(CHIP,                   0x102040, 0xd6dcee)   // a header chip that is a button; a blue action: dried, this spool, new spool
UI_COLOUR(SCRIM,                  0x000000, 0x8090a8)   // behind a popup, at UI_OPA_SCRIM

// ---- text ----------------------------------------------------
UI_COLOUR(INK,                    0xe8f0ff, 0x131820)   // titles and values
UI_COLOUR(INK_2,                  0xc8d8f0, 0x182331)   // body text
UI_COLOUR(INK_SOFT,               0x8fa8c8, 0x283b50)   // secondary body text, still readable
UI_COLOUR(CAPTION,                0x4a6fa0, 0x3e597f)   // captions and hints
UI_COLOUR(RULE,                   0x2a4060, 0xb0bbd5)   // rules and inactive bars; as text it is INK_FAINT
UI_COLOUR(INK_FAINT,              0x2a4060, 0x667591)   // header captions and the faintest hints
UI_COLOUR(VALUE_BLUE,             0x8ab0d8, 0x183953)   // dates and similar quiet values
UI_COLOUR(INK_MAX,                0xffffff, 0x111111)   // what must be typed exactly: a network password
UI_COLOUR(INK_BRIGHT,             0xf0f0f0, 0x181818)   // a spool's material and name, a list row
UI_COLOUR(ON_ACCENT,              0x0a1020, 0xffffff)   // a label on a button filled with the accent
UI_COLOUR(OFF_TEXT,               0x8098b8, 0x304359)   // the label of an option not chosen
UI_COLOUR(ID_TEXT,                0x4a7080, 0x415d6a)   // a UUID and similar machine values
UI_COLOUR(STATUS_BLUE,            0x5090e0, 0x3079c7)   // a neutral status line, a date with no drying mode
UI_COLOUR(HDR_OFF,                0x606060, 0x606060)   // a header icon whose device is not there
UI_COLOUR(DISABLED_BG,            0x111820, 0xe6ebf3)   // a button that cannot be used now, a switch that is off
UI_COLOUR(DISABLED_TEXT,          0x2a3848, 0x707b8a)   // its label, and an option that is off

// ---- meaning -------------------------------------------------
UI_COLOUR(ACCENT,                 0x28d49a, 0x008c58)   // the house colour: titles, active choices, sliders, links
UI_COLOUR(GOOD,                   0x28d49a, 0x008c58)   // a good state: found, connected, enough left, saved
UI_COLOUR(OK_BG,                  0x1a4020, 0xaecaaf)   // a confirming button
UI_COLOUR(OK_BG_PRESSED,          0x2a7030, 0x7cbf82)
UI_COLOUR(OK_TEXT,                0x80ffb0, 0x008b46)   // its label
UI_COLOUR(OK_TEXT_2,              0x40c080, 0x008a4f)   // the smaller confirming label
UI_COLOUR(WARN,                   0xf0b838, 0x9c6f00)   // amber: attention, waiting, the scale's own figure
UI_COLOUR(BAD,                    0xe04040, 0xdb3b3c)   // red: wrong, failed
UI_COLOUR(BAD_TEXT,               0xff8080, 0xc74f53)   // a red label on a dark button
UI_COLOUR(BAD_BG,                 0x3a1410, 0xedd4ce)   // a declining or destructive button
UI_COLOUR(BAD_BG_PRESSED,         0x602020, 0xe2b6b1)
// A settings row that deletes something: the factory reset's row in the
// system screen (TONE_DANGER there), dark red with the pressed red as border.
UI_COLOUR(DANGER_ROW,             0x180a0e, 0xf9f2f4)
UI_COLOUR(DANGER_TEXT,            0xff6060, 0xd93d43)
UI_COLOUR(ARCHIVED,               0x808080, 0x4d4d4d)   // an archived spool, a weight nobody reported
UI_COLOUR(ARCHIVE_TEXT,           0xffb060, 0xaa6717)   // archiving: its label, the bin icon
UI_COLOUR(ARCHIVE_BG,             0x3a1a00, 0xedd4c2)
UI_COLOUR(ARCHIVE_BG_PRESSED,     0x6a3000, 0xe1ae8c)   // also its border
UI_COLOUR(RESTORE_BG_PRESSED,     0x156040, 0x55b788)
UI_COLOUR(DRY,                    0x5ad1ff, 0x0083ad)   // drying: the drop icon
UI_COLOUR(SIGNAL_LOW,             0xe06020, 0xcc4f0d)   // weak WiFi in the header
UI_COLOUR(SIGNAL_LOW_LIST,        0xff8000, 0xc85300)   // weak WiFi in the network list
UI_COLOUR(ALERT_BG_PRESSED,       0x5a2418, 0xe4baad)
UI_COLOUR(ALERT_TEXT,             0xffb0a0, 0x4b1d15)

// ---- buttons by role -----------------------------------------
UI_COLOUR(GO_BG,                  0x1a3020, 0xc5d7c9)   // the green fill: go ahead, an active choice, the current row, restore
UI_COLOUR(GO_BG_PRESSED,          0x2a5030, 0x9eb9a0)   // also its border
UI_COLOUR(QUIET_BG_PRESSED,       0x2a3040, 0xc8ccd9)   // a quiet button pressed, a switch that is off pressed
UI_COLOUR(CHOICE_BG,              0x0a2a40, 0xc8d8eb)   // a chosen language or date format
UI_COLOUR(CHOICE_BG_PRESSED,      0x1a4060, 0xacbfd9)
UI_COLOUR(AMBER_BG,               0x2a2010, 0xe7dccf)   // tare, the factor keys, the vendor answer
UI_COLOUR(AMBER_BG_PRESSED,       0x4a4020, 0xc3b9a0)
UI_COLOUR(AMBER_LINE,             0x3a3010, 0xd7cbb1)   // their border, and a hint row's
UI_COLOUR(AMBER_ROW,              0x1a1a08, 0xe9e9dc)   // a hint row
UI_COLOUR(CAUTION_BG,             0x3a2800, 0xe4d0b3)   // go ahead despite a warning; a caution row's border
UI_COLOUR(CAUTION_BG_PRESSED,     0x5a4000, 0xcdb288)
UI_COLOUR(CAUTION_ROW,            0x161206, 0xf3f0e9)   // a settings row that needs care
UI_COLOUR(CLOSE_LINE,             0x601010, 0xe1b5ab)   // the border of a close or unlink button
UI_COLOUR(PICKED_BG,              0x1a4030, 0xadc8ba)   // a chosen answer: backend, raise capacity, a matching link, a keypad's OK
UI_COLOUR(ALT_TEXT,               0x80c8ff, 0x003154)   // a blue answer's label: empty spool, new spool
UI_COLOUR(KEY_DEL,                0x1a1020, 0xf5ecf7)   // the delete key of a number pad
UI_COLOUR(MATCH_BG_PRESSED,       0x18705a, 0x31a889)
UI_COLOUR(NFC_FRAME,              0x3a6ea8, 0x3a6ea8)   // the frame of the NFC reset question

// One widget each
UI_COLOUR(LINK_BG,                0x1e3000, 0xcbd7b4)   // main screen: link a spool
UI_COLOUR(LINK_BG_PRESSED,        0x2e5000, 0xa5ba85)
UI_COLOUR(LINK_LINE,              0x4a7800, 0x4a7800)
UI_COLOUR(LINK_TEXT,              0xb8e030, 0x578400)
UI_COLOUR(COPY_BG,                0x00222a, 0xd0e5ec)   // main screen: copy a spool
UI_COLOUR(COPY_BG_PRESSED,        0x003a48, 0xafccd7)
UI_COLOUR(COPY_LINE,              0x00b8d4, 0x0086a1)
UI_COLOUR(COPY_TEXT,              0x20d8f8, 0x0087a5)
UI_COLOUR(WEIGHT_SENT,            0x40ff80, 0x009017)   // the weight button once the value is sent
UI_COLOUR(WEIGHT_COUNT,           0x60f0c0, 0x008b61)   // its countdown
UI_COLOUR(AMS_YES_TEXT,           0x80ffa0, 0x008b37)   // AMS assignment question
UI_COLOUR(AMS_NO_TEXT,            0xffa0a0, 0xb45d5f)
UI_COLOUR(AMS_NO_PRESSED,         0x702020, 0xdda9a3)
UI_COLOUR(FILAMENT_BG,            0x0a2820, 0xcae0d9)   // weight question: this filament
UI_COLOUR(BAG_BG_PRESSED,         0x2a6030, 0x6ab56f)
UI_COLOUR(KOFI_BG,                0x1a2800, 0xd4dfc1)   // info screen tiles
UI_COLOUR(KOFI_INK,               0xa0d840, 0x4b8600)
UI_COLOUR(DISCORD_BG,             0x12103a, 0xeee5f3)
UI_COLOUR(DISCORD_INK,            0x8090ff, 0x596fd9)
UI_COLOUR(MAKERWORLD_BG,          0x1a0a18, 0xf8eff8)
UI_COLOUR(MAKERWORLD_INK,         0xc060e0, 0xac4dcc)

// ---- LVGL default theme --------------------------------------
// What a widget shows where this code sets nothing: scrollbars, the
// focus ring, parts of the keyboard. Dark keeps the values LVGL 8.3
// starts with (lv_palette_main BLUE and RED), so that theme is unchanged.
UI_COLOUR(LV_PRIMARY,            0x2196f3, 0x008c58)
UI_COLOUR(LV_SECONDARY,          0xf44336, 0xdb3b3c)
