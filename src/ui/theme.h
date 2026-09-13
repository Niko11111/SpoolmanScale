#pragma once

#include <lvgl.h>

// ============================================================
//  THEME
//
//  The one table for what the panel looks like: colours, type
//  sizes, radii, the house measurements of a button. Around 900
//  call sites still carry these as literals; a module moves onto
//  this table when it is next touched, and a new module starts
//  here. Once the literals are gone, a second palette - light,
//  or one per backend - is a second copy of the colour block and
//  a switch, not a hunt through the tree.
//
//  Names say what a colour is for, not what it looks like:
//  UI_COL_CAPTION rather than "dim blue". A palette that swaps
//  the blue for grey changes one line and every caption follows.
// ============================================================

// ---- surfaces ------------------------------------------------
#define UI_COL_GROUND          0x0a1020   // the screen behind everything
#define UI_COL_SURFACE         0x0c1828   // a popup's box
#define UI_COL_SURFACE_2       0x0a1828   // inputs, quiet buttons, list bodies
#define UI_COL_ROW             0x0a1e30   // a settings row
#define UI_COL_ROW_PRESSED     0x1a3050   // the same row under the finger, and its border
#define UI_COL_LINE            0x1a3060   // dividers, the slider track, a quiet border
#define UI_COL_LINE_SOFT       0x1a2840   // the fainter border of an input
#define UI_COL_POPUP_BORDER    0x2a4080   // the frame of a question
#define UI_COL_EMPTY           0x101f33   // an empty bay
#define UI_COL_SCRIM           0x000000   // behind a popup, at UI_OPA_SCRIM

#define UI_OPA_SCRIM           LV_OPA_70

// ---- text ----------------------------------------------------
#define UI_COL_INK             0xe8f0ff   // titles and values
#define UI_COL_INK_2           0xc8d8f0   // body text
#define UI_COL_INK_SOFT        0x8fa8c8   // secondary body text, still readable
#define UI_COL_CAPTION         0x4a6fa0   // captions and hints
#define UI_COL_RULE            0x2a4060   // rules and inactive bars - never text
#define UI_COL_VALUE_BLUE      0x8ab0d8   // dates and similar quiet values

// ---- meaning -------------------------------------------------
#define UI_COL_ACCENT          0x28d49a   // the house green: active, found, ok
#define UI_COL_ACCENT_DIM      0x0d2e1a   // the fill behind an active choice
#define UI_COL_OK_BG           0x1a4020   // a confirming button
#define UI_COL_OK_BG_PRESSED   0x2a7030
#define UI_COL_OK_TEXT         0x80ffb0   // its label
#define UI_COL_OK_TEXT_2       0x40c080   // the smaller confirming label
#define UI_COL_WARN            0xf0b838   // amber: attention, waiting, the scale's own figure
#define UI_COL_BAD             0xe04040   // red: wrong, failed
#define UI_COL_BAD_TEXT        0xff8080   // a red label on a dark button
#define UI_COL_BAD_BG          0x3a1010   // a declining or destructive button
#define UI_COL_BAD_BG_PRESSED  0x602020

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
