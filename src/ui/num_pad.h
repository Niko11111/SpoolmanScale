#pragma once

#include <stdint.h>

// ============================================================
//  NUM PAD
//
//  The house keypad for one number: the usual header with back and close,
//  the value with its unit on the left, a hint on the right, the digits in
//  a 3x4 grid with the delete key beside 0, and the answer column - the main
//  action large, Cancel under it. The shape of the price and tare pads, for
//  every screen that only asks for a value.
//
//  One pad at a time, built on demand. Its buttons call the owner's
//  callbacks from inside LVGL's event: no HTTP there, and nothing that
//  deletes screens - set a pending flag. The pad deletes itself
//  asynchronously when it closes, unless its owner replaces it from the loop
//  (NumPadSpec.replaced_from_loop).
// ============================================================

struct NumPadSpec {
  const char *title;
  const char *hint;       // right of the value; "" for none
  const char *unit;       // after the value; "" for none
  const char *primary;    // caption of the main action, with its icon if any
  const char *initial;    // the value it opens with; "" for an empty field
  uint8_t     max_chars;  // digits and point together
  bool        decimal;    // offers the point
  bool        secret;     // never written to the log (a password)
  int         help_title; // the header's "?"; -1 for none
  int         help_text;
  // The main action, with what was typed. Returns whether the pad closes:
  // false keeps it open, e.g. after numPadSetHint() refused the value.
  bool (*on_done)(const char *text);
  // Back arrow and Cancel. The close button goes to the main screen.
  void (*on_leave)();
  // For an owner whose screen is rebuilt on the loop after the pad: leaving
  // or saving then only stops the pad from taking input, and the loop calls
  // numPadDropParked() right before it builds the next screen. Deleted from
  // its own button, the pad was gone a frame before that screen existed, and
  // the home screen flashed in between.
  bool replaced_from_loop;
  // A step under a card's Options rather than a screen of its own: the pad
  // stands as the large popup (UI_POPUP_LARGE_W x _H) over what is beneath,
  // with its title on top and Back for a way out. Back calls on_leave.
  bool popup;
  // After every key, with what is typed so far; null for none. For a hint
  // that follows the value (numPadSetHintGood()).
  void (*on_input)(const char *text);
};

void showNumPad(const NumPadSpec &spec);
bool numPadOpen();
// Replaces the hint, in amber when it refuses what was typed.
void numPadSetHint(const char *text, bool refusal);
// Replaces the hint in green: what the value typed so far comes to.
void numPadSetHintGood(const char *text);

// For navigation: hidden with the other overlays, deleted with them.
void numPadHide();
void numPadClose();
// Deletes a pad that was left or saved with replaced_from_loop set, at once.
// From the loop only, right before the owner builds its screen; a pad still
// taking input is left alone.
void numPadDropParked();
