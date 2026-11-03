#pragma once

#include <stdint.h>

// Central point for the first time setup state.
//
// The flag itself lives in app_state, but nothing should assign it directly:
// going through here means every change lands in the log with the reason. The
// setup chain spans a reboot (choosing German restarts the device) and half a
// dozen screens, so a wrong value is otherwise very hard to trace after the
// fact.
void setSetupActive(bool active, const char *reason);

// One line at boot saying which branch was taken and what the flag ended up
// as. Answers "was this a real first boot or menu navigation" without
// guesswork.
void logSetupBootState(const char *branch);

// The numbered steps of the first setup, shown as "n of N" in each step's
// header. Language and welcome come before the count, the closing screen
// after it.
enum SetupStep : uint8_t {
  SETUP_STEP_NONE = 0,
  SETUP_STEP_WIFI,
  SETUP_STEP_BACKEND,
  SETUP_STEP_SERVER,
  SETUP_STEP_ONLINE,        // instead of the server: which service, its key comes next
  SETUP_STEP_CREDENTIALS,
  SETUP_STEP_SCALE
};

// How many numbered steps the chosen backend takes, and where a step falls
// in them; 0 for a step that is not counted. The scale is always the last.
int setupStepCount();
// The same as seen from one step. On the online page nothing is switched yet,
// and whichever service is picked has the credentials step.
int setupStepTotal(SetupStep step);
int setupStepNumber(SetupStep step);

// What the server step found, for the closing summary: the address test got
// no usable answer and the user went on with Later, or the server asked for
// a key. Both are set by the address screen and cleared by a good answer.
void setupNoteServerLater(bool later);
bool setupServerLater();
void setupNoteKeyRequired(bool required);
bool setupKeyRequired();
