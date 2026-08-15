#pragma once

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
