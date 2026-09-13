#pragma once

// What the restart button runs before it restarts. A setting that needs a
// restart is written here and not by the button that chose it: written
// earlier, a cancelled change was on the next boot anyway.
typedef void (*RebootCommitFn)();

void showRebootPopup(RebootCommitFn commit = nullptr);
// For the navigation: a reboot question under another screen is void.
void closeRebootPopup();
