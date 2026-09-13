#pragma once

void clearTagDisplay();
// Zone 4's big figure carries "waiting for a scan" at boot. As a hint it takes
// the caption size and colour; the first weight painted into it takes them
// back. Called by whoever writes the label.
void zone4WaitingStyle(bool waiting);
