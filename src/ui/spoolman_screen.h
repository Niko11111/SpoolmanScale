#pragma once

void buildSpoolmanScreen();
// Deletes the address screen and drops the three labels that hang off it.
void closeSpoolmanScreen();
// Runs the address test the save button parked. Called from appLoop().
void handleSpoolmanScreenDeferredActions();
void showSpoolmanFailScreen(bool is_setup_flow);

// Throws the stored backend address away and rebuilds the address screen, so
// the numeric pad comes back. The escape hatch for a host name that was typed
// in the browser and turned out wrong: the pad cannot produce letters, so
// without this there is no way to correct one from the device.
//
// Called from the confirm popup, never straight from a button.
void spoolmanClearHost();
