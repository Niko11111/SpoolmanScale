#pragma once

// ============================================================
//  BAMBUDDY DEVICE PRESENCE
//
//  Makes the scale appear in BamBuddy under Settings >
//  SpoolBuddy and keeps it there: registration, heartbeat,
//  live weight, tag removal, and an answer to every command
//  the server queues for it.
//
//  Kept out of app_loop because it is a state machine, not a
//  step: registration has to survive a device being deleted in
//  the web interface, and the commands have to be answered even
//  when the answer is "this scale cannot do that".
// ============================================================

// Once per loop pass. Does nothing unless BamBuddy is the active backend and
// WiFi is up, and paces its own requests internally.
void bambuddyDeviceTick();

// Forgets the registration so the next tick registers again. Called when the
// address, the key or the backend itself changes - the device may be talking
// to a different server after that.
void bambuddyDeviceReset();
