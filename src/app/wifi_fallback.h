#pragma once

// Switching between the remembered networks, see services/wifi_known_rules.h:
// away from a network that has been gone a while, and back to the preferred
// one once it is in range and nobody is using the scale.

// From the reconnect watchdog in appLoop(), after its guards (setup screens,
// Improv, the setup portal, a roaming switch). connected: the station is up.
// quiet: nobody is using the scale, as for the roaming check.
// True while it holds the radio: a scan of its own runs, or it has just
// started a switch. The watchdog then starts no begin() of its own.
bool wifiFallbackTick(bool connected, bool quiet);

// A scan of its own runs. The roaming check waits, the two would read each
// other's results.
bool wifiFallbackBusy();
