#pragma once

#include <stdint.h>

// What the MAX17048 says the cell is doing. Resting is a rate near zero on a
// cell that has not reached full. Full is the ceiling with the rate fallen
// away, which is the only way this chip reports "done": it has no flag for it.
enum FuelGaugeFlow : uint8_t {
  FUEL_FLOW_RESTING = 0,
  FUEL_FLOW_CHARGING,
  FUEL_FLOW_DISCHARGING,
  FUEL_FLOW_FULL
};

bool fuelGaugePresent();
// Whether a gauge has ever answered on this scale (NVS "fuel_seen"). The
// settings for the battery are only offered then.
bool fuelGaugeSeen();
int fuelGaugePercent();
FuelGaugeFlow fuelGaugeFlow();

// One read of state-of-charge and charge rate on I2C_EXT. Call from the loop
// task, which owns that bus. A scale that has never had a gauge is asked only
// with force, at boot and on a bus rescan, so the poll does not sit on the NFC
// reader's bus for nothing; one that has had one is asked every half minute
// while it is missing. force also ignores that wait. Returns true when
// the header's picture of the cell changed.
bool fuelGaugePoll(bool force = false);
