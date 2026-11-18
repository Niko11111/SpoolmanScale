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
int fuelGaugePercent();
FuelGaugeFlow fuelGaugeFlow();

// One read of state-of-charge and charge rate on I2C_EXT. Call from the loop
// task, which owns that bus. A scale with no gauge is asked only every half
// minute, so the poll does not sit on the NFC reader's bus for nothing.
// force ignores that wait, for boot and for a bus rescan. Returns true when
// the header's picture of the cell changed.
bool fuelGaugePoll(bool force = false);
