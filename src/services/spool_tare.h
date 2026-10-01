#pragma once

#include <ArduinoJson.h>
#include <stdint.h>

// The empty spool's weight, recorded at up to three levels: the spool's own,
// else the filament's default, else the vendor's. 0 counts as unset at every
// level, and with none set the tare is 0.
//
// One chain for every place that reads a spool: the lookup weighs with it,
// and the link and copy lists have to agree, or a copy built from a spool
// whose tare sits only on the filament or the vendor books the core as
// filament - 130 to 250 g on a 1 kg spool.
//
// `source`, when given, receives which level answered (TareSource in
// app/app_state.h).
float spoolTare(JsonVariantConst spool, uint8_t* source = nullptr);
