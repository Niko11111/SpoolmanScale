#pragma once

#include <ArduinoJson.h>
#include <stdint.h>

// The empty spool's weight, recorded at up to three levels: the spool's own,
// else the filament's default, else the vendor's. Only a level without a value
// passes on to the next; a stored 0 is a tare of nothing (tare_chain.h). With
// none set the tare is 0. The FilaMan and BamBuddy mappers leave a 0 of theirs
// out, because there it means no value.
//
// One chain for every place that reads a spool: the lookup weighs with it,
// and the link and copy lists have to agree, or a copy built from a spool
// whose tare sits only on the filament or the vendor books the core as
// filament - 130 to 250 g on a 1 kg spool.
//
// `source`, when given, receives which level answered (TareSource in
// app/app_state.h).
float spoolTare(JsonVariantConst spool, uint8_t* source = nullptr);
