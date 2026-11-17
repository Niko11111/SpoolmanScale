#pragma once

// A read-rate measurement for comparing readers and antennas (Notes, PN7160,
// 6.9). For a few seconds the reader does nothing but this: every 200 ms one
// poll, and a tag it finds is asked for one block - a Bambu tag sector 0
// block 1 with its own key B (as the scan path reads it), an NTAG page 4, an
// ISO 15693 tag block 0. The same steps for the PN532 and the PN7160, at the
// same pace, so the two rates compare. Any other 4 byte tag counts its UID
// only once its Bambu key has failed three times in a row.
//
// Started over the web (web/web_nfc_test.cpp, maintenance gate), run by the
// loop task; the scan path stands aside while it runs. No screen of its own.

#include <stddef.h>
#include <stdint.h>

#define NFC_MEASURE_SECONDS_DEFAULT 10
#define NFC_MEASURE_SECONDS_MAX     60

// Parks a measurement for the loop task. False while one is waiting or
// running, or when seconds is outside 1..NFC_MEASURE_SECONDS_MAX.
bool nfcMeasureRequest(uint16_t seconds);

// Called from appLoop() on every pass. Starts a parked measurement, runs one
// cycle when one is due, ends it when its time is up. True while one runs:
// the reader is the measurement's then.
bool nfcMeasureTick();

// The running or last measurement as one JSON object. state is idle, pending,
// running, done or failed (the reader was not ready).
void nfcMeasureJson(char* out, size_t out_len);
