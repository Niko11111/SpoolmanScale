#pragma once

// What the reader's exchanges with tags came to, counted by cause. A PN7160
// says why a command failed (NCI status codes); the PN532 path does not count
// these. Pure: no reader, no clock, tested on the host
// (test/test_nfc_rf_counts.py).

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// NCI 2.0 status codes the chip sends in its error notifications.
#define NCI_STATUS_RF_FRAME_CORRUPTED   0x02
#define NCI_STATUS_ACTIVATION_FAILED    0xA1   // found a tag, could not select it
#define NCI_STATUS_RF_TRANSMISSION      0xB0   // the answer arrived garbled
#define NCI_STATUS_RF_PROTOCOL          0xB1
#define NCI_STATUS_RF_TIMEOUT           0xB2   // the tag did not answer

struct NfcRfCounts {
  uint32_t commands;          // tag commands sent
  uint32_t answered_ok;       // an answer whose status byte was 0
  uint32_t tag_status;        // an answer, but its status byte was not 0
  uint32_t no_answer;         // nothing came back before the deadline
  uint32_t dropped;           // the chip dropped the tag during the command
  uint32_t rf_timeout;        // the chip: the tag did not answer
  uint32_t rf_corrupted;      // the chip: the answer was garbled
  uint32_t rf_protocol;       // the chip: protocol error
  uint32_t activation_failed; // the chip: a tag in the field could not be selected
  uint32_t other_errors;      // any other error notification
  uint32_t reselect_miss;     // a tag selected before did not come back in a poll
  uint8_t  last_error;        // raw status of the last error notification, 0 = none
};

// One error notification from the chip, counted by its status.
inline void nfcRfCountError(NfcRfCounts& c, uint8_t status) {
  c.last_error = status;
  switch (status) {
    case NCI_STATUS_RF_TIMEOUT:         c.rf_timeout++; break;
    case NCI_STATUS_RF_TRANSMISSION:
    case NCI_STATUS_RF_FRAME_CORRUPTED: c.rf_corrupted++; break;
    case NCI_STATUS_RF_PROTOCOL:        c.rf_protocol++; break;
    case NCI_STATUS_ACTIVATION_FAILED:  c.activation_failed++; break;
    default:                            c.other_errors++; break;
  }
}

// The status as a word for a log line.
inline const char* nfcRfStatusName(uint8_t status) {
  switch (status) {
    case NCI_STATUS_RF_TIMEOUT:         return "rf timeout";
    case NCI_STATUS_RF_TRANSMISSION:    return "transmission error";
    case NCI_STATUS_RF_FRAME_CORRUPTED: return "frame corrupted";
    case NCI_STATUS_RF_PROTOCOL:        return "protocol error";
    case NCI_STATUS_ACTIVATION_FAILED:  return "activation failed";
    default:                            return "other";
  }
}

// The counters as one JSON object, for the measurement's answer.
inline int nfcRfCountsJson(const NfcRfCounts& c, char* out, size_t out_len) {
  return snprintf(out, out_len,
                  "{\"commands\":%lu,\"answered_ok\":%lu,\"tag_status\":%lu,\"no_answer\":%lu,"
                  "\"dropped\":%lu,\"rf_timeout\":%lu,\"rf_corrupted\":%lu,\"rf_protocol\":%lu,"
                  "\"activation_failed\":%lu,\"other_errors\":%lu,\"reselect_miss\":%lu,"
                  "\"last_error\":%u}",
                  (unsigned long)c.commands, (unsigned long)c.answered_ok,
                  (unsigned long)c.tag_status, (unsigned long)c.no_answer,
                  (unsigned long)c.dropped, (unsigned long)c.rf_timeout,
                  (unsigned long)c.rf_corrupted, (unsigned long)c.rf_protocol,
                  (unsigned long)c.activation_failed, (unsigned long)c.other_errors,
                  (unsigned long)c.reselect_miss, (unsigned)c.last_error);
}
