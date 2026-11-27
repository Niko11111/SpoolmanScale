#pragma once

#include <cstring>

#include "app/app_loop.h"
#include "services/tag_format_rules.h"

// What the second tag question does with the read of a new tag
// (ui/second_tag_popup.cpp).

enum Tag2Step : uint8_t {
  T2S_WAIT,        // nothing settled yet
  T2S_LINK,        // link it now
  T2S_ASK_BACK,    // not linked: ask to lift the spool and put it back
  T2S_OTHER_SPOOL, // a Bambu chip of another spool: not linked, said on the card
};

// Whether a chip that opened with the Bambu keys belongs to another spool.
// Both chips of one Bambu spool carry the same tray uuid, so two of them
// settle it - two spools of the same filament side by side included. With
// only one (the spool's first tag was no Bambu tag), the chip's material,
// colour and maker against the spool's decide: data_differs is
// tagSpoolCompare(). On 23.11.2026 a Bambu "PLA Tough+" chip was linked to a
// ColorFabb PETG spool because nothing asked.
inline bool tag2BambuOtherSpool(const char* first_tray, const char* second_tray,
                                bool data_differs) {
  if (strlen(first_tray) == TAG_HEX_LEN_TRAY_UUID &&
      strlen(second_tray) == TAG_HEX_LEN_TRAY_UUID)
    return strcmp(first_tray, second_tray) != 0;
  return data_differs;
}

// first_bambu: the spool's first tag was a Bambu tag.
// refused_before: this chip refused the Bambu keys once already in this
// question, and has been off the reader since.
// other_spool: tag2BambuOtherSpool() for a chip read as Bambu.
//
// A refusal alone does not tell a foreign card from a weak Bambu chip: on
// 15.11.2026 a Bambu chip held far off and moved slowly answered both probes
// with the card's authentication error (0x14). So on a Bambu spool the first
// refusal gets the put-back a silent chip gets, and only a second one, after
// the spool was put back, links the card as a plain tag. Anything that read
// as something else (NTAG, Creality, blank) is linked at once.
inline Tag2Step tag2Step(TagVerdict v, bool first_bambu, bool refused_before,
                         bool other_spool) {
  switch (v) {
    case TV_NONE:      return T2S_WAIT;
    case TV_NO_ANSWER: return T2S_ASK_BACK;
    case TV_REFUSED:   return (first_bambu && !refused_before) ? T2S_ASK_BACK : T2S_LINK;
    case TV_BAMBU:     return other_spool ? T2S_OTHER_SPOOL : T2S_LINK;
    case TV_OTHER:     return T2S_LINK;
  }
  return T2S_WAIT;
}
