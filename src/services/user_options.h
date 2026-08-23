#pragma once

#include <stdint.h>

extern uint8_t last_used_mode;
extern bool g_whole_gram;

// Which address the main screen status bar shows next to the scan counter.
// 0 = nothing, 1 = this device's IP, 2 = the filament manager's address,
// 3 = this device's mDNS name.
// Backend mode is useful when running more than one instance and you want to
// see at a glance which one the scale is talking to.
// Appended rather than inserted in a sensible order: the value is persisted,
// so putting the new one in the middle would silently move every device that
// was set to "backend" onto something else.
enum IpBarMode : uint8_t {
  IP_BAR_OFF     = 0,
  IP_BAR_DEVICE  = 1,
  IP_BAR_BACKEND = 2,
  IP_BAR_MDNS    = 3,
  IP_BAR_COUNT   = 4
};
extern uint8_t g_ip_bar_mode;

// Skip the confirmation popup for a FilaMan remote link, but only when the
// spool was already on the scale when the request came in. A material or
// colour mismatch always asks regardless - see showRemoteLinkPopup().
extern bool g_flm_autolink;

// Adopt a remotely linked spool for weighing when no tag turns up. The spool
// was chosen deliberately in the web UI, so the useful answer to "no tag" is
// to weigh it anyway rather than report a failure. Nothing is written to any
// tag and no binding is stored; it lasts until the next scan.
extern bool g_flm_tagless;
// Wake the panel when the load on the scale changes. On by default: putting a
// spool down is the action the device exists to answer, so having to touch the
// screen first to read the result is the wrong way round. Switchable for a
// scale that shares a bench with something that knocks it.
extern bool g_wake_on_load;

// Where the drying date goes in BamBuddy mode. BamBuddy has no field for it
// at all - upstream issues #2863 and #1754 are open and waiting for votes -
// so the scale needs somewhere to put it, and none of the choices is obvious
// enough to make for the user.
//   OFF      nothing is written, the reminder stays blank
//   SPOOLMAN straight into Spoolman's extra.last_dried, past BamBuddy but
//            into the same database. Only when BamBuddy proxies to Spoolman;
//            the spool id is the same on both sides.
//   NOTE     a "[dried:YYYY-MM-DD]" marker inside the note field, which is
//            the only free text BamBuddy offers. Works in both modes.
enum BbDriedTarget : uint8_t {
  BB_DRIED_OFF      = 0,
  BB_DRIED_SPOOLMAN = 1,
  BB_DRIED_NOTE     = 2,
  BB_DRIED_COUNT    = 3
};
extern uint8_t g_bb_dried_target;

// Which Spoolman extra field the scale writes the tag UID into, as a
// TagFieldId - see services/tag_field.h for the table behind it and for why
// the choice covers the value format as well as the field name. Default is
// extra.tag, what this firmware has always used, so an existing installation
// notices nothing.
//
// Spoolman only. FilaMan has the native rfid_uid column and BamBuddy a fixed
// schema, neither has extra fields to choose between.
extern uint8_t g_tag_field;

// Whether the choice above was ever made, as opposed to being the default
// nobody touched. Only an untouched installation is moved to Spoolman's native
// tags when a server turns out to have them - see tagFieldAutoSelect().
extern bool g_tag_field_chosen;

// Whether the scale may write to Spoolman's card_uids, the UID list SpoolLink
// keeps for the Snapmaker U1. Only ever offered while card_uids is the
// selected tag field: it is the one convention with a list format, and a
// comma separated value in tag or nfc_id would break the very tools the
// choice exists to line up with. Off by default, and off it changes nothing at
// all: linking, copying and unlinking behave exactly as they did before.
//
// Reading that field needs no switch and never had one - it cannot damage
// anything, and the field's presence is signal enough. Writing changes the
// user's database, so it stays their decision. It also opens the link list to
// spools that already carry UIDs, which is the only way to add a second tag
// from the scale.
extern bool g_card_uids_write;
