#pragma once

#include <stdint.h>

// Whether this device has a load cell at all. A SpoolmanScale can be built
// with display and reader only - there is a printable mount for exactly that -
// and it is then a spool terminal: hold a tag against it, see the spool, put
// it away on a shelf or hand it to a printer.
//
// Off takes the whole weighing side out of the way rather than leaving it
// broken on screen: the ADC is never probed, the home screen loses its scale
// column and the TARE key, the menu loses calibration and bag weight, and the
// diagnosis stops reporting a chip nobody fitted as a fault.
//
// On by default, so a device that has a scale notices nothing at all. It is
// read once while the interface is built, which is why changing it asks for a
// restart instead of rearranging the home screen under the user's hands.
extern bool g_scale_fitted;

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
  IP_BAR_OFF          = 0,
  IP_BAR_DEVICE       = 1,
  IP_BAR_BACKEND      = 2,
  IP_BAR_MDNS         = 3,
  // Address and port. Its own mode rather than a port added to the one above:
  // that one exists to tell two servers apart at a glance and drops the port
  // because it is the same on all of them, and the bar is only 94 px wide.
  // With two instances of the same manager on one host the port is the only
  // thing that differs, and then it is the only thing worth showing.
  IP_BAR_BACKEND_PORT = 4,
  IP_BAR_COUNT        = 5
};
extern uint8_t g_ip_bar_mode;

// Skip the confirmation popup for a FilaMan remote link, but only when the
// spool was already on the scale when the request came in. A material or
// colour mismatch always asks regardless - see showRemoteLinkPopup().
extern bool g_flm_autolink;

// Whether a remote write trigger actually writes the tag, or only links the
// UID. On by default: the button that sends the trigger is labelled "write
// RFID tag", so writing is the answer the user already gave by pressing it,
// and asking a second time on the device is what testers complained about.
// The confirmation still appears - it just confirms both steps at once, and
// says which format it is about to put on the tag.
//
// Off turns the trigger back into the pure link it was before, for anyone who
// uses it to bind tags that already carry something else.
extern bool g_flm_remote_write;

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

// Try Snapmaker's keys on a 4 byte tag that refused the Bambu ones. Off by
// default, and off means not one extra byte goes to the reader: nobody here
// owns a Snapmaker spool, so the decoding is proven on a contributor's tag
// only, and the attempt costs every other 4 byte tag about half a second.
// Only in the web interface, the device has no screen to spare for it.
extern bool g_snapmaker_tags;

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

// The two fields FilaMan's Bambu Lab plugin owns, and whether this scale
// keeps them up to date. Reading them needs no switch and never had one: it
// cannot damage anything, and a spool the printer already knows is a spool
// this scale should recognise. Writing changes somebody else's field, so it
// stays the user's decision.
//
// The chip uid goes into the first free of bambu_rfid_tag_1 and _2, and the
// plugin only ever fills the first from what the AMS reported. Off by
// default: it is metadata, and the one case where it earns its keep is a
// Bambu tag that will not decrypt and has nothing but its chip uid to offer.
extern bool g_flm_bambu_tags;

// external_id is the only field the plugin's duplicate check looks at. A
// spool this scale linked carries the tray uuid in rfid_uid instead, is
// therefore invisible to that check, and gets created a second time - five of
// seven on the instance this was measured on. Writing it as well ends that.
//
// On by default, and the price is in the info text: once the plugin owns the
// record it also maintains remaining_weight_g from the AMS estimate, which
// replaces a measured value until the next weighing.
extern bool g_flm_ext_id;

// Whether the scale offers to put the spool data on the tag once a link has
// been made on the device, and in which format.
//
// Backend independent, unlike everything else in this file: what a tag holds
// is an agreement between the tag and whoever reads it later, and no backend
// ever sees it. The question used to appear after every single link of a
// writable NTAG, in every mode, with the format hard coded - which is what
// testers reported as the thing that annoyed them most.
//
// Off by default. A link binds the UID; putting a record on the tag as well
// is a separate intention, and the tag page in the browser is the place that
// shows what would go on there before it does.
// What happens to a writable NTAG right after it was linked. Three states, one
// value: two switches would have a fourth ("off, but without asking") that
// means nothing.
//
// Off by default. A link binds the UID; putting a record on the tag as well is
// a separate intention, and the tag page in the browser is the place that shows
// what would go on there before it does.
enum TagWriteMode : uint8_t {
  TAGWRITE_OFF    = 0,
  TAGWRITE_ASK    = 1,   // the question that used to be the "on" of a switch
  TAGWRITE_ALWAYS = 2,   // write straight away, only the result is reported
};
extern uint8_t g_tagwrite_mode;

// Whether a tag whose record disagrees with the spool it is bound to leads to
// an offer to write it again. Off by default and a switch of its own: the one
// above answers "a link just happened", this one answers "this tag has been
// lying around since something changed", and a scale that writes tags is not
// automatically a scale that wants to be asked about every old one.
//
// Compared are material, brand and colour. Temperatures are left out - Spoolman
// often carries none, and 0 against 220 is a difference that means nothing -
// and so is the format: an ACE tag read while OpenSpool is selected says
// nothing about the spool being wrong.
extern bool g_tagmismatch_ask;

// A TagFormat - see services/tag_write.h. OpenSpool by default: it is the
// record the filament managers read, where ACE only ever talks to the printer.
extern uint8_t g_tagwrite_fmt;

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

// Whether the scale copies the hardware uid of the tag on the reader into
// extra.rfid_tag, the field Happy Hare v4 resolves its gate readers against.
// Off by default.
//
// It exists because a Bambu tag has two identities and only one of them ever
// leaves the scale: the tray uuid out of the encrypted contents binds the
// spool, while an MMU's gate reader sees nothing but the chip's hardware uid.
// The same spool is then found here and unknown at the printer.
//
// Not a second binding and not a tag field: whatever the tag field choice
// says stays exactly where it is, and this only ever adds. It grows on its
// own, because a spool is found by its tray uuid from either side while each
// side contributes its own chip uid the first time it faces the reader.
//
// Unlike the tag fields this is written on every lookup rather than on an
// explicit link - a library that is already bound would otherwise have to be
// relinked spool by spool to get anything out of it.
extern bool g_hw_uid_write;

// Whether the scale asks for a second tag right after a link succeeded.
// Off by default.
//
// The community asked for a second reader, one per side of the case, so a
// spool with a chip on each flange is recognised whichever way round it lies.
// The hardware has one reader, so this is the flow that replaces the part:
// link, turn the spool over, done.
//
// A Bambu spool half solves this on its own today - both chips carry the same
// tray uuid, so the second one is found and appended the next time that side
// happens to face the reader. Two NTAGs share nothing, and without this the
// user has to look the spool up in the link list a second time.
//
// Only offered where the source in force can hold more than one tag; see
// tagFieldHoldsSeveral() and backendCanHoldSecondTag(). Writing the second tag
// is not a separate setting - it runs through the same link as the first one,
// so g_tagwrite_mode asks for it the same way.
extern bool g_tag2_ask;

// Whether the scale offers the AMS bay picker after weighing a spool, for the
// backends that can pin a spool to a bay. Off by default: the assignment also
// configures the bay on the printer over MQTT, and that is a side effect
// nobody should get without having asked for it.
//
// Only two states, so a switch rather than the three way mode FilaMan's own
// AMS assignment carries. There "always" means the server flag stays raised
// and every weighing opens a window; here there is no window and no implicit
// bay, so an "always" would have nothing to do.
extern bool g_ams_pick_ask;

// Whether the device may use Bluetooth Low Energy at all. Off by default, and
// off means the BLE stack is never started: no radio time shared with WiFi,
// no internal RAM taken. On means the features that need it (a device scan,
// the label printer) start the stack when they run and release it right
// after; nothing stays up between uses. Settings > Connection > Bluetooth.
extern bool g_ble_enabled;
