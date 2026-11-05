#pragma once

#define FW_VERSION  "v0.8.4-beta.54"
#define DONATION_URL "ko-fi.com/formfollowsfunction"

// Backlight PWM duty on GPIO45, 8 bit, straight through to LovyanGFX. Not a
// percentage: 255 is full output.
//
// Min and max describe what the panel is driven at, the default only describes
// what a fresh device starts with. They happen to share the value 255 today,
// which is exactly why they stay separate: tying the slider to the default
// would silently cap it if that default ever changed.
#define BRIGHT_MIN                10   // not 0: the screen has to stay usable
#define BRIGHT_MAX               255
#define BRIGHT_NORMAL_DEFAULT    255
#define DIM_TIMEOUT_DEFAULT   300000
#define SLEEP_TIMEOUT_DEFAULT 1200000
#define OFF_TIMEOUT_DEFAULT        0   // 0 = stage skipped

// Main screen zone 4: the fill of the remaining-filament bar is written from
// two places in spoolman_lookup.cpp and created in main_screen.cpp. It used to
// be a bare 190 in all three, which is how the bar and its background came to
// disagree the moment one of them was widened.
#define MAIN_BAR_W  194

// The right half of zone 4, which without a load cell carries a note instead
// of the live weights. x=218 is the column 2 axis the design guide fixes,
// 254 runs it out to the 8 px right margin, and y=189 with h=70 is the zone
// the two vertical dividers already span.
#define MAIN_NOSCALE_X  218
#define MAIN_NOSCALE_W  254
#define MAIN_ZONE4_Y    189
#define MAIN_ZONE4_H     70

// The AMS button that fills that space when the backend has an AMS view. 46 px
// clears the 44 px the design guide asks of a button, and y=209 puts its lower
// edge on 255 - inside the zone, level with the progress bar opposite.
#define MAIN_AMS_BTN_Y  209
#define MAIN_AMS_BTN_H   46
// The countdown fill inside that button: inside its 1 px border.
#define MAIN_AMS_FILL_W  (MAIN_NOSCALE_W - 2)
#define MAIN_AMS_FILL_H  (MAIN_AMS_BTN_H - 2)

// The AMS chip in the header. 18 px is the label's 16 plus its border, which
// centres inside the 26 px header with 4 px above and below. The touch pad is
// capped at 8: the diagnosis banner owns y=26..47 and is clickable.
#define HDR_AMS_H           18
#define HDR_AMS_PAD_X        7
#define HDR_AMS_TOUCH_PAD    8

// The factor of a scale nobody has calibrated, in counts per gram. A round
// guess for the 2 kg cell most builds use (about 1075 by calculation): a 1 kg
// reads roughly double, a 5 kg less than half, and even a 2 kg can be a quarter
// off. Good enough for the thresholds in grams and to see the cell respond, and
// never a measurement, which is why the banner says so until it is replaced.
#define CAL_FACTOR_DEFAULT         1000.0f
// The factory value of earlier firmware, still in the NVS of a reset device.
#define CAL_FACTOR_LEGACY_DEFAULT  1.0f
// How far a calibration that hits the factory value exactly is moved off it.
#define CAL_FACTOR_MEASURED_STEP   0.01f
#define SCALE_FILTER_SIZE   8

// The app slot size of the partition table this firmware ships with. A device
// whose slots are smaller was flashed with the old table and is told so once:
// OTA never rewrites the table, only a flash over USB does.
#define PARTITION_APP_SLOT_CURRENT_BYTES  0x600000
// Whether the public web flasher already carries that table. It only does
// from the first public release after the table changed: a beta tag never
// updates the flasher. Until then the hint must stay silent, because it would
// send people to a flasher whose "Update" hands them the previous release with
// the old table, a downgrade. Set to 1 in the release commit and leave it.
#define FLASHER_HAS_CURRENT_LAYOUT  1
// The public web flasher, where the hint sends a device on the old layout.
#define FLASHER_URL "https://niko11111.github.io/SpoolmanScale/"
// The manual. A German page lives under de/, the English one at the root.
#define DOCS_URL "https://niko11111.github.io/SpoolmanScale-Docs/"

// The two chips on I2C_EXT. Named because a bare 0x2A stood in three files and
// meant nothing to anyone reading a bus scan.
#define I2C_ADDR_PN532      0x24
#define I2C_ADDR_NAU7802    0x2A

// What a calibration is allowed to produce. A failed I2C read comes back as
// all ones through Adafruit_BusIO, so an absent ADC delivers a sample of -1
// for every reading: tare and calibration then agree perfectly and the factor
// collapses towards zero, which turns every later weight into a number like
// -3487423847234 g. A real cell at gain 128 lands somewhere around 100 to 2000
// counts per gram, so this band rejects the nonsense without arguing with
// anyone's hardware.
#define CAL_FACTOR_MIN        1.0f
#define CAL_FACTOR_MAX   100000.0f
// Below this the factor is not unusual, it is broken - it makes the device
// unusable, so loadPrefs() repairs it instead of honouring it.
#define CAL_FACTOR_BROKEN     0.001f
// The reference weight someone types in. A gram or two cannot calibrate
// anything, and nobody puts 50 kg on a filament scale.
#define CAL_KNOWN_MIN_G      10.0f
#define CAL_KNOWN_MAX_G   20000.0f

// Remote link, triggered from the FilaMan web UI. The window matches the 60
// seconds the FilaMan frontend polls for a result, so both sides give up at
// the same time instead of one waiting on the other.
#define REMOTE_LINK_TIMEOUT_MS  60000

// How far apart a Bambu tag's colour and a spool's may lie, as the sum of
// the three channel differences, before the two count as different colours.
// The link list has filtered by this since it compared colours at all.
#define TAG_SPOOL_COLOR_DIST_MAX  120

// Deriving the empty-spool weight from a brand new spool: the reading minus
// the nominal filament weight. Outside these bounds the reading is not a full
// spool of the expected filament - a half-used one, or a nominal weight that
// is wrong - and a derived tare would be nonsense written to a filament or an
// entire brand.
#define NEW_SPOOL_TARE_MIN_G     30.0f
#define NEW_SPOOL_TARE_MAX_G    600.0f
// How long a remote link waits for a tag before falling back to adopting the
// spool for weighing only. Long enough that someone reaching for a tag is not
// cut off, far short of the full timeout, which otherwise ends in a failure
// for a spool that simply has no tag on it.
#define REMOTE_LINK_TAGLESS_MS  10000

// A spool shown by its typed id (app/id_spool.h). It counts as put on the pad
// from this load, the threshold the location question uses for a real spool,
// and is dropped again when nothing was put on within the idle time. Once
// lifted it stays shown for a quarter of the minute a lifted tag gets
// (NO_TAG_CLEAR_MS in app_loop.cpp): long enough to tap the location or AMS
// button on the way, short enough that nobody has to reach for the x. Nothing
// is asked on its own after a lift - the location, AMS and bay questions hang
// off a tag leaving the reader - so no question loses its spool to the end.
#define ID_SPOOL_LOAD_MIN_G     50.0f
#define ID_SPOOL_IDLE_MS        120000UL
#define ID_SPOOL_LIFTED_MS      15000UL

// A spool that reads a few grams over its label weight is simply full, not
// mislabelled. Only a real difference is worth interrupting the weighing for.
#define BB_CAP_TOLERANCE_G   2.0f

// How far the net reading may be from a spool's stored remaining weight for
// the link list to put that spool first. Bambu cores alone vary by 11 g (241
// to 252 in a real library), and the stored figure lags behind a print that
// was never booked against it.
#define LINK_WEIGHT_TOLERANCE_G  20.0f

// How still the pad has to be before a reading counts as the spool's weight,
// where nothing was weighed on purpose: the AMS question and the card for an
// unknown spool. Deliberately looser and far shorter than the auto weight
// criterion (0.5 g over 3 s): there the user is waiting for a countdown, here
// they are putting a spool down and picking it up again. With the 1.6 s
// moving average in front of it, this settles about 2.4 s after the spool
// lands instead of the 5 s the strict values needed.
#define PAD_SETTLE_TOL_G   2.0f
#define PAD_SETTLE_MS      800

// What a spool starts with when it is created off the pad
// (services/spool_start.h). A net reading within this band around the label
// is a full spool: Bambu winds up to about 1.5 % over the label, and an empty
// spool someone weighed is good to a few grams. On Bambu's fixed core the
// band widens by the 11 g the real cores vary (241 to 252 g in one library).
// Below START_MIN_NET_G of filament the pad counts as empty: the spool is
// being held to the reader, or only its core lies there.
#define START_FULL_TOL_PCT          3
#define START_FULL_TOL_MIN_G       15.0f
#define START_TARE_DEFAULT_SLACK_G 10.0f
#define START_MIN_NET_G            20.0f

// Creating a spool straight from a Bambu tag. The tag carries material,
// brand, colour and temperatures, but no weights at all - a Bambu Lab core
// weighs 250 g, which is also BamBuddy's own default, so a spool created here
// matches what its web UI would have produced.
// Bambu tags carry no vendor string - block 16 reads back empty even on a
// tag whose 48 blocks all decrypt cleanly. The name is implicit: only Bambu
// Lab makes tags that derive with this KDF. The main screen has always shown
// this fallback, so creating a spool uses the same one rather than sending an
// empty brand the server would turn into a filament with no vendor at all.
#define BAMBU_VENDOR_NAME     "Bambu Lab"
#define BAMBU_CORE_WEIGHT_G      250
// The nominal filament weights Bambu sells, for a tag that names no net
// weight of its own (Bambu tags carry theirs): the scale takes whichever is
// closest to what it reads, which beats guessing 1000 g for a 250 g refill.
#define NEWTAG_LABEL_COUNT         4
#define NEWTAG_LABEL_CHOICES  { 250, 500, 750, 1000 }

// The verbose heartbeat is checked every 5 s but only written when something
// moved by at least this much, plus one line per keepalive interval so the
// last timestamp still marks how far the loop got. Measured on a real day:
// 90 % of heartbeat lines repeated the previous one byte for byte.
#define HEARTBEAT_QUIET_DELTA_B   1024
#define HEARTBEAT_KEEPALIVE_MS   60000

// How long to wait before re-announcing a tag that the auto-link has just made
// resolvable. Spoolman suppresses a repeat of the same UID from the same
// reader within 3 seconds (DEBOUNCE_WINDOW in its scanrelay.py), so an
// immediate second scan would be swallowed and never reach a paired browser.
#define TAG_RESCAN_DELAY_MS  3500

// How often to ask again whether a tag that came up unknown has been linked in
// the meantime. Only ever while such a tag is on the pad, and only over the
// cheap server side lookup - never the full inventory scan, and never
// /tag/scan, which would broadcast an unknown tag on every attempt.
#define TAG_RECHECK_MS  4000

// The longest the recheck waits after probes that got no answer. Each such
// probe doubles the gap up to this: a probe blocks the loop for up to the 5 s
// connect timeout, and on 21.09.2026 two of them back to back left the loop
// one pass in 12 s, which read as a frozen scale.
#define TAG_RECHECK_MAX_MS  60000

// How long a picker that opened by itself - the location list after a spool
// was lifted, BamBuddy's bay choice - waits for a tap before it closes as if
// Cancel was pressed. The same 30 s as the second tag question. Its Cancel
// drains over that time, so the close never comes as a surprise.
#define PICK_COUNTDOWN_MS  30000

// ============================================================
//  Hardware self diagnosis
// ============================================================
// How often the diagnosis re-evaluates. It probes one I2C address per pass,
// so this is the extra bus traffic it costs; everything else it reads is
// state the loop already keeps.
#define DIAG_TICK_MS  2000

// A bus with a loose contact flips the finding on almost every tick, which
// wrote a log line every two to four seconds and buried everything else. Per
// window, only the first few changes get a line of their own; the rest are
// counted and reported in one line when the window closes.
#define DIAG_LOG_WINDOW_MS  60000
#define DIAG_LOG_BURST      4

// Peak to peak spread of the moving average window that stops being noise and
// starts being a wiring fault. A settled pad sits inside a gram or two; a
// signal wire that is only half seated swings by hundreds.
#define DIAG_NOISE_G  20.0f
// How long that spread has to hold before it is reported. A hand on the pad or
// a spool being placed produces one to two seconds of it, and neither is a
// fault worth interrupting anyone for.
#define DIAG_NOISE_SUSTAIN_MS  10000

// A+ and A- swapped: the cell reads the load with the wrong sign, so an empty
// pad sits far below zero and putting something on it drives the number down
// rather than up.
#define DIAG_INVERTED_G  -200.0f
#define DIAG_INVERTED_SUSTAIN_MS  5000
// What rules the inversion out for the rest of the session. Someone who tared
// with a spool on the pad and then lifted it sits at a large negative number
// too, and that is not a fault - but their cell has read a real positive load
// at some point, and a swapped one never does.
#define DIAG_POSITIVE_SEEN_G  50.0f

// How many times the loop re-initialises a reader that is on the bus but not
// answering, before it stops trying. Mirrors SCALE_RECOVER_ATTEMPTS, which is
// declared next to the scale watchdog in app_loop.cpp.
#define NFC_RECOVER_ATTEMPTS  3

// Signal strength as four bars, drawn by the status page for the WiFi link
// and by the printer page for the printer's Bluetooth RSSI: one ladder for
// both, green from three bars up.
#define SIGNAL_BARS_4_DBM  -50
#define SIGNAL_BARS_3_DBM  -65
#define SIGNAL_BARS_2_DBM  -75
