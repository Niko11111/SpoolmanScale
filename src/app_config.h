#pragma once

#define FW_VERSION  "v0.7.0-beta.124"
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

#define CAL_FACTOR_DEFAULT  1.0f
#define SCALE_FILTER_SIZE   8

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

// A spool that reads a few grams over its label weight is simply full, not
// mislabelled. Only a real difference is worth interrupting the weighing for.
#define BB_CAP_TOLERANCE_G   2.0f

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
// The nominal filament weights Bambu sells. The scale picks whichever is
// closest to what it reads and the user can correct it before saving, which
// beats guessing 1000 g for a 250 g refill.
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

// ============================================================
//  Hardware self diagnosis
// ============================================================
// How often the diagnosis re-evaluates. It probes one I2C address per pass,
// so this is the extra bus traffic it costs; everything else it reads is
// state the loop already keeps.
#define DIAG_TICK_MS  2000

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
