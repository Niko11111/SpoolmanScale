#pragma once

#include <stdint.h>

// Short confirmation tones through the WT32-SC01 Plus's onboard I2S amplifier
// and whatever small speaker is plugged into its SPK connector.
//
// Off by default: most scales have no speaker fitted, and an option that does
// nothing until hardware is added should not be on when it arrives. The
// Sound switch is that on/off. Volume sits behind it, as an attenuation in
// whole dB below full scale, so a loud speaker can be turned far down.
//
// soundPlay() only queues and returns, so it is safe from any task and costs
// the loop nothing. A low priority task renders the tone and stops the I2S
// clock again afterwards, so the amplifier is not left idling and hissing
// between beeps. The task and the I2S channel are created on the first beep.
//
// GPIO35 and GPIO36 come out of reset as the I2S clock, and the onboard
// amplifier hisses until something drives them. soundParkClockPins() drives
// them, and DOUT, low at boot. soundPrepareDeepSleep() holds that level
// across deep sleep. Wake is a reset, and the park runs again.

enum SoundEvent : uint8_t {
  SND_NFC_READ,       // a new tag was placed on the reader
  SND_TAG_UNKNOWN,    // the lookup finished and the tag is not in the inventory
  SND_WRITE_OK,       // a tag write or erase finished
  SND_WRITE_FAIL,     // a tag write or erase failed
  SND_WEIGHT_OK,      // auto weight saved the weight to the backend
  SND_WEIGHT_MANUAL,  // the weight button saved the weight to the backend
  SND_WEIGHT_FAIL,    // a weight save tried and the backend refused it
  SND_ASK,            // a write request from FilaMan or the browser waits on the display
  SND_PRINT_OK,       // a label printer took the label
  SND_PRINT_FAIL,     // a label could not be printed
  SND_UPDATE_OK,      // a firmware update was written, the restart follows
  SND_UPDATE_FAIL,    // a firmware update was not written
  SND_LINK_LOST,      // WiFi, or the backend behind it, stopped answering after it had
  SND_TEST,           // played when the volume is changed, ignores the event switches
  SND_PAUSE,          // silence between two previewed tones, never played alone
};

// Volume as attenuation: 0 dB is full scale, which overdrives some speakers;
// the slider reaches down to SND_ATT_MAX_DB, where a loud one is still audible.
constexpr uint8_t SND_ATT_MAX_DB     = 48;
constexpr uint8_t SND_ATT_DEFAULT_DB = 12;   // what was "Medium" before the slider

extern bool    g_sound_on;      // Sound switch, off by default, NVS "snd_on"
extern bool    g_snd_nfc;       // NVS "snd_nfc"
extern bool    g_snd_write;     // NVS "snd_write"
extern bool    g_snd_weight;    // NVS "snd_weight"
extern bool    g_snd_ask;       // NVS "snd_ask"
extern bool    g_snd_print;     // NVS "snd_print"
extern bool    g_snd_update;    // NVS "snd_update"
extern bool    g_snd_link;      // NVS "snd_link"
extern uint8_t g_snd_att_db;    // 0..SND_ATT_MAX_DB, NVS "snd_att"
// Which tone set plays: true (the default) the softer chimes of Feature AA,
// which ring out instead of stopping flat, false the short beeps of PR #79.
// NVS "snd_chime".
extern bool    g_snd_chime;

// Reads the values above from NVS. Called from loadPrefs().
void soundLoadPrefs();

// Drives GPIO35, GPIO36 and GPIO37 low, and releases a hold left by deep
// sleep. Called at boot, before the startup delay.
void soundParkClockPins();

// Stops a tone in progress and holds the clock pins low across deep sleep.
void soundPrepareDeepSleep();

// Plays the tone for e if sound is on and the switch for e is on. Never
// blocks; a tone that finds the queue full is dropped. SND_LINK_LOST plays
// at most once in ten minutes, so a link that keeps dropping does not nag.
void soundPlay(SoundEvent e);

// Plays the count tones in order with a pause between them, so a settings
// row can let you hear what it switches on. Ignores the event switches,
// only the Sound switch counts. count is capped at SND_PREVIEW_MAX.
constexpr uint8_t SND_PREVIEW_MAX = 3;
void soundPreview(const SoundEvent *events, uint8_t count);
