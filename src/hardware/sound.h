#pragma once

#include <stdint.h>

// Short confirmation tones through the WT32-SC01 Plus's onboard I2S amplifier
// and whatever small speaker is plugged into its SPK connector.
//
// Off by default: most scales have no speaker fitted, and an option that does
// nothing until hardware is added should not be on when it arrives. The
// Sound switch is that on/off. Volume sits behind it.
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
  SND_TEST,           // played when the volume is changed, ignores the event switches
};

enum SoundVolume : uint8_t {
  SND_VOL_LOW  = 0,
  SND_VOL_MED  = 1,
  SND_VOL_HIGH = 2,
  SND_VOL_MAX  = 3,
  SND_VOL_COUNT
};

extern bool    g_sound_on;      // Sound switch, off by default, NVS "snd_on"
extern bool    g_snd_nfc;       // NVS "snd_nfc"
extern bool    g_snd_write;     // NVS "snd_write"
extern bool    g_snd_weight;    // NVS "snd_weight"
extern uint8_t g_snd_volume;    // SoundVolume, NVS "snd_vol"

// Reads the five values above from NVS. Called from loadPrefs().
void soundLoadPrefs();

// Drives GPIO35, GPIO36 and GPIO37 low, and releases a hold left by deep
// sleep. Called at boot, before the startup delay.
void soundParkClockPins();

// Stops a tone in progress and holds the clock pins low across deep sleep.
void soundPrepareDeepSleep();

// Plays the tone for e if sound is on and the switch for e is on. Never
// blocks; a tone that finds the queue full is dropped.
void soundPlay(SoundEvent e);
