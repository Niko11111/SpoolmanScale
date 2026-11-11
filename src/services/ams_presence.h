#pragma once

#include <stdint.h>

// ============================================================
//  AMS PRESENCE
//
//  Whether the configured printer actually has an AMS, cached.
//
//  backendHasAmsView() answers a different and much cheaper
//  question: whether the active backend could talk about a
//  printer at all. It is a mode check and two string compares.
//  Whether a printer has an AMS bolted to it is only knowable
//  by asking the server, which blocks, so the answer is fetched
//  on a slow timer and kept.
//
//  Everything that decides whether to show a way into the AMS
//  view reads this, so the affordance disappears on a printer
//  that has no AMS instead of leading to an empty page.
// ============================================================

// First ask shortly after boot, once the network and the backend have
// settled. Then rarely: an AMS is bolted on and off in the physical world,
// not several times an hour.
#define AMS_PRESENCE_FIRST_MS     20000
#define AMS_PRESENCE_INTERVAL_MS  300000UL

// An AMS source beside Spoolman that does not answer costs the loop the whole
// timeout of every request, touch and display standing still. Each pass in a
// row without an answer doubles the wait, up to an hour; an answer brings back
// the five minutes.
#define AMS_PRESENCE_MAX_WAIT_MS  3600000UL

inline uint32_t amsPresenceWaitMs(uint8_t misses) {
  uint32_t wait = AMS_PRESENCE_INTERVAL_MS;
  for (uint8_t i = 0; i < misses && wait < AMS_PRESENCE_MAX_WAIT_MS; i++) wait *= 2;
  return wait < AMS_PRESENCE_MAX_WAIT_MS ? wait : AMS_PRESENCE_MAX_WAIT_MS;
}

// True when the printer is known to have at least one AMS unit. False while
// the answer is still unknown, so a way in appears once it is confirmed
// rather than flickering away when it is not.
bool amsPresenceHasAms();

// The printer the answer belongs to, or 0. Saves the view a lookup.
int  amsPresencePrinterId();

// Throws the answer away, for a backend switch or a changed host: the next
// tick asks again. Without this the chip would keep promising an AMS that
// belongs to a server no longer in use.
void amsPresenceForget();

// Called from appLoop(). Does nothing on most passes.
void amsPresenceTick();
