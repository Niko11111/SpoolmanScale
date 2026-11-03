#pragma once

#include <stdint.h>

#include "services/server_refusal_rules.h"

// ============================================================
//  THE SERVER SAID NO
//
//  serverReachNote() is where every flow hands its HTTP code, so that is where
//  a refusal asks for its popup, under the same rule as a lost connection:
//  every time for something the user set off, once for the lookup behind a tag
//  placement until a request succeeds again.
//
//  The wait a 429 names comes from BackendHttp, the only place that sees the
//  header. Background requests hold off until it is over; what the user sets
//  off still goes out, one request, and gets an honest answer.
// ============================================================

// From BackendHttp, on whichever core ran the request.
void serverRefusalRecord(int code, const char* retry_after);

// Whether background requests should wait for a server that asked for it.
bool serverPauseActive();

// The last refusal since serverRefusalClearSeen(), 0 for none. For the address
// test: an open /health says nothing about the key, the requests behind it do.
void serverRefusalClearSeen();
int  serverRefusalSeen();

// Counts every refusal. For a request that goes through several layers, where
// the code does not make it back to the caller: an unanswered field list turns
// a 401 into "not supported" on the way up. Compare before and after.
uint32_t serverRefusalCount();

// The key, the address or the backend changed: nothing recorded still applies.
void serverRefusalForget();

// From serverReachNote().
void serverRefusalNote(int code, bool user_action);

// For the screen, from the loop. REFUSAL_NONE when nothing is asked for.
ServerRefusal serverRefusalPopupTake();

// The texts. Short enough for the weight line, the popup's body below it.
int serverRefusalTitleId(ServerRefusal refusal);
int serverRefusalTextId(ServerRefusal refusal);
