#pragma once

#include <Arduino.h>

// The session log card on /logs: the ring in RAM, followed live, with a font
// size that can be turned up, colour for the lines that matter, a filter and
// a full screen view of the same card. One view of that log, not a second
// page next to it. Feed: /api/log/session, registered by page_logs.cpp.
String sessionLogCard();

// Its script, with the captions it needs. Goes after the card's markup.
String sessionLogScript();
