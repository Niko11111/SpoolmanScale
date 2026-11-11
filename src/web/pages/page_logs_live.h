#pragma once

#include <WebServer.h>

// The session log on a page of its own (/log/live): the whole window, a font
// size that can be turned up, colour for the lines that matter and a filter.
// The card on /logs is a 340 px box in 12 px type, too small to follow a tag
// being written. Same feed as the card, /api/log/session; same gate as /logs.
void logLiveRoutes(WebServer &srv);
