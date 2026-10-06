#pragma once

#include <Arduino.h>
#include <WebServer.h>

// The display screenshot card on the logs page and its routes: take a
// picture, list the held ones, fetch one as a BMP, drop one or all. The
// browser turns each BMP into the PNG it saves. Registered by the logs page,
// behind its gate.
String screenshotCard();
void   screenshotRoutes(WebServer& srv);
