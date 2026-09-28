#pragma once

#include <Arduino.h>
#include <WebServer.h>

// The Bambu catalog's card on the tags page and its one route: how many
// colours the scale knows and since when, and the button that loads the
// table (bambu/bambu_catalog.h). Its own file so the tags page, already
// close to its size limit, only calls in.
void bambuCatalogCard(String& h);
void bambuCatalogRoutes(WebServer& srv);
