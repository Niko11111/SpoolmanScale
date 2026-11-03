#pragma once

#include <Arduino.h>
#include <WebServer.h>

// The online services on the backend page (services/backend_profiles.h): the
// fourth tab, the line under the tabs, a card per service, their script and
// their routes. Apart from the tab, the page looks as it did for someone who
// never opens it.
String backendOnlineTab();
String backendOnlineNote();
String backendOnlineCards();
String backendOnlineScript();
void   backendOnlineRoutes(WebServer &srv);
