#pragma once

// from_options routes the back button to the Spoolman options screen instead
// of the backend screen. Two places open this outside the setup flow, and
// landing a level above the one you came from is disorienting in both.
void showExtraFieldsScreen(bool is_setup_flow, bool from_options = false);
void buildExtraFieldsScreen(bool is_setup_flow);
void checkAndCreateExtraFields(bool create_missing);
void resetExtraFieldsScreenState();
void handleExtraFieldsDeferredActions();
