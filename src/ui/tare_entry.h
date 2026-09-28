#pragma once

// The empty spool weight, weighed or typed in (issue #40). Opened from the
// weight popup's empty spool button. Either way the value goes on to the
// popup that asks where it is stored - spool, filament or brand.
void showTareChoice();

// Both dialogs of this file, for the navigation. Closed, not hidden.
void closeTareEntry();
