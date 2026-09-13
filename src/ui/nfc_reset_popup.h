#pragma once

// The one time hint that an optional hardware change exists, shown only to
// devices whose reader has actually needed recovery - see services/nfc_reset.h
// for why that gate matters. Two ways out and no third: ask again later, or
// never again. There is deliberately no timer that brings it back on its own
// after "never", because a dismissal that does not hold teaches people that
// the button is broken.
void showNfcResetHint();
void closeNfcResetHint();
