#pragma once

// Name lookups for the backend requests, kept from standing the loop still.
//
// A name is looked up where it is asked for, as before, until a lookup fails.
// From then on it is answered "no" at once, and a task on the other core
// looks it up again in the background (host_lookup_rules.h); once that finds
// it, requests go through again. Only the one lookup that finds the name
// gone still waits for lwIP to give up.
//
// True for an address literal and for an empty host, without a lookup: the
// client parses those itself. Safe to call from any task.
bool hostLookupOk(const char* host);
