#pragma once

#include <Arduino.h>
#include <WebServer.h>

// ============================================================
//  THE TAG PAGE'S LINK SIDE
//
//  Link, move and unlink the tag on the reader from /tags: the
//  three routes, what services/tag_link.cpp reports said in the
//  user's language, and the script for the two questions the
//  page asks (move a tag another spool holds, unlink it). Its own
//  file because page_tags.cpp is at its size limit.
//
//  Every route only parks; tagLinkTick() does the requests on the
//  loop task.
// ============================================================

// The link fields of /api/tag, without the braces:
// "linkspool":7,"linkstate":"held",... for the page's poll.
String tagLinkPollJson();

// A <script> block with the questions and the unlink button's handler. Goes
// before the page's main script, which calls tlHeld() and tlSync() from its
// poll.
String tagLinkScript();

// /api/tag/link, /api/tag/move and /api/tag/unlink, all behind GATE_MAINT.
void tagLinkRoutes(WebServer& srv);
