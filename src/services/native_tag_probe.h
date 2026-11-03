#pragma once

// ============================================================
//  WHAT THE ANSWER TO THE NATIVE TAG PROBE MEANS
//
//  GET /api/v1/tag/reader says whether a server keeps tags in a relation of
//  their own. Only two answers say anything about that. Everything else, no
//  answer at all, a 5xx, a refused key, a rate limit, says nothing, and a link
//  must not act as if it had heard "no": that wrote the tag into an extra
//  field of a server that has the relation.
// ============================================================

enum NativeProbeAnswer { NATIVE_PROBE_PRESENT, NATIVE_PROBE_ABSENT, NATIVE_PROBE_UNSURE };

// A probe's answer that a link may not pass on as its own code. See below.
#define NATIVE_PROBE_ODD_ANSWER (-91)

// 404 from Spoolman before 0.27, 405 and 501 from a server that speaks
// Spoolman's API but left this part out.
inline bool backendAnswerMeansAbsent(int code) {
  return code == 404 || code == 405 || code == 501;
}

inline NativeProbeAnswer nativeProbeAnswer(int code) {
  if (code == 200) return NATIVE_PROBE_PRESENT;
  return backendAnswerMeansAbsent(code) ? NATIVE_PROBE_ABSENT : NATIVE_PROBE_UNSURE;
}

// What a link reports when the probe said nothing: the probe's own code, so a
// server that is down is named as down. Not one that means something else from
// a link: 2xx would read as linked, 409 as another spool holding the tag.
inline int nativeProbeLinkCode(int code) {
  return ((code >= 200 && code < 300) || code == 409) ? NATIVE_PROBE_ODD_ANSWER : code;
}
